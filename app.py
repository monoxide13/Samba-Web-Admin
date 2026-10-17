#!/usr/bin/env python3
"""Three-page browser administration UI; never run this process as root."""
from __future__ import annotations

import json
import os
import pwd
import secrets
import selectors
import subprocess
import sys
import time
from pathlib import Path
from threading import RLock

from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from waitress import serve

from schema import GLOBALS, SHARES
from urlmount import MountPathMiddleware

BASE = Path(__file__).resolve().parent
ACCOUNT = pwd.getpwuid(os.geteuid()).pw_name
SESSION_TTL = 15 * 60
MAX_SESSIONS = 256
app = Flask(__name__)
app.wsgi_app = MountPathMiddleware(app.wsgi_app)
app.secret_key = secrets.token_bytes(32)  # restart invalidates all session cookies
app.config.update(SESSION_COOKIE_NAME='samba_admin_session', SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE='Strict',
                  SESSION_COOKIE_SECURE=os.getenv('SAMBA_ADMIN_SECURE_COOKIE') == '1',
                  MAX_CONTENT_LENGTH=256 * 1024)

# Each browser has a random session ID in a signed, HttpOnly cookie; admin
# credentials live only in RAM keyed by that ID. This is a single-process app.
vault: dict[str, dict] = {}
vault_lock = RLock()


def browser_session() -> dict:
    now = time.monotonic()
    with vault_lock:
        for key, value in list(vault.items()):
            if now - value['last'] > SESSION_TTL:
                del vault[key]
        sid = session.get('sid')
        if not isinstance(sid, str) or sid not in vault:
            if len(vault) >= MAX_SESSIONS:
                raise RuntimeError('Too many open sessions')
            sid = secrets.token_urlsafe(32)
            session.clear()
            session['sid'] = sid
            vault[sid] = {'csrf': secrets.token_urlsafe(32), 'last': now,
                          'username': '', 'password': ''}
        vault[sid]['last'] = now
        return vault[sid]


@app.before_request
def setup():
    browser_session()
    if request.method == 'POST':
        token = request.form.get('csrf', '')
        if not secrets.compare_digest(token, browser_session()['csrf']):
            abort(403)


@app.after_request
def headers(response):
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'none'; style-src 'self'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
    return response


@app.context_processor
def constants():
    entry = browser_session()
    return {'csrf': entry['csrf'], 'authorized': bool(entry['password']),
            'account': ACCOUNT}


class WorkerError(Exception):
    pass


def sudo_worker(password: str, payload: dict) -> dict:
    """Wait for the helper's READY marker before sending the JSON body.

    Crucially, sudo's -S password and worker's stdin payload are not sent
    together. This also handles sudoers NOPASSWD without corrupting input.
    """
    args = ['sudo', '-k', '-S', '-p', '__SAMBA_ADMIN_SUDO_PROMPT__', '--',
            '/usr/bin/python3', '-u', str(BASE / 'root_worker.py')]
    proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, bufsize=0, close_fds=True)
    output = b''
    errors = b''
    sent_password = False
    ready = b'__SAMBA_ADMIN_READY__\n'
    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ, 'stdout')
    sel.register(proc.stderr, selectors.EVENT_READ, 'stderr')
    try:
        until = time.monotonic() + 20
        while ready not in output:
            if time.monotonic() >= until:
                raise WorkerError('Timed out authenticating with sudo')
            events = sel.select(min(1, until - time.monotonic()))
            for key, _ in events:
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    sel.unregister(key.fileobj)
                    continue
                if key.data == 'stdout':
                    output += chunk
                else:
                    errors += chunk
                    marker = b'__SAMBA_ADMIN_SUDO_PROMPT__'
                    if marker in errors and not sent_password:
                        proc.stdin.write((password + '\n').encode())
                        sent_password = True
                    elif marker in errors and sent_password and errors.count(marker) > 1:
                        raise WorkerError('Incorrect sudo password or account is not sudo-authorized')
            if not sel.get_map() and ready not in output:
                raise WorkerError(errors.decode(errors='replace')[-700:] or 'Unable to launch root helper')
            if len(output) + len(errors) > 32768:
                raise WorkerError('Excessive output from sudo')
        # Ready guarantees sudo is finished with stdin. The worker reads JSON now.
        rest, err = proc.communicate((json.dumps(payload) + '\n').encode(), timeout=45)
        complete = (output + rest).split(ready, 1)[-1].strip()
        if proc.returncode != 0 or not complete:
            raise WorkerError((errors + err).decode(errors='replace')[-700:] or 'Root helper failed')
        try:
            result = json.loads(complete.splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            raise WorkerError('Malformed response from root helper') from None
        if not result.get('ok'):
            raise WorkerError(result.get('error', 'Unknown privileged operation error'))
        return result.get('data', {})
    except (subprocess.TimeoutExpired, BrokenPipeError, OSError) as exc:
        raise WorkerError(f'Privileged command failed: {exc}') from exc
    finally:
        sel.close()
        if proc.poll() is None:
            proc.kill()
        proc.wait()


def backend(payload: dict):
    entry = browser_session()
    if not entry['password']:
        raise WorkerError('Enter sudo credentials first')
    return sudo_worker(entry['password'], payload)


def status():
    if not browser_session()['password']:
        return None
    try:
        return backend({'action': 'status'})
    except WorkerError as exc:
        flash(str(exc), 'error')
        return None


@app.route('/')
def system():
    return render_template('system.html', title='System configuration',
                           data=status(), fields=GLOBALS)


@app.route('/accounts')
def accounts():
    data = status()
    chosen = request.args.get('user', '')
    selected = next((u for u in data['users'] if u['name'] == chosen), None) if data else None
    return render_template('accounts.html', title='Users & groups', data=data, selected=selected)


@app.route('/shares')
def shares():
    data = status()
    editing = request.args.get('edit', '')
    selected = next((s for s in data['shares'] if s['name'] == editing), None) if data else None
    return render_template('shares.html', title='Shares & permissions', data=data,
                           selected=selected, fields=SHARES)


@app.route('/credentials', methods=['POST'])
def credentials():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    if username != ACCOUNT:
        flash(f'This application is running as {ACCOUNT}; sudo credentials must belong to that account.', 'error')
    elif '\n' in password or '\r' in password or not password:
        flash('Enter a valid sudo password.', 'error')
    else:
        try:
            sudo_worker(password, {'action': 'ping'})
            with vault_lock:
                entry = browser_session()
                entry['username'] = username
                entry['password'] = password
            flash('Sudo credentials accepted for this browser session.', 'success')
        except WorkerError as exc:
            flash(f'Sudo authentication failed: {exc}', 'error')
    return redirect(url_for('system'))


@app.route('/logout', methods=['POST'])
def logout():
    with vault_lock:
        entry = browser_session()
        entry['password'] = ''
        entry['username'] = ''
    flash('This browser’s sudo credentials were cleared.', 'success')
    return redirect(url_for('system'))


def updates_from_form(fields):
    updates = {}
    for key, _, _, _ in fields:
        name = 'cfg_' + key.replace(' ', '_')
        if name not in request.form:
            raise ValueError(f'Missing form field {name}')
        value = request.form[name].strip()
        updates[key] = value if value else None
    return updates


@app.route('/action', methods=['POST'])
def action():
    operation = request.form.get('operation', '')
    dest = request.form.get('return_to', 'system')
    if dest not in ('system', 'accounts', 'shares'):
        dest = 'system'
    try:
        payload = {'action': operation}
        if operation == 'config':
            which = request.form.get('type')
            payload.update(type=which, revision=request.form.get('revision', ''))
            if which == 'global_save':
                payload['updates'] = updates_from_form(GLOBALS)
            elif which == 'share_save':
                payload.update(name=request.form.get('name', ''),
                               old_name=request.form.get('old_name', ''),
                               updates=updates_from_form(SHARES))
            elif which == 'share_delete':
                payload.update(name=request.form.get('name', ''), confirm=request.form.get('confirm', ''))
            else:
                raise ValueError('Unsupported configuration request')
        elif operation in ('user_create',):
            payload.update(username=request.form.get('username', ''),
                           primary_group=request.form.get('primary_group', ''),
                           nohome=request.form.get('nohome') == 'on',
                           nologin=request.form.get('nologin') == 'on')
        elif operation in ('user_shell', 'user_home'):
            payload.update(username=request.form.get('username', ''),
                           nologin=request.form.get('nologin') == 'on')
        elif operation == 'user_delete':
            payload.update(username=request.form.get('username', ''),
                           confirm=request.form.get('confirm', ''))
        elif operation in ('group_create', 'group_delete'):
            payload.update(group=request.form.get('group', ''), confirm=request.form.get('confirm', ''))
        elif operation == 'membership':
            payload.update(username=request.form.get('username', ''), group=request.form.get('group', ''),
                           operation=request.form.get('member_action', ''))
        elif operation == 'samba_password':
            a, b = request.form.get('password', ''), request.form.get('password_confirm', '')
            if a != b:
                raise ValueError('Samba passwords do not match')
            payload.update(username=request.form.get('username', ''), password=a)
        elif operation == 'samba_toggle':
            payload.update(username=request.form.get('username', ''), operation=request.form.get('toggle_action', ''))
        elif operation == 'service_control':
            payload.update(service=request.form.get('service', ''),
                           command=request.form.get('command', ''))
        elif operation == 'share_directory':
            payload.update(name=request.form.get('name', ''), owner=request.form.get('owner', ''),
                           group=request.form.get('group', ''), mode=request.form.get('mode', ''),
                           create=request.form.get('create') == 'on')
        elif operation == 'acl_update':
            payload.update(name=request.form.get('name', ''), kind=request.form.get('kind', ''),
                           principal=request.form.get('principal', ''),
                           permissions=request.form.get('permissions', ''),
                           default=request.form.get('default') == 'on',
                           operation=request.form.get('acl_action', ''))
        else:
            raise ValueError('Unsupported operation')
        result = backend(payload)
        if operation == 'service_control':
            flash(f'{result["unit"]}: {result["command"]} completed.', 'success')
        else:
            note = (' smbd is not running; changes will apply when it starts.'
                    if result.get('reload') == 'skipped' else '')
            flash(f'{operation.replace("_", " ").capitalize()} completed.' +
                  (f' Backup: {result["backup"]}' if 'backup' in result else '') + note,
                  'success')
    except (WorkerError, ValueError) as exc:
        flash(str(exc), 'error')
    if dest == 'shares':
        return redirect(url_for('shares', edit=request.form.get('old_name') or request.form.get('name') or ''))
    if dest == 'accounts':
        return redirect(url_for('accounts', user=request.form.get('username', '')))
    return redirect(url_for('system'))


if __name__ == '__main__':
    if os.geteuid() == 0:
        raise SystemExit('Refusing to launch the web server as root')
    host = os.getenv('SAMBA_ADMIN_HOST', '0.0.0.0')
    port = int(os.getenv('SAMBA_ADMIN_PORT', '8080'))
    print(f'Samba Web Admin: http://{host}:{port}, sudo account: {ACCOUNT}', flush=True)
    serve(app, host=host, port=port, threads=4)
