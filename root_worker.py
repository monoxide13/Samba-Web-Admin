#!/usr/bin/env python3
"""Privileged, allowlisted Linux/Samba operations; invoked only via sudo.

Protocol: print READY on stdout after sudo has finished authenticating, then
read one newline-terminated JSON object on stdin and print one JSON response.
No password is passed in argv, environment, or on disk.
"""
from __future__ import annotations

import datetime as dt
import fcntl
import grp
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from schema import PROTECTED_SHARES, GROUPNAME, MODE, USERNAME, validate_group, validate_share, validate_updates, validate_username
from smbconfig import SmbConf

CONF = Path('/etc/samba/smb.conf')
LOCK = Path('/run/lock/samba-web-admin.lock')
ALLOWED_FS_ROOTS = ('/srv', '/mnt', '/media', '/home', '/data', '/opt/samba')
SUDO_PROCESS_ACCOUNT = os.environ.get('SUDO_USER', pwd.getpwuid(os.getuid()).pw_name)
MAX_PAYLOAD = 1024 * 1024

# Logical names presented to the user and their known systemd unit names.
# On Debian/Ubuntu, winbindd is generally winbind.service and the AD DC is
# samba-ad-dc.service. Alternative names are supported where present.
SERVICE_UNITS = {
    'smbd': ('smbd.service',),
    'nmbd': ('nmbd.service',),
    'winbindd': ('winbind.service', 'winbindd.service'),
    'samba-dc': ('samba-ad-dc.service', 'samba-dc.service'),
}
SERVICE_LABELS = {
    'smbd': 'SMB file sharing (smbd)',
    'nmbd': 'NetBIOS nameserver (nmbd)',
    'winbindd': 'Winbind (winbindd)',
    'samba-dc': 'Active Directory domain controller (samba-dc)',
}


def unit_properties(unit: str) -> dict[str, str]:
    """Query one allowlisted systemd unit without attempting to operate on it."""
    try:
        result = subprocess.run(
            ['systemctl', 'show', '--no-pager', '--property=LoadState',
             '--property=ActiveState', '--property=SubState',
             '--property=UnitFileState', '--', unit],
            text=True, capture_output=True, timeout=8,
            env={**os.environ, 'LC_ALL': 'C'},
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if result.returncode != 0:
        return {}
    return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)


def services_status() -> list[dict]:
    """Only a loaded, unmasked unit is eligible for control operations."""
    services = []
    for name, units in SERVICE_UNITS.items():
        selected = None
        for unit in units:
            props = unit_properties(unit)
            if props.get('LoadState') == 'loaded':
                selected = {
                    'name': name, 'label': SERVICE_LABELS[name], 'unit': unit,
                    'installed': True, 'active': props.get('ActiveState', 'unknown'),
                    'substate': props.get('SubState', 'unknown'),
                }
                break
        services.append(selected or {
            'name': name, 'label': SERVICE_LABELS[name], 'unit': '',
            'installed': False, 'active': 'not installed', 'substate': '',
        })
    return services


def service_control(payload: dict) -> dict:
    service = text(payload['service'], 32)
    operation = text(payload['command'], 12)
    if service not in SERVICE_UNITS or operation not in ('start', 'stop', 'restart'):
        raise ValueError('Unsupported Samba service operation')
    # Re-check at execution time; a previously rendered page is not authority
    # to run commands on an uninstalled service.
    selected = next(item for item in services_status() if item['name'] == service)
    if not selected['installed']:
        raise ValueError(f'{service} has no installed, unmasked systemd unit')
    cmd(['systemctl', operation, '--', selected['unit']], timeout=38)
    return {'service': service, 'unit': selected['unit'], 'command': operation}


def cmd(args: list[str], *, input_text: str | None = None, allowed_rc=(0,), timeout=30) -> str:
    result = subprocess.run(args, input=input_text, text=True, capture_output=True,
                            timeout=timeout, env={**os.environ, 'LC_ALL': 'C'})
    if result.returncode not in allowed_rc:
        raise ValueError(f'{Path(args[0]).name} failed ({result.returncode}): '
                         f'{(result.stderr or result.stdout).strip()[:900]}')
    return result.stdout


def text(value, maximum=2048) -> str:
    if not isinstance(value, str) or any(x in value for x in '\r\n\x00') or len(value) > maximum:
        raise ValueError('Invalid submitted text')
    return value


def bool_value(value) -> bool:
    if type(value) is not bool:
        raise ValueError('Expected a true/false setting')
    return value


def must_user(name: str, *, protected=True):
    validate_username(name)
    ent = pwd.getpwnam(name)
    if protected and (ent.pw_uid < uid_min() or ent.pw_uid == 0 or name == SUDO_PROCESS_ACCOUNT):
        raise ValueError('System and application accounts cannot be changed here')
    return ent


def uid_min() -> int:
    try:
        content = Path('/etc/login.defs').read_text()
        m = re.search(r'^\s*UID_MIN\s+(\d+)\s*$', content, re.M)
        return int(m.group(1)) if m else 1000
    except OSError:
        return 1000


def gid_min() -> int:
    try:
        content = Path('/etc/login.defs').read_text()
        m = re.search(r'^\s*GID_MIN\s+(\d+)\s*$', content, re.M)
        return int(m.group(1)) if m else 1000
    except OSError:
        return 1000


def assert_fs_path(path: str, *, allow_missing: bool = False) -> Path:
    path = text(path)
    p = Path(path)
    if not p.is_absolute() or path == '/' or '..' in p.parts:
        raise ValueError('Invalid filesystem path')
    # Reject symlink traversals in every existing path component, not just leaf.
    current = Path('/')
    for part in p.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ValueError('Symbolic links are not allowed for filesystem operations')
    rp = os.path.realpath(str(p))
    if not any(rp.startswith(prefix + '/') for prefix in ALLOWED_FS_ROOTS):
        raise ValueError('Filesystem changes are restricted to share data roots: '
                         + ', '.join(ALLOWED_FS_ROOTS))
    if not allow_missing and not p.is_dir():
        raise ValueError('Share path is not an existing directory')
    return p


def access_section(name: str) -> tuple[SmbConf, dict[str, str]]:
    config = SmbConf(CONF.read_text())
    if name.casefold() in PROTECTED_SHARES or name not in config.sections():
        raise ValueError('Share not editable here')
    return config, config.options(name)


def parse_defaults() -> dict[str, dict[str, str]]:
    # testparm -v lists compile-time defaults. Dummy share exposes service defaults.
    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=True) as tmp:
        tmp.write('[global]\n[__samba_admin_default_share__]\n    path = /tmp\n')
        tmp.flush()
        try:
            parsed = SmbConf(cmd(['testparm', '-s', '-v', tmp.name], timeout=15))
            return {'global': parsed.options('global'),
                    'share': parsed.options('__samba_admin_default_share__')}
        except (ValueError, OSError):
            return {'global': {}, 'share': {}}


def samba_accounts():
    try:
        result = cmd(['pdbedit', '-L'])
        return sorted({row.split(':', 1)[0] for row in result.splitlines() if ':' in row})
    except (ValueError, OSError):
        return []


def status(_):
    data = SmbConf(CONF.read_text())
    accounts = set(samba_accounts())
    minimum = uid_min()
    users = []
    for u in pwd.getpwall():
        if u.pw_uid < minimum and u.pw_name not in accounts:
            continue
        if u.pw_name == 'nobody':
            continue
        users.append({'name': u.pw_name, 'uid': u.pw_uid, 'gid': u.pw_gid,
                      'home': u.pw_dir, 'shell': u.pw_shell,
                      'samba': u.pw_name in accounts,
                      'managed': u.pw_uid >= minimum and u.pw_name != SUDO_PROCESS_ACCOUNT})
    groups = []
    for g in grp.getgrall():
        if g.gr_gid < gid_min() and not any(u['gid'] == g.gr_gid for u in users):
            continue
        members = sorted({*g.gr_mem, *(u['name'] for u in users if u['gid'] == g.gr_gid)})
        groups.append({'name': g.gr_name, 'gid': g.gr_gid, 'members': members,
                       'managed': g.gr_gid >= gid_min()})
    shares = []
    for name in data.sections():
        if name.lower() == 'global':
            continue
        opts = data.options(name)
        loc = opts.get('path', '')
        fs = None
        if loc and Path(loc).is_dir():
            try:
                st = os.stat(loc)
                fs = {'user': pwd.getpwuid(st.st_uid).pw_name,
                      'group': grp.getgrgid(st.st_gid).gr_name,
                      'mode': format(stat.S_IMODE(st.st_mode), '04o')}
                if shutil.which('getfacl'):
                    fs['acl'] = cmd(['getfacl', '-cp', '--', loc], timeout=10)
            except (KeyError, OSError, ValueError):
                fs = None
        shares.append({'name': name, 'options': opts, 'fs': fs,
                       'protected': name.casefold() in PROTECTED_SHARES})
    return {'revision': data.checksum(), 'raw': data.content,
            'global': data.options('global'), 'defaults': parse_defaults(),
            'users': sorted(users, key=lambda u: u['name']),
            'groups': sorted(groups, key=lambda g: g['name']),
            'shares': shares, 'include_warning': any('include' in data.options(section) for section in data.sections()),
            'run_as': SUDO_PROCESS_ACCOUNT,
            'services': services_status()}


def replace_config(new: SmbConf, old_content: str):
    # Save original, then atomic replace; rollback if smbd cannot reload.
    if CONF.is_symlink() or not CONF.is_file():
        raise ValueError('smb.conf must be a regular file, not a symlink')
    prior_stat = CONF.stat()
    backup = CONF.with_name(f'{CONF.name}.samba-admin-{dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")}.bak')
    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IMODE(prior_stat.st_mode))
    with os.fdopen(fd, 'w') as out:
        os.fchown(out.fileno(), prior_stat.st_uid, prior_stat.st_gid)
        out.write(old_content)
        out.flush()
        os.fsync(out.fileno())
    stage = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', prefix='.samba-admin-', dir=CONF.parent,
                                         delete=False) as tmp:
            stage = Path(tmp.name)
            os.fchmod(tmp.fileno(), stat.S_IMODE(prior_stat.st_mode))
            os.fchown(tmp.fileno(), prior_stat.st_uid, prior_stat.st_gid)
            tmp.write(new.content)
            tmp.flush()
            os.fsync(tmp.fileno())
        cmd(['testparm', '-s', str(stage)])
        os.replace(stage, CONF)
        stage = None
        # Saving configuration while the service is stopped is valid: reload
        # only if smbd is currently running. Starting it later picks up changes.
        smbd = unit_properties('smbd.service')
        reload_needed = smbd.get('LoadState') == 'loaded' and smbd.get('ActiveState') == 'active'
        if not reload_needed:
            return {'backup': str(backup), 'reload': 'skipped'}
        try:
            cmd(['systemctl', 'reload', '--', 'smbd.service'])
        except (ValueError, OSError) as exc:
            # A second copy preserves the immutable backup as a recovery artifact.
            restore = None
            try:
                with tempfile.NamedTemporaryFile(mode='wb', dir=CONF.parent,
                                                 prefix='.samba-restore-', delete=False) as tmp:
                    restore = Path(tmp.name)
                    os.fchmod(tmp.fileno(), stat.S_IMODE(prior_stat.st_mode))
                    os.fchown(tmp.fileno(), prior_stat.st_uid, prior_stat.st_gid)
                    tmp.write(old_content.encode())
                    tmp.flush()
                    os.fsync(tmp.fileno())
                os.replace(restore, CONF)
                restore = None
                cmd(['systemctl', 'reload', '--', 'smbd.service'])
            finally:
                if restore is not None:
                    restore.unlink(missing_ok=True)
            raise ValueError(f'Samba reload failed; restored original config: {exc}') from exc
    finally:
        if stage is not None:
            stage.unlink(missing_ok=True)
    return {'backup': str(backup), 'reload': 'reloaded'}


def edit_config(payload):
    expected = text(payload['revision'], 64)
    with open(LOCK, 'a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        old = CONF.read_text()
        conf = SmbConf(old)
        if expected != conf.checksum():
            raise ValueError('Configuration changed since the page loaded; refresh before saving')
        action = payload['type']
        if action == 'global_save':
            updates = payload['updates']
            validate_updates('global', updates)
            updated = conf.update('global', updates)
        elif action == 'share_save':
            name = text(payload['name'], 62).strip()
            validate_share(name)
            old_name = text(payload.get('old_name', ''), 62).strip()
            updates = payload['updates']
            validate_updates('share', updates)
            if not old_name:
                if not updates.get('path'):
                    raise ValueError('Directory required for new share')
                updated = conf.update(name, updates, create=True)
            else:
                if old_name != name:
                    raise ValueError('Rename by creating a new share and deleting the old share')
                if old_name.casefold() in PROTECTED_SHARES:
                    raise ValueError('Protected share')
                updated = conf.update(name, updates)
                if not updated.options(name).get('path'):
                    raise ValueError('Share needs a directory')
        elif action == 'share_delete':
            name = text(payload['name'], 62)
            validate_share(name)
            if text(payload.get('confirm', '')) != name:
                raise ValueError('Share deletion confirmation did not match')
            updated = conf.delete(name)
        else:
            raise ValueError('Unknown configuration operation')
        if updated.content == old:
            return {'unchanged': True}
        return replace_config(updated, old)


def user_create(p):
    name = text(p['username'], 32)
    validate_username(name)
    if name == SUDO_PROCESS_ACCOUNT:
        raise ValueError('Cannot manage application service account')
    nohome, nologin = bool_value(p['nohome']), bool_value(p['nologin'])
    shell = next((f for f in ('/usr/sbin/nologin', '/sbin/nologin') if Path(f).exists()), None) if nologin else '/bin/bash'
    if not shell:
        raise ValueError('nologin executable not found')
    args = ['useradd', '-s', shell]
    if nohome:
        args += ['-M', '-d', '/nonexistent']
    else:
        args += ['-m']
    primary = text(p.get('primary_group', ''), 32)
    if primary:
        validate_group(primary)
        grp.getgrnam(primary)
        args += ['-g', primary]
    else:
        args += ['-U']
    args += ['--', name]
    cmd(args)
    return {'created': name}


def user_shell(p):
    name = text(p['username'], 32)
    must_user(name)
    nologin = bool_value(p['nologin'])
    shell = next((f for f in ('/usr/sbin/nologin', '/sbin/nologin') if Path(f).exists()), None) if nologin else '/bin/bash'
    if not shell:
        raise ValueError('nologin executable not found')
    cmd(['usermod', '-s', shell, '--', name])
    return {'updated': name}


def user_home(p):
    """Change a login's *configured* home; never delete or migrate old files."""
    name = text(p['username'], 32)
    ent = must_user(name)
    nohome = bool_value(p['nohome'])
    if nohome:
        cmd(['usermod', '-d', '/nonexistent', '--', name])
        return {'updated': name, 'old_home_kept': True}
    destination = Path('/home') / name
    if destination.is_symlink():
        raise ValueError('Home directory may not be a symlink')
    if destination.exists():
        if not destination.is_dir() or destination.stat().st_uid != ent.pw_uid:
            raise ValueError('Existing home directory is not owned by the selected user')
    else:
        # Creating a new empty home is optional and does not migrate the old home.
        destination.mkdir(mode=0o700)
        os.chown(destination, ent.pw_uid, ent.pw_gid)
    cmd(['usermod', '-d', str(destination), '--', name])
    return {'updated': name, 'old_home_kept': True}


def user_delete(p):
    name = text(p['username'], 32)
    must_user(name)
    if text(p.get('confirm', '')) != name:
        raise ValueError('Type the username to confirm deletion')
    # Delete Samba password before Unix account. Do not remove home files.
    if name in samba_accounts():
        cmd(['smbpasswd', '-x', name])
    cmd(['userdel', '--', name])
    return {'deleted': name, 'home_kept': True}


def group_create(p):
    group = text(p['group'], 32)
    validate_group(group)
    cmd(['groupadd', '--', group])
    return {'created': group}


def group_delete(p):
    group = text(p['group'], 32)
    validate_group(group)
    g = grp.getgrnam(group)
    if (g.gr_gid < gid_min() or group == SUDO_PROCESS_ACCOUNT
            or g.gr_gid == pwd.getpwnam(SUDO_PROCESS_ACCOUNT).pw_gid):
        raise ValueError('System/application group cannot be deleted')
    if text(p.get('confirm', '')) != group:
        raise ValueError('Type the group name to confirm deletion')
    cmd(['groupdel', '--', group])
    return {'deleted': group}


def membership(p):
    user, group = text(p['username'], 32), text(p['group'], 32)
    must_user(user)
    validate_group(group)
    grp.getgrnam(group)
    operation = p['operation']
    if operation == 'add':
        cmd(['usermod', '-aG', group, '--', user])
    elif operation == 'remove':
        if pwd.getpwnam(user).pw_gid == grp.getgrnam(group).gr_gid:
            raise ValueError('Cannot remove primary group membership; change primary group separately')
        cmd(['gpasswd', '-d', user, group])
    else:
        raise ValueError('Unknown membership action')
    return {'updated': user}


def samba_password(p):
    user = text(p['username'], 32)
    must_user(user)
    secret = text(p['password'], 256)
    if not secret:
        raise ValueError('Samba password cannot be blank')
    if len(secret) > 127:
        raise ValueError('Samba password is too long')
    # smbpasswd -s reads two password lines. Root has no old password prompt.
    cmd(['smbpasswd', '-s', '-a', user], input_text=f'{secret}\n{secret}\n')
    cmd(['smbpasswd', '-e', user])
    return {'password_set': user}


def samba_toggle(p):
    user = text(p['username'], 32)
    must_user(user)
    operation = p['operation']
    if operation not in ('enable', 'disable', 'remove'):
        raise ValueError('Invalid Samba user operation')
    cmd(['smbpasswd', {'enable': '-e', 'disable': '-d', 'remove': '-x'}[operation], user])
    return {'updated': user}


def share_directory(p):
    name = text(p['name'], 62)
    _, opt = access_section(name)
    path = assert_fs_path(opt['path'], allow_missing=bool_value(p['create']))
    if p['create']:
        path.mkdir(parents=True, mode=0o770, exist_ok=True)
    if not path.is_dir():
        raise ValueError('Directory does not exist')
    user, group = text(p.get('owner', ''), 32), text(p.get('group', ''), 32)
    mode = text(p.get('mode', ''), 4)
    if user:
        validate_username(user)
        pwd.getpwnam(user)
    if group:
        validate_group(group)
        grp.getgrnam(group)
    if mode and not MODE.fullmatch(mode):
        raise ValueError('Filesystem mode must be 3 or 4 octal digits')
    if user or group:
        cmd(['chown', (user or '') + ':' + (group or ''), '--', str(path)])
    if mode:
        cmd(['chmod', mode, '--', str(path)])
    return {'updated': str(path), 'recursive': False}


def acl_update(p):
    name = text(p['name'], 62)
    _, opts = access_section(name)
    path = assert_fs_path(opts['path'])
    kind = p['kind']
    principal = text(p['principal'], 32)
    if kind == 'user':
        validate_username(principal)
        pwd.getpwnam(principal)
        prefix = 'u'
    elif kind == 'group':
        validate_group(principal)
        grp.getgrnam(principal)
        prefix = 'g'
    else:
        raise ValueError('Invalid ACL kind')
    default = bool_value(p['default'])
    prefix = ('d:' if default else '') + prefix + ':' + principal
    operation = p['operation']
    if operation == 'set':
        permissions = text(p['permissions'], 3)
        if not re.fullmatch(r'[r-][w-][x-]', permissions):
            raise ValueError('ACL permissions must resemble rwx, rw-, r-x, etc.')
        cmd(['setfacl', '-m', f'{prefix}:{permissions}', '--', str(path)])
    elif operation == 'remove':
        cmd(['setfacl', '-x', prefix, '--', str(path)])
    else:
        raise ValueError('Unknown ACL operation')
    return {'updated': str(path)}


ACTIONS = {
    'ping': lambda _: {'sudo': 'ok'}, 'service_control': service_control,
    'status': status, 'config': edit_config,
    'user_create': user_create, 'user_shell': user_shell, 'user_home': user_home, 'user_delete': user_delete,
    'group_create': group_create, 'group_delete': group_delete, 'membership': membership,
    'samba_password': samba_password, 'samba_toggle': samba_toggle,
    'share_directory': share_directory, 'acl_update': acl_update,
}


def main():
    if os.geteuid() != 0:
        print(json.dumps({'ok': False, 'error': 'Privileged helper must run as root'}))
        return 1
    print('__SAMBA_ADMIN_READY__', flush=True)
    try:
        line = sys.stdin.buffer.readline(MAX_PAYLOAD + 1)
        if len(line) > MAX_PAYLOAD or not line.endswith(b'\n'):
            raise ValueError('Invalid/oversized request')
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise ValueError('Expected JSON object')
        action = payload.get('action')
        if action not in ACTIONS:
            raise ValueError('Unsupported privileged action')
        data = ACTIONS[action](payload)
        print(json.dumps({'ok': True, 'data': data}))
    except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({'ok': False, 'error': str(exc)[:1200]}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
