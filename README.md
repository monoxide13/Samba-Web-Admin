# Samba Web Admin

A three-page Python web interface for administering a **standalone Linux Samba file server**. It edits the real `/etc/samba/smb.conf`, creates timestamped backup copies, validates the new configuration using `testparm`, atomically installs it, and reloads `smbd` **if it is running**. If `smbd` is stopped, the new configuration is saved and will be used when the service starts. System users, groups, Samba passwords, Unix share-directory ownership/modes, and POSIX ACLs are managed using standard Linux commands.

## Intended environment

Ubuntu 22.04+ or a similar Debian-family standalone Samba file server using local POSIX users and the default `smb.conf` path. **Not designed for Samba AD domain controllers, AD/LDAP-managed identities, clustered Samba, or registry-backed shares.** The app deliberately exposes a useful subset of Samba's options rather than attempting to reproduce all of `smb.conf`.

It has **no web-app account database or login system**. Each browser must independently enter credentials for the **Linux user running the web process** (which must have sudo access). This is a privilege gate, not a remotely accessible authentication service. Only one web process is supported; credentials are cached in RAM (not in cookies or on disk) for 15 minutes of inactivity. The browser's signed, HttpOnly, SameSite=Strict cookie carries only a random session ID. Closing a browser tab does not necessarily erase the browser cookie; use **Clear credentials** or let it expire. Cookies or sessions copied to another browser could be reused like any bearer session, so physical control and encrypted transport still matter.

**Concurrent browser sessions are not recommended:** the login form warns about this. `smb.conf` changes are guarded by a file-revision check, but simultaneous Linux user/group/permission operations may still collide or overwrite changes. Refreshing a page fetches a new snapshot of the actual `/etc/samba/smb.conf`, users/groups, and systemd services; refreshing discards unsaved form edits.

The server **listens on all IPv4 interfaces** by default (`0.0.0.0:8080`), allowing connections from any reachable IP address. The application does not impose an IP allowlist or firewall rule: securing its exposure is the administrator's responsibility. HTTP transmits sudo credentials and session cookies without transport encryption; use HTTPS through a reverse proxy or a trusted network if that matters for your deployment. Set `SAMBA_ADMIN_SECURE_COOKIE=1` when accessing exclusively via HTTPS so browser cookies are sent only over HTTPS. The app still refuses to run its web server as root.

## Installation

```bash
sudo apt update
sudo apt install samba samba-common-bin acl sudo python3-venv python3-pip
# Copy this extracted directory into /opt/samba-web-admin.
sudo mkdir -p /opt/samba-web-admin
sudo cp -a ./app.py ./root_worker.py ./schema.py ./smbconfig.py ./urlmount.py ./templates ./static ./requirements.txt /opt/samba-web-admin/
# Do not make this directory writable to untrusted local users.
sudo chown -R root:root /opt/samba-web-admin
sudo chmod -R go-w /opt/samba-web-admin
sudo python3 -m venv /opt/samba-web-admin/.venv
sudo /opt/samba-web-admin/.venv/bin/pip install -r /opt/samba-web-admin/requirements.txt
# Run as YOUR sudo-enabled account; NOT root.
/opt/samba-web-admin/.venv/bin/python /opt/samba-web-admin/app.py
```

Visit `http://SERVER_IP:8080` from another device (replace `SERVER_IP` with your server's LAN address), or `http://127.0.0.1:8080` locally. A user's ability to run `sudo /usr/bin/python3 /opt/samba-web-admin/root_worker.py` is required. This tool assumes the invoking user can authenticate to sudo; it does not modify sudoers. The root worker executes only known, allowlisted operations. All sudo authentication is performed against the web-process Linux identity. If the user has `NOPASSWD` sudo, sudo cannot verify the entered password; this is an inherited sudo policy limitation.

Run only when needed, and use Ctrl-C to stop the server. For a different port: `SAMBA_ADMIN_PORT=8090 /opt/samba-web-admin/.venv/bin/python /opt/samba-web-admin/app.py`. You can override the bind address with `SAMBA_ADMIN_HOST=192.168.1.10` or `SAMBA_ADMIN_HOST=127.0.0.1`; set `SAMBA_ADMIN_HOST=::` to bind IPv6 where supported. The default remains `0.0.0.0` (all IPv4 interfaces). No built-in network access restrictions are applied.

## Reverse proxy and subpath support

All internal links, static CSS URLs, form actions, and redirects use Flask `url_for` and the request's WSGI mount prefix. These entry points are supported by the same running app:

- Direct: `http://SERVER_IP:8080/` (root `/`).
- Reverse-proxied: `http://hostname/samba/` or `http://hostname/samba` (external mount `/samba`).

For an **Nginx proxy that strips `/samba/` before forwarding**, send `X-Forwarded-Prefix` explicitly so the app can reconstruct external links:

```nginx
location = /samba {
    return 301 /samba/;
}
location /samba/ {
    proxy_pass http://127.0.0.1:8080/;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Prefix /samba;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

**The trailing slash on `proxy_pass` matters:** `proxy_pass ...:8080/;` strips the external `/samba/` prefix; the header above is then necessary. Without either the original path or that header, a backend cannot know which path the browser used.

For a proxy that **retains** the `/samba` prefix in requests to the app, the application detects it from the request path; no prefix header is needed. Arbitrary prefixes (including nested paths) work in either mode when the appropriate path/header is forwarded.

To prevent clients accessing `0.0.0.0:8080` from forging a forwarded mount prefix, the app trusts `X-Forwarded-Prefix` (or `X-Script-Name`) **only from the loopback proxy addresses** `127.0.0.1` and `::1` by default. For a proxy running on another machine/container, set its source address/CIDR before launching, for example:

```bash
SAMBA_ADMIN_TRUSTED_PROXIES=127.0.0.1/32,::1/128,192.168.20.5/32 \
  /opt/samba-web-admin/.venv/bin/python /opt/samba-web-admin/app.py
```

`SAMBA_ADMIN_TRUSTED_PROXIES` changes only which upstream proxy headers are accepted, **not which IPs can connect**. Network access remains unrestricted by the app. If using HTTPS exclusively through the proxy, set `SAMBA_ADMIN_SECURE_COOKIE=1`; avoid exposing the HTTP port outside a trusted network.

## Service controls

The System configuration page includes Start, Stop, and Restart controls for these logical services, checking the systemd unit's installed/loaded state on every action:

| Display name | Debian/Ubuntu unit (other aliases also supported) |
| --- | --- |
| `smbd` | `smbd.service` |
| `nmbd` | `nmbd.service` |
| `winbindd` | `winbind.service` (`winbindd.service`) |
| `samba-dc` | `samba-ad-dc.service` (`samba-dc.service`) |

If a service is absent or masked, it appears as unavailable and has **no control buttons**. The privileged helper checks again before any start/stop/restart operation, and never attempts a control command for an unavailable unit. Start/stop/restart do not change systemd boot enablement. `samba-ad-dc.service` is normally only used for an AD domain controller, not a standalone Samba file server; don't start it just because a unit happens to be installed.

## Three pages

1. **System configuration**: start/stop/restart controls for installed Samba-related services, selected `[global]` settings with actual installation defaults from `testparm -s -v`, original configuration view, validation, backup, and reload when `smbd` is running.
2. **Users & groups**: create/delete local Linux users and groups, add/remove supplementary group membership, set interactive shell to `/usr/sbin/nologin` (or `/sbin/nologin`), choose *no home* at user creation or update an account home setting (without migrating/removing files), set/enable/disable/remove Samba passwords. New Linux users have no Linux password set. Passwords for Samba are separate. By default, Linux user deletion **retains files and home directories**.
3. **Shares & permissions**: create/edit/delete sections, allowed/read/write lists, force user/group, Unix masks, ownership and permission inheritance, filesystem owner/group/mode, and POSIX ACL entries (including default/inheritable entries).

Existing Samba special shares (`[homes]`, `[printers]`, `[print$]`) are visible but their definitions are protected from editing. Included files are **not** edited. Only direct `smb.conf` sections are managed. Comments and unrelated options inside those sections are preserved where possible. The parser is line-oriented and is not intended for advanced multiline/include-heavy Samba configurations. Test on a copy first in such environments.

## Share ownership and permission concepts

- **Samba access control**: `valid users`, `read list`, `write list`, `read only`, guest settings.
- **Unix owner and group of the share root directory**: `chown` on that *directory only*. For new group inheritance set setgid on the directory, e.g. mode `2770`.
- **Inherit Unix owner**: Samba `inherit owner = yes` affects new files and folders from clients. This is separate from root-directory `chown`.
- **Inherit Unix permissions**: Samba `inherit permissions = yes` uses parent permissions instead of create and directory masks. New files normally need directory write/search and valid ACLs to be usable by multiple people.
- **POSIX ACLs**: Set a `default` ACL for inheritance by new children. ACLs and Unix permissions can still deny access permitted by Samba share lists. Existing children are not modified recursively.
- **Force user/group**: tells Samba what Unix identity to use for filesystem operations and has different semantics from ownership of the top-level shared directory.

Directory creation/ownership/mode/ACL edits are restricted to descendants of `/srv`, `/mnt`, `/media`, `/home`, `/data`, and `/opt/samba` (change `ALLOWED_FS_ROOTS` in root_worker.py only after reviewing it). They refuse symlink traversal and only alter the root of the chosen share. Creating and removing shares never deletes their underlying files or directories. Path validation and locking guard modifications to `smb.conf`. Every configuration change creates a backup at `/etc/samba/smb.conf.samba-admin-<timestamp>.bak`.

## Verification

```bash
python3 -m unittest discover -s tests -v
sudo testparm -s /etc/samba/smb.conf
sudo systemctl status smbd
```

Be aware that `testparm` detects syntax/internal configuration errors but does not guarantee that all clients, permissions, or backing paths will function as intended.

## Limitations and behavior to know

- Only a subset of parameters is editable. Samba aliases such as `writable` (inverse of `read only`) are not automatically normalized. Avoid editing shares that use contradictory aliases in the raw file.
- This tool targets systemd and local POSIX accounts and passdb (`pdbedit`, `smbpasswd`); distributions not using systemd may need adaptation. Service detection recognizes common Debian/Ubuntu unit names and aliases.
- `smbpasswd` password changes require a preexisting Unix account and a Samba password database that supports local accounts.
- Neither Unix group membership changes nor Samba reload force existing client sessions to immediately reconnect; clients may need to disconnect/reconnect to see new permissions.
- No recursive chmod/chown, automatic migration of user homes, domain account changes, full Samba ACL editor, or automatic reconciliation of share access lists when users/groups are deleted.
- The sudo password is retained in RAM while the session is unlocked, and is sent to the local `sudo` subprocess via stdin on every root operation. The SMB password is separately sent to the root helper after sudo authentication has finished. No passwords are logged, supplied in command-line arguments, or saved in configuration files.

## A note from the author
This was vibe coded with ChatGPT.
