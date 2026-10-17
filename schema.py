"""Whitelisted SMB settings and validation."""
from __future__ import annotations
import re

# (key, label, kind, help)
GLOBALS = [
    ('workgroup', 'Workgroup', 'text', 'Windows workgroup name.'),
    ('server string', 'Server description', 'text', 'Description presented to clients.'),
    ('netbios name', 'NetBIOS name', 'text', 'Optional alternative SMB server name.'),
    ('map to guest', 'Map to guest', 'guest', 'Controls which failed logins are treated as guests.'),
    ('server min protocol', 'Minimum SMB protocol', 'protocol', 'Reject older SMB dialects; SMB1/NT1 is discouraged.'),
    ('server max protocol', 'Maximum SMB protocol', 'protocol', 'Normally left at the Samba default.'),
    ('log level', 'Log level', 'text', 'Usually 0 or 1; high values generate very large logs.'),
    ('load printers', 'Load printers', 'bool', 'Advertise printers automatically.'),
    ('usershare allow guests', 'Allow usershare guests', 'bool', 'Controls guest access for usershares (not ordinary guest shares).'),
]
SHARES = [
    ('path', 'Directory', 'path', 'Absolute filesystem path to share.'),
    ('comment', 'Description', 'text', 'Optional description visible to clients.'),
    ('browseable', 'Browseable', 'bool', 'Whether this share appears in network browsing.'),
    ('read only', 'Read only', 'bool', 'Write access is disabled unless overridden by write list.'),
    ('guest ok', 'Guest access', 'bool', 'Allow unauthenticated connections if global guest settings permit.'),
    ('valid users', 'Allowed users/groups', 'principals', 'Space-separated usernames and @group names; empty means unrestricted by this setting.'),
    ('read list', 'Read-only users/groups', 'principals', 'Users or @groups restricted to read-only for an otherwise writable share.'),
    ('write list', 'Write-allowed users/groups', 'principals', 'Users or @groups allowed to write even if share read only=yes; filesystem permissions still apply.'),
    ('force user', 'Force filesystem user', 'user', 'All authenticated connections perform file operations as this Linux user.'),
    ('force group', 'Force filesystem group', 'group', 'File operations run with this primary group.'),
    ('inherit permissions', 'Inherit parent permissions', 'bool', 'New children inherit parent Unix mode; overrides create/directory masks.'),
    ('inherit owner', 'Inherit parent ownership', 'bool', 'New files/folders inherit the parent Unix owner (Samba 4 supports yes).'),
    ('inherit acls', 'Inherit POSIX ACLs', 'bool', 'Use parent default ACLs; configure default ACLs on the directory as well.'),
    ('create mask', 'File creation mask', 'mode', 'Octal mask applied to new file permissions (unless inherit permissions=yes).'),
    ('directory mask', 'Directory creation mask', 'mode', 'Octal mask applied to new directory permissions (unless inherit permissions=yes).'),
    ('force create mode', 'Forced file mode bits', 'mode', 'Octal bits always added to new files.'),
    ('force directory mode', 'Forced folder mode bits', 'mode', 'Octal bits always added to new folders.'),
    ('hide unreadable', 'Hide unreadable files', 'bool', 'Hide directory entries the current user cannot read.'),
]
FIELDS = {'global': GLOBALS, 'share': SHARES}
PROTECTED_SHARES = {'homes', 'printers', 'print$', 'global', 'ipc$', 'admin$'}
USERNAME = re.compile(r'^[a-z_][a-z0-9_.-]{0,30}\$?$', re.I)
GROUPNAME = re.compile(r'^[a-z_][a-z0-9_.-]{0,30}$', re.I)
SHARENAME = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9 _.-]{0,60}$')
MODE = re.compile(r'^[0-7]{3,4}$')


def validate_username(name: str):
    if not USERNAME.fullmatch(name):
        raise ValueError('Username contains unsupported characters')


def validate_group(name: str):
    if not GROUPNAME.fullmatch(name):
        raise ValueError('Group name contains unsupported characters')


def validate_share(name: str):
    if not SHARENAME.fullmatch(name) or name.casefold() in PROTECTED_SHARES:
        raise ValueError('Invalid or protected share name')


def validate_value(key: str, kind: str, value: str | None):
    if value is None:
        return
    if '\r' in value or '\n' in value or '\x00' in value or len(value) > 2048:
        raise ValueError(f'Invalid value for {key}')
    if kind == 'bool' and value not in {'yes', 'no'}:
        raise ValueError(f'{key}: expected yes or no')
    if kind == 'guest' and value not in {'Never', 'Bad User', 'Bad Password', 'Bad Uid'}:
        raise ValueError('Invalid map to guest setting')
    if kind == 'protocol' and value.upper() not in {'SMB2', 'SMB2_02', 'SMB2_10', 'SMB3', 'SMB3_00', 'SMB3_02', 'SMB3_11', 'NT1', 'DEFAULT'}:
        raise ValueError('Unknown SMB protocol option')
    if kind == 'mode' and not MODE.fullmatch(value):
        raise ValueError(f'{key}: expected 3 or 4 octal digits')
    if kind == 'path' and (not value.startswith('/') or value == '/' or '[' in value or ']' in value):
        raise ValueError('Share directory must be an absolute path other than /')
    if kind == 'user':
        validate_username(value)
    if kind == 'group':
        validate_group(value)
    if kind == 'principals':
        for entry in value.replace(',', ' ').split():
            if entry.startswith('@'):
                validate_group(entry[1:])
            else:
                validate_username(entry)


def validate_updates(which: str, values: dict[str, str | None]):
    kinds = {key: kind for key, _, kind, _ in FIELDS[which]}
    if set(values) - set(kinds):
        raise ValueError('Attempt to set a non-managed Samba parameter')
    for key, value in values.items():
        validate_value(key, kinds[key], value)
    if which == 'share' and values.get('path') is None:
        # A path is required when creating a share; editing can preserve existing path.
        pass
