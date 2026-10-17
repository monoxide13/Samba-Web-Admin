"""Safely recognize the externally visible WSGI mount path.

Trust proxy headers only from explicitly listed proxy source networks.
"""
from __future__ import annotations

import ipaddress
import os
import re

# A reverse proxy must identify the externally visible mount path if it
# strips that path before forwarding. When it retains the prefix, the path
# itself is enough to infer the mount. Do not trust forwarded headers from
# arbitrary clients on the publicly bound listener.
TRUSTED_PROXIES = tuple(
    ipaddress.ip_network(item.strip(), strict=False)
    for item in os.getenv('SAMBA_ADMIN_TRUSTED_PROXIES', '127.0.0.1/32,::1/128').split(',')
    if item.strip()
)


def valid_prefix(prefix: str) -> str:
    """Return a safe URL mount path, or '' for an invalid/empty prefix."""
    if not isinstance(prefix, str) or not prefix.startswith('/') or ',' in prefix:
        return ''
    prefix = prefix.rstrip('/')
    if not prefix or not re.fullmatch(r'/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+', prefix):
        return ''
    return prefix


def path_prefix(path: str) -> str:
    """Infer a retained proxy prefix from one of this app's known routes."""
    for suffix in ('/credentials', '/logout', '/action', '/accounts', '/shares'):
        if path == suffix:
            return ''
        if path.endswith(suffix):
            return valid_prefix(path[:-len(suffix)])
    if '/static/' in path:
        return valid_prefix(path.split('/static/', 1)[0])
    if path.startswith('/') and path not in ('/', '/static'):
        # Any extra path ending in '/' acts as a mounted index page.
        if path.endswith('/'):
            return valid_prefix(path[:-1])
        # '/samba' (no trailing slash) is also a valid mount URL.
        if path.count('/') == 1 and path not in ('/favicon.ico',):
            return valid_prefix(path)
    return ''


def peer_is_proxy(remote: str) -> bool:
    try:
        address = ipaddress.ip_address(remote)
        return any(address in network for network in TRUSTED_PROXIES)
    except ValueError:
        return False


class MountPathMiddleware:
    """Set WSGI SCRIPT_NAME so every url_for() is relative to the mount."""
    def __init__(self, application):
        self.application = application

    def __call__(self, environ, start_response):
        path = environ.get('PATH_INFO', '/')
        prefix = ''
        if peer_is_proxy(environ.get('REMOTE_ADDR', '')):
            prefix = valid_prefix(environ.get('HTTP_X_FORWARDED_PREFIX', '')
                                  or environ.get('HTTP_X_SCRIPT_NAME', ''))
        if not prefix:
            prefix = path_prefix(path)
        if prefix and not environ.get('SCRIPT_NAME'):
            environ['SCRIPT_NAME'] = prefix
            if path == prefix:
                environ['PATH_INFO'] = '/'
            elif path.startswith(prefix + '/'):
                environ['PATH_INFO'] = path[len(prefix):] or '/'
        return self.application(environ, start_response)


