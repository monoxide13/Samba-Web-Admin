"""Exercise path rewriting without relying on installed Flask/Waitress."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import urlmount


class MountPathTests(unittest.TestCase):
    def setUp(self):
        self.calls = []

        def downstream(environ, start_response):
            self.calls.append((environ.get('SCRIPT_NAME', ''), environ['PATH_INFO']))
            start_response('200 OK', [])
            return [b'OK']
        self.middleware = urlmount.MountPathMiddleware(downstream)

    def req(self, path, peer='192.0.2.1', **extra):
        env = {'PATH_INFO': path, 'SCRIPT_NAME': '', 'REMOTE_ADDR': peer, **extra}
        self.assertEqual(list(self.middleware(env, lambda *_: None)), [b'OK'])
        return self.calls[-1]

    def test_root_remains_root_and_routes_not_mistaken_for_mounts(self):
        for path in ('/', '/accounts', '/shares', '/action', '/credentials',
                     '/logout', '/static/style.css'):
            self.assertEqual(self.req(path), ('', path))

    def test_preserved_prefix_and_direct_mount_entry(self):
        cases = {
            '/samba': ('/samba', '/'), '/samba/': ('/samba', '/'),
            '/samba/accounts': ('/samba', '/accounts'),
            '/samba/shares': ('/samba', '/shares'),
            '/samba/action': ('/samba', '/action'),
            '/samba/static/style.css': ('/samba', '/static/style.css'),
            '/admin/samba/accounts': ('/admin/samba', '/accounts'),
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(self.req(path), expected)

    def test_stripped_prefix_with_proxy_header(self):
        self.assertEqual(self.req('/accounts', peer='127.0.0.1',
                                  HTTP_X_FORWARDED_PREFIX='/samba'),
                         ('/samba', '/accounts'))
        self.assertEqual(self.req('/', peer='::1', HTTP_X_FORWARDED_PREFIX='/samba/'),
                         ('/samba', '/'))

    def test_untrusted_forwarded_header_ignored(self):
        self.assertEqual(self.req('/accounts', HTTP_X_FORWARDED_PREFIX='/malicious'),
                         ('', '/accounts'))
        self.assertEqual(self.req('/', peer='127.0.0.1',
                                  HTTP_X_FORWARDED_PREFIX='//invalid'), ('', '/'))
        self.assertEqual(self.req('/', peer='127.0.0.1',
                                  HTTP_X_FORWARDED_PREFIX='/bad, /samba'), ('', '/'))

    def test_existing_script_name_left_untouched(self):
        env = {'REMOTE_ADDR': '127.0.0.1', 'PATH_INFO': '/shares',
               'SCRIPT_NAME': '/already-mounted', 'HTTP_X_FORWARDED_PREFIX': '/samba'}
        self.middleware(env, lambda *_: None)
        self.assertEqual(self.calls[-1], ('/already-mounted', '/shares'))


if __name__ == '__main__':
    unittest.main()
