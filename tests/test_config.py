import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from smbconfig import SmbConf
from schema import validate_updates


class ConfigurationTests(unittest.TestCase):
    source = '''# Samba config\n[global]\n    workgroup = WORKGROUP\n    # keep me\n    log level = 1\n\n[Documents]\n    path = /srv/samba/docs\n    custom option = untouched\n    read only = yes\n\n[Other]\n    path = /srv/samba/other\n'''

    def test_preserve_comments_and_unmanaged_keys(self):
        changed = SmbConf(self.source).update('Documents', {'read only': 'no', 'guest ok': 'no'})
        self.assertEqual(changed.options('Documents')['read only'], 'no')
        self.assertEqual(changed.options('Documents')['guest ok'], 'no')
        self.assertIn('# keep me', changed.content)
        self.assertIn('custom option = untouched', changed.content)
        self.assertIn('[Other]', changed.content)
        self.assertEqual(changed.options('Other')['path'], '/srv/samba/other')

    def test_delete_setting_reverts_default(self):
        changed = SmbConf(self.source).update('Documents', {'read only': None})
        self.assertNotIn('read only', changed.options('Documents'))

    def test_duplicate_keys_are_deduplicated(self):
        source = '[global]\n workgroup = A\n workgroup = B\n'
        changed = SmbConf(source).update('global', {'workgroup': 'C'})
        self.assertEqual(changed.content.count('workgroup ='), 1)
        self.assertEqual(changed.options('global')['workgroup'], 'C')

    def test_new_share_and_delete(self):
        new = SmbConf(self.source).update('New', {'path': '/srv/samba/new'}, create=True)
        self.assertEqual(new.options('New')['path'], '/srv/samba/new')
        again = new.delete('New')
        self.assertNotIn('New', again.sections())
        self.assertIn('Documents', again.sections())

    def test_reject_newline_and_unsafe_value(self):
        with self.assertRaises(ValueError):
            SmbConf(self.source).update('global', {'workgroup': 'TEST\n[malicious]'})
        with self.assertRaises(ValueError):
            validate_updates('share', {'path': '/srv\n[evil]'})
        with self.assertRaises(ValueError):
            validate_updates('share', {'unlisted parameter': 'anything'})

    def test_optimistic_version(self):
        self.assertEqual(len(SmbConf(self.source).checksum()), 64)
        self.assertNotEqual(SmbConf(self.source).checksum(), SmbConf(self.source + '\n').checksum())


if __name__ == '__main__':
    unittest.main()
