import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import root_worker as worker
from smbconfig import SmbConf


class WorkerTests(unittest.TestCase):
    def test_config_edit_requires_current_checksum(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / 'smb.conf'
            lock = Path(temp) / 'lock'
            config.write_text('[global]\n workgroup = SAMPLE\n')
            with patch.object(worker, 'CONF', config), patch.object(worker, 'LOCK', lock), \
                 patch.object(worker, 'replace_config') as replace:
                with self.assertRaisesRegex(ValueError, 'changed since'):
                    worker.edit_config({'revision': '0' * 64, 'type': 'global_save',
                                        'updates': {'workgroup': 'WORKGROUP'}})
                replace.assert_not_called()
                worker.edit_config({'revision': SmbConf(config.read_text()).checksum(),
                                    'type': 'global_save', 'updates': {'workgroup': 'WORKGROUP'}})
                replace.assert_called_once()
                self.assertEqual(replace.call_args.args[0].options('global')['workgroup'], 'WORKGROUP')

    def test_save_config_with_smbd_stopped_does_not_attempt_reload(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / 'smb.conf'
            original = '[global]\n workgroup = TEST\n'
            config.write_text(original)
            updated = SmbConf(original).update('global', {'workgroup': 'NEW'})
            with patch.object(worker, 'CONF', config), \
                 patch.object(worker, 'unit_properties', return_value={
                     'LoadState': 'loaded', 'ActiveState': 'inactive'}), \
                 patch.object(worker, 'cmd', return_value='') as commands, \
                 patch.object(worker.os, 'fchown'):
                result = worker.replace_config(updated, original)
            self.assertEqual(result['reload'], 'skipped')
            self.assertEqual(commands.call_count, 1)  # testparm only
            self.assertEqual(commands.call_args.args[0][0], 'testparm')
            self.assertIn('NEW', config.read_text())
            self.assertTrue(Path(result['backup']).exists())

    def test_save_config_with_smbd_active_reloads(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / 'smb.conf'
            original = '[global]\n workgroup = TEST\n'
            config.write_text(original)
            updated = SmbConf(original).update('global', {'workgroup': 'NEW'})
            with patch.object(worker, 'CONF', config), \
                 patch.object(worker, 'unit_properties', return_value={
                     'LoadState': 'loaded', 'ActiveState': 'active'}), \
                 patch.object(worker, 'cmd', return_value='') as commands, \
                 patch.object(worker.os, 'fchown'):
                result = worker.replace_config(updated, original)
            self.assertEqual(result['reload'], 'reloaded')
            self.assertEqual(commands.call_args.args[0],
                             ['systemctl', 'reload', '--', 'smbd.service'])

    def test_directory_path_rejects_symlink_escape(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'safe').mkdir()
            (root / 'safe' / 'link').symlink_to('/etc')
            with patch.object(worker, 'ALLOWED_FS_ROOTS', (temp,)):
                worker.assert_fs_path(str(root / 'safe'))
                with self.assertRaisesRegex(ValueError, 'Symbolic links'):
                    worker.assert_fs_path(str(root / 'safe' / 'link' / 'passwd'))
                with self.assertRaises(ValueError):
                    worker.assert_fs_path('/etc')

    def test_protect_known_samba_share(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / 'smb.conf'
            config.write_text('[global]\n[homes]\n path = /home/%S\n')
            with patch.object(worker, 'CONF', config):
                with self.assertRaises(ValueError):
                    worker.access_section('homes')


if __name__ == '__main__':
    unittest.main()
