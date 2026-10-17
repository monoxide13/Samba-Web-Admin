"""No service changes may be attempted for an unavailable systemd unit."""
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import root_worker as worker


class ServiceTests(unittest.TestCase):
    def test_unit_properties_inactive_service_is_installed(self):
        result = subprocess.CompletedProcess(args=[], returncode=0, stdout=(
            'LoadState=loaded\nActiveState=inactive\nSubState=dead\nUnitFileState=disabled\n'), stderr='')
        with patch.object(worker.subprocess, 'run', return_value=result) as run:
            props = worker.unit_properties('smbd.service')
        self.assertEqual(props['ActiveState'], 'inactive')
        self.assertIn('--', run.call_args.args[0])

    def test_missing_and_masked_services_are_not_controllable(self):
        with patch.object(worker, 'unit_properties', side_effect=lambda unit: {
            'LoadState': 'masked' if unit == 'smbd.service' else 'not-found'
        }), patch.object(worker, 'cmd') as command:
            services = worker.services_status()
            self.assertEqual(len(services), 4)
            self.assertTrue(all(not item['installed'] for item in services))
            with self.assertRaisesRegex(ValueError, 'no installed'):
                worker.service_control({'service': 'smbd', 'command': 'restart'})
            command.assert_not_called()

    def test_winbind_alias_resolved_and_only_selected_unit_started(self):
        def details(unit):
            return {'LoadState': 'loaded', 'ActiveState': 'inactive', 'SubState': 'dead'} \
                if unit == 'winbind.service' else {'LoadState': 'not-found'}
        with patch.object(worker, 'unit_properties', side_effect=details), \
             patch.object(worker, 'cmd', return_value='') as command:
            services = worker.services_status()
            self.assertEqual(next(item for item in services if item['name'] == 'winbindd')['unit'],
                             'winbind.service')
            result = worker.service_control({'service': 'winbindd', 'command': 'start'})
            command.assert_called_once_with(['systemctl', 'start', '--', 'winbind.service'],
                                            timeout=38)
            self.assertEqual(result['unit'], 'winbind.service')

    def test_dc_canonical_name(self):
        with patch.object(worker, 'unit_properties', side_effect=lambda unit: {
            'LoadState': 'loaded', 'ActiveState': 'active', 'SubState': 'running'
        } if unit == 'samba-ad-dc.service' else {}):
            self.assertEqual(worker.services_status()[-1]['unit'], 'samba-ad-dc.service')

    def test_reject_unapproved_operations_without_systemctl(self):
        with patch.object(worker, 'cmd') as command, \
             patch.object(worker, 'unit_properties') as probe:
            for value in ('enable', 'disable', 'reload', 'status', 'start;rm -rf /'):
                with self.assertRaises(ValueError):
                    worker.service_control({'service': 'smbd', 'command': value})
            with self.assertRaises(ValueError):
                worker.service_control({'service': 'not-a-service', 'command': 'start'})
            command.assert_not_called()
            probe.assert_not_called()


if __name__ == '__main__':
    unittest.main()
