"""Render the modified pages with Jinja2 to catch template syntax regressions."""
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

from jinja2 import Environment, FileSystemLoader, select_autoescape

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from schema import GLOBALS
from root_worker import SERVICE_LABELS


class TemplateTests(unittest.TestCase):
    def setUp(self):
        self.env = Environment(loader=FileSystemLoader(Path(__file__).resolve().parents[1] / 'templates'),
                               autoescape=select_autoescape(['html']))
        self.env.globals.update(
            url_for=lambda endpoint, **kw: '/samba/' + ('' if endpoint == 'system' else
                              ('static/style.css' if endpoint == 'static' else endpoint)),
            get_flashed_messages=lambda **kw: [],
            request=SimpleNamespace(endpoint='system'),
        )

    def render(self, authorized=False, installed=True):
        services = [dict(name=name, label=label, installed=installed,
                         unit=(name + '.service') if installed else '',
                         active='active' if installed else 'not installed',
                         substate='running' if installed else '')
                    for name, label in SERVICE_LABELS.items()]
        return self.env.get_template('system.html').render(
            title='System configuration', authorized=authorized, account='testaccount', csrf='xyz',
            fields=GLOBALS, data={
                'services': services, 'include_warning': False, 'global': {},
                'defaults': {'global': {}}, 'revision': 'abc', 'raw': '[global]\n',
            } if authorized else None)

    def test_login_notice_and_prefix_links(self):
        html = self.render()
        self.assertIn('Single-session administration recommended.', html)
        self.assertIn('href="/samba/static/style.css"', html)
        self.assertIn('href="/samba/accounts"', html)
        self.assertIn('action="/samba/credentials"', html)

    def test_controls_display_when_installed(self):
        html = self.render(authorized=True)
        self.assertIn('Refreshing this page re-reads', html)
        self.assertIn('Samba service controls', html)
        self.assertEqual(html.count('name="operation" value="service_control"'), 12)
        self.assertIn('action="/samba/action"', html)

    def test_no_controls_for_uninstalled(self):
        html = self.render(authorized=True, installed=False)
        self.assertNotIn('name="operation" value="service_control"', html)
        self.assertIn('No actions', html)


if __name__ == '__main__':
    unittest.main()
