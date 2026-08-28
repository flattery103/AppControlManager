import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVER = ROOT / 'server'
if str(SERVER) not in sys.path:
    sys.path.insert(0, str(SERVER))
os.environ['APPCONTROL_DB'] = str(Path(tempfile.gettempdir()) / 'acm-0163-timezone.db')

import app


class TimezoneTests(unittest.TestCase):
    def test_format_display_time_uses_dst_aware_iana_timezone(self):
        self.assertEqual(app.format_display_time('2026-01-15T18:00:00+00:00', 'America/Chicago'), 'Jan 15, 2026 12:00 PM')
        self.assertEqual(app.format_display_time('2026-07-15T18:00:00+00:00', 'America/Chicago'), 'Jul 15, 2026 1:00 PM')

    def test_invalid_timezone_falls_back_to_utc(self):
        self.assertEqual(app.format_display_time('2026-08-28T00:04:00+00:00', 'Not/AZone'), 'Aug 28, 2026 12:04 AM')

    def test_server_settings_table_is_additive(self):
        app.init_db()
        with app.db() as conn:
            row = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='server_settings'").fetchone()
            self.assertIsNotNone(row)

    def test_utcnow_remains_utc_storage(self):
        value = app.utcnow()
        self.assertIn('+00:00', value)

    def test_settings_nav_and_routes_exist(self):
        text = (SERVER / 'app.py').read_text(encoding='utf-8')
        self.assertIn("('/settings','Settings'", text)
        self.assertIn("@app.get('/settings'", text)
        self.assertIn("@app.post('/admin/settings/timezone'", text)


    def test_settings_ui_is_global_admin_only_and_explains_iana_timezone(self):
        text = (SERVER / 'app.py').read_text(encoding='utf-8')
        self.assertIn("administration.append(('/settings','Settings','⚙'))", text)
        self.assertIn('Global administrator permission required.', text)
        self.assertIn('Current display timezone', text)
        self.assertIn("list='timezone-list'", text)
        self.assertIn('America/Chicago', text)
        self.assertIn('Timezone saved', text)


if __name__ == '__main__':
    unittest.main()
