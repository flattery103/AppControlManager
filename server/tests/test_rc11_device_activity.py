import unittest
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class Rc11DeviceActivityTests(unittest.TestCase):
    def test_device_summary_is_limited_and_links_to_full_activity(self):
        app = (ROOT / 'server/app.py').read_text(encoding='utf-8')
        self.assertIn('timeline=sorted(timeline,key=lambda x:x[0] or \'\',reverse=True)[:25]', app)
        self.assertIn("View All Activity", app)
        self.assertIn("/devices/{device_id}/activity", app)

    def test_full_device_activity_route_is_paginated(self):
        app = (ROOT / 'server/app.py').read_text(encoding='utf-8')
        self.assertIn("@app.get('/devices/{device_id}/activity'", app)
        self.assertIn("pager(f'/devices/{device_id}/activity'", app)

    def test_equal_timestamp_activity_has_stable_nonoverlapping_pages(self):
        server_dir = ROOT / 'server'
        if str(server_dir) not in sys.path:
            sys.path.insert(0, str(server_dir))
        import app as app_module

        fd, path = tempfile.mkstemp(prefix='acm-rc11-activity-', suffix='.db')
        os.close(fd); os.unlink(path)
        old_path = app_module.DB_PATH; app_module.DB_PATH = path
        self.addCleanup(setattr, app_module, 'DB_PATH', old_path)
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        app_module.init_db(); stamp = app_module.utcnow()
        with sqlite3.connect(path) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("INSERT INTO organizations(id,name,slug,status,created_at) VALUES(99,'Org','activity-org','active',?)", (stamp,))
            conn.execute("INSERT INTO devices(id,hostname,device_key_hash,created_at,organization_id) VALUES('d1','pc','x',?,99)", (stamp,))
            for i in range(60):
                conn.execute("INSERT INTO commands(device_id,command_type,payload,status,created_at,result) VALUES('d1','test','{}','completed',?,?)", (stamp, f'command-{i}'))
            conn.commit()
            first = app_module.device_activity_rows(conn, 'd1', 50, 0)
            second = app_module.device_activity_rows(conn, 'd1', 50, 50)
        first_ids = {(r['source_order'], r['source_id']) for r in first}
        second_ids = {(r['source_order'], r['source_id']) for r in second}
        self.assertEqual(50, len(first_ids))
        self.assertEqual(10, len(second_ids))
        self.assertFalse(first_ids & second_ids)


if __name__ == '__main__':
    unittest.main()
