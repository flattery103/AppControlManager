import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ReleaseCandidateOffboardingTests(unittest.TestCase):
    def app_with_temp_db(self):
        server_dir = ROOT / 'server'
        if str(server_dir) not in sys.path:
            sys.path.insert(0, str(server_dir))
        import app as app_module
        fd, path = tempfile.mkstemp(prefix='acm-rc8-offboard-', suffix='.db')
        os.close(fd)
        os.unlink(path)
        old_path = app_module.DB_PATH
        app_module.DB_PATH = path
        app_module.init_db()
        self.addCleanup(setattr, app_module, 'DB_PATH', old_path)
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return app_module, path

    def test_successful_offboard_purges_operational_state_and_retains_audit(self):
        app_module, path = self.app_with_temp_db()
        now = app_module.utcnow()
        with sqlite3.connect(path) as conn:
            conn.execute("INSERT INTO organizations(id,name,slug,status,created_at) VALUES(801,'Offboard Org','offboard-org','active',?)", (now,))
            conn.execute("INSERT INTO devices(id,hostname,device_key_hash,created_at,organization_id) VALUES('offboard-device','OLD-PC','secret',?,801)", (now,))
            conn.execute("INSERT INTO events(device_id,event_id,received_at) VALUES('offboard-device',3077,?)", (now,))
            conn.execute("INSERT INTO commands(device_id,command_type,payload,status,created_at) VALUES('offboard-device','uninstall_agent','{}','completed',?)", (now,))
            conn.commit()

        response = app_module.offboard_complete(app_module.OffboardComplete(success=True, result='removed'), 'offboard-device')

        self.assertEqual(response, {'ok': True, 'purged': True})
        with sqlite3.connect(path) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM devices WHERE id='offboard-device'").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM events WHERE device_id='offboard-device'").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM commands WHERE device_id='offboard-device'").fetchone()[0], 0)
            audit = conn.execute("SELECT action,detail FROM audit_log WHERE object_id='offboard-device' ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(audit[0], 'device_offboard_completed')
        self.assertIn('OLD-PC', audit[1])


if __name__ == '__main__':
    unittest.main()
