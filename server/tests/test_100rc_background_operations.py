import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[2]


class ReleaseCandidateBackgroundOperationTests(unittest.TestCase):
    def setup_app(self):
        server_dir = ROOT / "server"
        if str(server_dir) not in sys.path:
            sys.path.insert(0, str(server_dir))
        import app
        fd, path = tempfile.mkstemp(prefix="acm-rc-bg-", suffix=".db")
        os.close(fd); os.unlink(path)
        old = app.DB_PATH; app.DB_PATH = path; app.init_db()
        self.addCleanup(setattr, app, "DB_PATH", old)
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        with sqlite3.connect(path) as conn:
            conn.execute("INSERT INTO organizations(id,name,slug,status,created_at) VALUES(601,'One','one-rc','active',?)", (app.utcnow(),))
            conn.execute("INSERT INTO devices(id,hostname,device_key_hash,learning_mode,policy_mode,created_at,organization_id) VALUES('d1','PC','x',1,'learning',?,601)", (app.utcnow(),))
            conn.commit()
        return app, path

    def test_targeted_retry_is_scoped_constrained_and_audited(self):
        app, path = self.setup_app()
        digest = "c" * 64
        principal = app.Principal(1, "admin", "Admin", "org_admin", 601)
        response = app.retry_background_policy_item("d1", digest, principal)
        self.assertEqual(response.status_code, 303)
        with sqlite3.connect(path) as conn:
            conn.row_factory = sqlite3.Row
            command = conn.execute("SELECT command_type,payload FROM commands").fetchone()
            audit = conn.execute("SELECT action FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(command["command_type"], "retry_background_policy_item")
        self.assertEqual(json.loads(command["payload"]), {"key_digest": digest, "requested_by": "admin"})
        self.assertEqual(audit["action"], "background_policy_item_retry_queued")
        self.assertIsNone(app.validate_agent_command(command["command_type"], command["payload"]))

    def test_targeted_actions_reject_bad_digest_and_cross_tenant(self):
        app, _ = self.setup_app()
        with self.assertRaises(HTTPException) as bad:
            app.retry_background_policy_item("d1", "raw-key", app.Principal(1, "admin", "Admin", "org_admin", 601))
        self.assertEqual(bad.exception.status_code, 400)
        with self.assertRaises(HTTPException) as denied:
            app.dismiss_background_policy_item("d1", "d" * 64, app.Principal(2, "other", "Other", "org_admin", 999))
        self.assertEqual(denied.exception.status_code, 403)

    def test_targeted_commands_require_only_digest_and_actor(self):
        app, _ = self.setup_app()
        for command_type in ("retry_background_policy_item", "dismiss_background_policy_item"):
            self.assertEqual(app.validate_agent_command(command_type, "{}"), f"{command_type} requires key_digest and requested_by.")
            payload = json.dumps({"key_digest": "e" * 64, "requested_by": "admin", "path": "C:\\Temp\\bad.exe"})
            self.assertEqual(app.validate_agent_command(command_type, payload), f"{command_type} accepts only key_digest and requested_by.")


if __name__ == "__main__":
    unittest.main()
