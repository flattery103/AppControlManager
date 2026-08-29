import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

from pydantic import ValidationError


ROOT = Path(__file__).resolve().parents[2]


class ReleaseCandidateOperationalTelemetryTests(unittest.TestCase):
    def app_with_temp_db(self):
        server_dir = ROOT / "server"
        if str(server_dir) not in sys.path:
            sys.path.insert(0, str(server_dir))
        import app as app_module

        fd, path = tempfile.mkstemp(prefix="acm-100rc-telemetry-", suffix=".db")
        os.close(fd)
        os.unlink(path)
        old_path = app_module.DB_PATH
        app_module.DB_PATH = path
        app_module.init_db()
        self.addCleanup(setattr, app_module, "DB_PATH", old_path)
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return app_module, path

    def seed_device(self, app_module, path):
        with sqlite3.connect(path) as conn:
            conn.execute(
                "INSERT INTO organizations(id,name,slug,status,created_at) VALUES(501,'RC Org','rc-org','active',?)",
                (app_module.utcnow(),),
            )
            conn.execute(
                """INSERT INTO devices(id,hostname,device_key_hash,learning_mode,policy_mode,created_at,organization_id)
                   VALUES('rc-device','RC-PC','x',1,'learning',?,501)""",
                (app_module.utcnow(),),
            )
            conn.commit()

    def test_heartbeat_persists_bounded_operational_health(self):
        app_module, path = self.app_with_temp_db()
        self.seed_device(app_module, path)
        work = app_module.BackgroundWorkSummaryIn(
            key_digest="a" * 64,
            display_name="Example Product",
            kind="product",
            status="processing",
            attempts=1,
            age_seconds=42,
            elapsed_seconds=15,
            rule_mode="product",
            updated_at="2026-08-29T21:00:00+00:00",
        )
        app_module.heartbeat(
            app_module.HeartbeatRequest(
                learning_mode=True,
                policy_mode="learning",
                service_status="running",
                rule_worker_status="running",
                tray_status="running",
                last_command_poll_at="2026-08-29T21:00:00+00:00",
                background_work=[work],
            ),
            "rc-device",
        )
        with sqlite3.connect(path) as conn:
            row = conn.execute(
                """SELECT service_status,rule_worker_status,tray_status,last_command_poll_at,
                          background_work_json FROM devices WHERE id='rc-device'"""
            ).fetchone()
        self.assertEqual(row[:4], ("running", "running", "running", "2026-08-29T21:00:00+00:00"))
        self.assertEqual(json.loads(row[4])[0]["display_name"], "Example Product")

    def test_heartbeat_rejects_unbounded_or_unsafe_work_summaries(self):
        app_module, _ = self.app_with_temp_db()
        valid = {
            "key_digest": "b" * 64,
            "display_name": "Product",
            "kind": "product",
            "status": "queued",
            "attempts": 0,
            "updated_at": "2026-08-29T21:00:00+00:00",
        }
        with self.assertRaises(ValidationError):
            app_module.HeartbeatRequest(background_work=[valid] * 51)
        with self.assertRaises(ValidationError):
            app_module.BackgroundWorkSummaryIn(**{**valid, "key_digest": "raw-cache-key"})
        with self.assertRaises(ValidationError):
            app_module.BackgroundWorkSummaryIn(**{**valid, "status": "invented"})


if __name__ == "__main__":
    unittest.main()
