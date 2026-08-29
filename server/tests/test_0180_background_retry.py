import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

from fastapi import HTTPException


ROOT = Path(__file__).resolve().parents[2]


class Release0180BackgroundRetryTests(unittest.TestCase):
    def text(self, rel):
        return (ROOT / rel).read_text(encoding="utf-8")

    def app_with_temp_db(self):
        server_dir = ROOT / "server"
        if str(server_dir) not in sys.path:
            sys.path.insert(0, str(server_dir))
        import app as app_module

        fd, path = tempfile.mkstemp(prefix="acm-0180-background-", suffix=".db")
        os.close(fd)
        os.unlink(path)
        old_path = app_module.DB_PATH
        app_module.DB_PATH = path
        app_module.init_db()
        self.addCleanup(setattr, app_module, "DB_PATH", old_path)
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return app_module, path

    def seed_device(self, app_module, path, *, failed=2):
        now = app_module.utcnow()
        with sqlite3.connect(path) as conn:
            conn.execute(
                "INSERT INTO organizations(id,name,slug,status,created_at) VALUES(99,'Org One','org-one-0180','active',?)",
                (now,),
            )
            conn.execute(
                """INSERT INTO devices
                   (id,hostname,device_key_hash,agent_version,created_at,organization_id,
                    learning_mode,policy_mode,background_policy_status,
                    background_policy_pending,background_policy_failed)
                   VALUES('d1','pc1','x','0.18.0',?,99,0,'enforcement','failed',3,?)""",
                (now, failed),
            )
            conn.commit()

    def test_schema_and_heartbeat_persist_bounded_background_diagnostics(self):
        app_module, path = self.app_with_temp_db()
        self.seed_device(app_module, path)
        with sqlite3.connect(path) as conn:
            columns = {row[1] for row in conn.execute("PRAGMA table_info(devices)")}
        self.assertIn("background_policy_error", columns)
        self.assertIn("background_policy_oldest_at", columns)

        app_module.heartbeat(
            app_module.HeartbeatRequest(
                learning_mode=False,
                policy_mode="enforcement",
                background_policy_error="ConfigCI failed for helper.dll",
                background_policy_oldest_at="2026-08-29T01:02:03+00:00",
            ),
            "d1",
        )
        with sqlite3.connect(path) as conn:
            row = conn.execute(
                "SELECT background_policy_error,background_policy_oldest_at FROM devices WHERE id='d1'"
            ).fetchone()
        self.assertEqual(row, ("ConfigCI failed for helper.dll", "2026-08-29T01:02:03+00:00"))

        app_module.heartbeat(
            app_module.HeartbeatRequest(learning_mode=False, policy_mode="enforcement"),
            "d1",
        )
        with sqlite3.connect(path) as conn:
            preserved = conn.execute(
                "SELECT background_policy_error,background_policy_oldest_at FROM devices WHERE id='d1'"
            ).fetchone()
        self.assertEqual(preserved, row)

        app_module.heartbeat(
            app_module.HeartbeatRequest(
                learning_mode=False,
                policy_mode="enforcement",
                background_policy_error=None,
                background_policy_oldest_at=None,
            ),
            "d1",
        )
        with sqlite3.connect(path) as conn:
            cleared = conn.execute(
                "SELECT background_policy_error,background_policy_oldest_at FROM devices WHERE id='d1'"
            ).fetchone()
        self.assertEqual(cleared, (None, None))

    def test_retry_route_is_tenant_scoped_and_requires_approver(self):
        app_module, path = self.app_with_temp_db()
        self.seed_device(app_module, path)
        with self.assertRaises(HTTPException) as denied:
            app_module.retry_background_policy(
                "d1", app_module.Principal(2, "viewer", "Viewer", "viewer", 99)
            )
        self.assertEqual(denied.exception.status_code, 403)
        with self.assertRaises(HTTPException) as cross_tenant:
            app_module.retry_background_policy(
                "d1", app_module.Principal(3, "other", "Other", "approver", 100)
            )
        self.assertEqual(cross_tenant.exception.status_code, 403)

    def test_retry_route_queues_fixed_command_and_audits_actor(self):
        app_module, path = self.app_with_temp_db()
        self.seed_device(app_module, path)
        principal = app_module.Principal(1, "admin", "Admin", "org_admin", 99)
        response = app_module.retry_background_policy("d1", principal)
        self.assertEqual(response.status_code, 303)
        with sqlite3.connect(path) as conn:
            conn.row_factory = sqlite3.Row
            command = conn.execute(
                "SELECT command_type,payload,status FROM commands WHERE device_id='d1'"
            ).fetchone()
            event = conn.execute(
                "SELECT actor,action,device_id FROM audit_log WHERE action='background_policy_retry_queued'"
            ).fetchone()
        self.assertEqual(command["command_type"], "retry_background_policy")
        self.assertEqual(json.loads(command["payload"]), {"requested_by": "admin"})
        self.assertEqual(command["status"], "pending")
        self.assertEqual(tuple(event), ("admin", "background_policy_retry_queued", "d1"))

    def test_retry_command_passes_server_delivery_validation(self):
        app_module, _ = self.app_with_temp_db()
        payload = json.dumps({"requested_by": "admin"})

        self.assertIsNone(
            app_module.validate_agent_command("retry_background_policy", payload)
        )
        self.assertEqual(
            app_module.validate_agent_command("retry_background_policy", "{}"),
            "retry_background_policy requires requested_by.",
        )

    def test_retry_route_does_not_queue_when_endpoint_command_is_busy(self):
        app_module, path = self.app_with_temp_db()
        self.seed_device(app_module, path)
        with sqlite3.connect(path) as conn:
            conn.execute(
                "INSERT INTO commands(device_id,command_type,payload,status,created_at) VALUES('d1','update_agent','{}','processing',?)",
                (app_module.utcnow(),),
            )
            conn.commit()
        response = app_module.retry_background_policy(
            "d1", app_module.Principal(1, "admin", "Admin", "org_admin", 99)
        )
        self.assertEqual(response.status_code, 303)
        self.assertIn("busy=1", response.headers["location"])
        with sqlite3.connect(path) as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM commands WHERE command_type='retry_background_policy'"
            ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_device_page_shows_diagnostics_and_retry_only_when_queue_is_free(self):
        app_module, path = self.app_with_temp_db()
        self.seed_device(app_module, path)
        with sqlite3.connect(path) as conn:
            conn.execute(
                "UPDATE devices SET background_policy_error=?,background_policy_oldest_at=? WHERE id='d1'",
                ("ConfigCI failed for helper.dll", "2026-08-29T01:02:03+00:00"),
            )
            conn.commit()
        principal = app_module.Principal(1, "admin", "Admin", "org_admin", 99)
        html = app_module.device_detail("d1", principal).body.decode("utf-8")
        self.assertIn("ConfigCI failed for helper.dll", html)
        self.assertIn("Oldest pending", html)
        self.assertIn("Retry Failed Background Work", html)

        with sqlite3.connect(path) as conn:
            conn.execute(
                "INSERT INTO commands(device_id,command_type,payload,status,created_at) VALUES('d1','update_agent','{}','pending',?)",
                (app_module.utcnow(),),
            )
            conn.commit()
        busy_html = app_module.device_detail("d1", principal).body.decode("utf-8")
        self.assertNotIn("Retry Failed Background Work", busy_html)

    def test_endpoint_store_retry_preserves_ready_and_installed_work(self):
        models = self.text("windows-agent/src/AppGuard.Core/BackgroundPolicyModels.cs")
        store = self.text("windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs")
        agent = self.text("windows-agent/src/AppGuard.Service/AgentWorker.cs")
        self.assertIn("BackgroundPolicyQueueStatus", models)
        self.assertIn("RetryFailedWork", store)
        retry = store[store.index("RetryFailedWork"):]
        self.assertIn("BackgroundPolicyStatuses.Failed", retry)
        self.assertIn("Attempts = 0", retry)
        self.assertNotIn("BackgroundPolicyStatuses.Ready", retry.split("public", 1)[0])
        self.assertNotIn("BackgroundPolicyStatuses.Installed", retry.split("public", 1)[0])
        self.assertIn('case "retry_background_policy"', agent)
        self.assertIn("BackgroundPolicyError", agent)
        self.assertIn("BackgroundPolicyOldestAt", agent)


if __name__ == "__main__":
    unittest.main()
