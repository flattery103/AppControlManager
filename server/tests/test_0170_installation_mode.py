import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class Release0170InstallationModeTests(unittest.TestCase):
    VERSION = "0.17.0"

    def text(self, rel):
        path = ROOT / rel
        return path.read_text(encoding="utf-8") if path.is_file() else ""

    def _app_with_temp_db(self):
        server_dir = ROOT / "server"
        if str(server_dir) not in sys.path:
            sys.path.insert(0, str(server_dir))
        import app as app_module

        fd, path = tempfile.mkstemp(prefix="acm-0170-", suffix=".db")
        os.close(fd)
        os.unlink(path)
        old_path = app_module.DB_PATH
        app_module.DB_PATH = path
        app_module.init_db()
        self.addCleanup(setattr, app_module, "DB_PATH", old_path)
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return app_module, path

    def _seed_device(self, app_module, path):
        now = app_module.utcnow()
        with sqlite3.connect(path) as conn:
            conn.execute("INSERT INTO organizations(id,name,slug,status,created_at) VALUES(99,'Org','org-0170','active',?)", (now,))
            conn.execute(
                "INSERT INTO devices(id,hostname,device_key_hash,agent_version,created_at,organization_id,learning_mode,policy_mode) VALUES(?,?,?,?,?,?,0,'enforcement')",
                ("d1", "pc1", "x", self.VERSION, now, 99),
            )
            conn.commit()

    def test_installation_schema_is_additive(self):
        app_module, path = self._app_with_temp_db()
        with sqlite3.connect(path) as conn:
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertIn("installation_requests", tables)
            columns = {r[1] for r in conn.execute("PRAGMA table_info(installation_requests)")}
        for name in (
            "device_id", "file_path", "requested_by", "source", "status", "duration_minutes",
            "activation_expires_at", "approved_at", "approved_by", "started_at", "ends_at",
            "completed_at", "decision_note", "created_at",
        ):
            self.assertIn(name, columns)
        self.assertNotIn("DROP TABLE", self.text("server/app.py"))

    def test_command_validation_accepts_bounded_installation_commands(self):
        app_module, _ = self._app_with_temp_db()
        self.assertIsNone(app_module.validate_agent_command(
            "start_installation_mode", '{"installation_id":7,"duration_minutes":15,"trigger":"user","actor":"ORG\\\\user"}'
        ))
        self.assertIn("1-240", app_module.validate_agent_command(
            "start_installation_mode", '{"installation_id":7,"duration_minutes":241}'
        ))
        self.assertIsNone(app_module.validate_agent_command(
            "end_installation_mode", '{"installation_id":7,"reason":"user_finished"}'
        ))

    def test_user_request_approval_waits_for_endpoint_start_and_expires_in_four_hours(self):
        app_module, path = self._app_with_temp_db()
        self._seed_device(app_module, path)
        created = app_module.create_installation_request(app_module.ApprovalIn(
            file_path=r"C:\\Users\\user\\Downloads\\Firefox Installer.exe",
            product_name="Firefox Installer", requested_by=r"ORG\\user", reason="Install Firefox"
        ), "d1")
        request_id = created["installation_id"]
        principal = app_module.Principal(1, "admin", "Admin", "global_admin", None)
        app_module.approve_installation(request_id, duration_minutes=15, principal=principal)
        with sqlite3.connect(path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM installation_requests WHERE id=?", (request_id,)).fetchone()
            commands = conn.execute("SELECT COUNT(*) FROM commands WHERE device_id='d1'").fetchone()[0]
        self.assertEqual(row["status"], "approved")
        self.assertEqual(row["duration_minutes"], 15)
        self.assertEqual(commands, 0, "admin approval must not start Installation Mode")
        approved = datetime.fromisoformat(row["approved_at"])
        expires = datetime.fromisoformat(row["activation_expires_at"])
        self.assertAlmostEqual((expires - approved).total_seconds(), 4 * 3600, delta=2)

        started = app_module.start_installation_request(
            request_id,
            app_module.InstallationStartIn(requested_by=r"ORG\\user"),
            "d1",
        )
        self.assertTrue(started["ok"])
        with sqlite3.connect(path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT status FROM installation_requests WHERE id=?", (request_id,)).fetchone()
            cmd = conn.execute("SELECT command_type,payload FROM commands WHERE device_id='d1' ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(row["status"], "starting")
        self.assertEqual(cmd["command_type"], "start_installation_mode")
        self.assertIn('"duration_minutes": 15', cmd["payload"])

    def test_manual_admin_start_queues_immediately_and_is_bounded(self):
        app_module, path = self._app_with_temp_db()
        self._seed_device(app_module, path)
        principal = app_module.Principal(1, "admin", "Admin", "global_admin", None)
        app_module.start_device_installation_mode("d1", duration_minutes=30, principal=principal)
        with sqlite3.connect(path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM installation_requests ORDER BY id DESC LIMIT 1").fetchone()
            cmd = conn.execute("SELECT * FROM commands ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(row["source"], "admin")
        self.assertEqual(row["status"], "starting")
        self.assertEqual(row["duration_minutes"], 30)
        self.assertEqual(cmd["command_type"], "start_installation_mode")
        with self.assertRaises(Exception):
            app_module.start_device_installation_mode("d1", duration_minutes=241, principal=principal)

    def test_endpoint_installation_report_updates_authoritative_times(self):
        app_module, path = self._app_with_temp_db()
        self._seed_device(app_module, path)
        now = app_module.utcnow()
        with sqlite3.connect(path) as conn:
            request_id = conn.execute(
                "INSERT INTO installation_requests(device_id,file_path,requested_by,source,status,duration_minutes,created_at) VALUES(?,?,?,?,?,?,?)",
                ("d1", r"C:\\setup.exe", r"ORG\\user", "user", "starting", 15, now),
            ).lastrowid
            conn.commit()
        report = app_module.InstallationReportIn(
            status="active", started_at="2026-08-28T20:00:00+00:00", ends_at="2026-08-28T20:15:00+00:00",
            detail="Installation Mode active."
        )
        app_module.report_installation(request_id, report, "d1")
        with sqlite3.connect(path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT status,started_at,ends_at,decision_note FROM installation_requests WHERE id=?", (request_id,)).fetchone()
        self.assertEqual(row["status"], "active")
        self.assertEqual(row["started_at"], report.started_at)
        self.assertEqual(row["ends_at"], report.ends_at)
        self.assertIn("active", row["decision_note"].lower())

    def test_endpoint_has_persistent_timer_cumulative_delta_and_force_enforcement_fallback(self):
        paths = self.text("windows-agent/src/AppGuard.Core/Paths.cs")
        manager = self.text("windows-agent/src/AppGuard.Service/InstallationModeManager.cs")
        worker = self.text("windows-agent/src/AppGuard.Service/AgentWorker.cs")
        helper = self.text("windows-agent/src/AppGuard.Service/PolicyHelper.cs")
        force = self.text("windows-agent/scripts/Force-Enforcement.ps1")
        self.assertIn("InstallationModeStatePath", paths)
        self.assertIn("installation-mode.json", paths)
        self.assertIn("CheckExpirationAsync", manager)
        self.assertIn("EndsAt", manager)
        self.assertIn("FinalizeInstallationModeAsync", manager)
        self.assertIn("ForceEnforcementAsync", manager)
        self.assertIn("CheckExpirationAsync", worker)
        self.assertIn("Install-MergedSupplemental.ps1", helper)
        self.assertIn("AppControl Manager Installation", helper)
        install_section = helper[helper.index("FinalizeInstallationModeAsync"):]
        self.assertNotIn("Install-LearnedBaselineFromFragments.ps1", install_section)
        self.assertIn("Set-RuleOption -FilePath $xml -Option 3 -Delete", force)
        self.assertNotIn("Install-LearnedBaselineFromFragments", force)

    def test_tray_exposes_request_installation_approved_start_and_active_countdown(self):
        request = self.text("windows-agent/src/AppGuard.Tray/RequestForm.cs")
        session = self.text("windows-agent/src/AppGuard.Tray/SessionRequestForm.cs")
        approval = self.text("windows-agent/src/AppGuard.Tray/InstallationApprovalForm.cs")
        active = self.text("windows-agent/src/AppGuard.Tray/InstallationModeForm.cs")
        tray = self.text("windows-agent/src/AppGuard.Tray/TrayContext.cs")
        self.assertIn("Request Installation", request)
        self.assertIn('Action = "request_installation"', request)
        self.assertIn("Request Installation", session)
        self.assertIn('Action = "request_installation_session"', session)
        self.assertIn("Installation Approved", approval)
        self.assertIn("Start Installation", approval)
        self.assertIn("Not Now", approval)
        self.assertIn("INSTALLATION MODE ACTIVE", active)
        self.assertIn("Finish Installation Early", active)
        self.assertIn("TimeRemaining", active)
        self.assertIn("InstallationApprovalForm", tray)
        self.assertIn("InstallationModeForm", tray)
        self.assertIn("Approved installation...", tray)
        self.assertIn("ShowApprovedInstallation", tray)


    def test_pipe_request_carries_installation_id_for_start_and_finish_actions(self):
        models = self.text("windows-agent/src/AppGuard.Core/Models.cs")
        pipe_start = models.index("public sealed class PipeRequest")
        pipe_end = models.index("public sealed class BlockedSnapshot", pipe_start)
        pipe = models[pipe_start:pipe_end]
        self.assertIn('[JsonPropertyName("installation_id")] public long? InstallationId', pipe)

    def test_admin_ui_distinguishes_installation_requests_and_device_controls(self):
        app = self.text("server/app.py")
        self.assertIn("Installation Requests", app)
        self.assertIn("Approve Installation", app)
        self.assertIn("activation window", app.lower())
        self.assertIn("Start Installation Mode", app)
        self.assertIn("End Installation Mode Now", app)
        self.assertIn("INSTALLATION MODE ACTIVE", app)
        self.assertIn("/admin/devices/{device_id}/installation-mode/start", app)
        self.assertIn("/admin/devices/{device_id}/installation-mode/end", app)
        self.assertIn("RedirectResponse(f'/devices/{device_id}'", app)


    def test_device_installation_banner_distinguishes_starting_active_and_suppresses_normal_mode_toggle(self):
        app_module, path = self._app_with_temp_db()
        self._seed_device(app_module, path)
        principal = app_module.Principal(1, "admin", "Admin", "global_admin", None)
        now = app_module.utcnow()
        with sqlite3.connect(path) as conn:
            iid = conn.execute(
                "INSERT INTO installation_requests(device_id,file_path,requested_by,source,status,duration_minutes,created_at) VALUES(?,?,?,?,?,?,?)",
                ("d1", r"C:\\setup.exe", r"ORG\\user", "user", "starting", 15, now),
            ).lastrowid
            conn.commit()
        starting = app_module.device_detail("d1", principal=principal).body.decode("utf-8")
        self.assertIn("INSTALLATION MODE STARTING", starting)
        self.assertNotIn("INSTALLATION MODE ACTIVE</b>", starting)
        with sqlite3.connect(path) as conn:
            conn.execute("UPDATE installation_requests SET status='active',started_at=?,ends_at=? WHERE id=?", (now, now, iid))
            conn.execute("UPDATE devices SET learning_mode=1,policy_mode='learning' WHERE id='d1'")
            conn.commit()
        active = app_module.device_detail("d1", principal=principal).body.decode("utf-8")
        self.assertIn("INSTALLATION MODE ACTIVE", active)
        self.assertNotIn("Enable Enforcement", active)
        self.assertIn("End Installation Mode Now", active)

    def test_0170_release_notes_preserve_installation_mode_contract(self):
        notes = ROOT / "0.17.0-FEATURES.txt"
        self.assertTrue(notes.is_file())
        text = notes.read_text(encoding="utf-8")
        self.assertIn("Installation Mode", text)
        self.assertIn("four hours", text)
        self.assertIn("Enforcement", text)


if __name__ == "__main__":
    unittest.main()
