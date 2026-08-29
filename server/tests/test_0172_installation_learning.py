import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class Release0172InstallationLearningTests(unittest.TestCase):
    def text(self, rel):
        return (ROOT / rel).read_text(encoding="utf-8")

    def _app_with_temp_db(self):
        server_dir = ROOT / "server"
        if str(server_dir) not in sys.path:
            sys.path.insert(0, str(server_dir))
        import app as app_module

        fd, path = tempfile.mkstemp(prefix="acm-0172-", suffix=".db")
        os.close(fd)
        os.unlink(path)
        old_path = app_module.DB_PATH
        app_module.DB_PATH = path
        app_module.init_db()
        self.addCleanup(setattr, app_module, "DB_PATH", old_path)
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return app_module, path

    def _seed_active_installation(self, app_module, path):
        now = app_module.utcnow()
        with sqlite3.connect(path) as conn:
            conn.execute(
                "INSERT INTO organizations(id,name,slug,status,created_at) VALUES(99,'Org','org-0172','active',?)",
                (now,),
            )
            conn.execute(
                "INSERT INTO devices(id,hostname,device_key_hash,agent_version,created_at,organization_id,learning_mode,policy_mode) "
                "VALUES(?,?,?,?,?,?,1,'learning')",
                ("d1", "pc1", "x", "0.17.2", now, 99),
            )
            request_id = conn.execute(
                "INSERT INTO installation_requests(device_id,file_path,requested_by,source,status,duration_minutes,created_at) "
                "VALUES(?,?,?,?,?,?,?)",
                ("d1", r"C:\\setup.exe", r"ORG\\user", "user", "active", 15, now),
            ).lastrowid
            conn.commit()
        return request_id

    def test_completed_with_warnings_is_terminal_and_restores_enforcement(self):
        app_module, path = self._app_with_temp_db()
        request_id = self._seed_active_installation(app_module, path)
        detail = (
            "Installation Mode completed with warnings. Enforcement restored. "
            "Processed 42 learned files; installed 16 safe authorization rules; "
            "skipped 26 temporary or unverifiable files."
        )

        app_module.report_installation(
            request_id,
            app_module.InstallationReportIn(
                status="completed_with_warnings",
                completed_at="2026-08-29T00:00:00+00:00",
                detail=detail,
            ),
            "d1",
        )

        with sqlite3.connect(path) as conn:
            conn.row_factory = sqlite3.Row
            request = conn.execute(
                "SELECT status,completed_at,decision_note FROM installation_requests WHERE id=?",
                (request_id,),
            ).fetchone()
            device = conn.execute(
                "SELECT learning_mode,policy_mode FROM devices WHERE id='d1'"
            ).fetchone()

        self.assertEqual(request["status"], "completed_with_warnings")
        self.assertEqual(request["completed_at"], "2026-08-29T00:00:00+00:00")
        self.assertEqual(request["decision_note"], detail)
        self.assertEqual(device["learning_mode"], 0)
        self.assertEqual(device["policy_mode"], "enforcement")

    def test_completed_with_warnings_renders_as_warning_not_failure(self):
        app_module, path = self._app_with_temp_db()
        request_id = self._seed_active_installation(app_module, path)
        with sqlite3.connect(path) as conn:
            conn.execute(
                "UPDATE installation_requests SET status='completed_with_warnings',decision_note=? WHERE id=?",
                ("Enforcement restored; skipped 26 temporary or unverifiable files.", request_id),
            )
            conn.commit()

        principal = app_module.Principal(1, "admin", "Admin", "global_admin", None)
        html = app_module.requests_page(page_num=1, principal=principal).body.decode("utf-8")

        self.assertIn("Completed With Warnings", html)
        self.assertIn("badge badge-warn'>Completed With Warnings", html)
        self.assertNotIn("badge badge-bad'>Completed With Warnings", html)

    def test_terminal_warning_ignores_a_stale_active_report(self):
        app_module, path = self._app_with_temp_db()
        request_id = self._seed_active_installation(app_module, path)
        app_module.report_installation(
            request_id,
            app_module.InstallationReportIn(
                status="completed_with_warnings",
                completed_at="2026-08-29T00:00:00+00:00",
                detail="Enforcement restored with warnings.",
            ),
            "d1",
        )

        result = app_module.report_installation(
            request_id,
            app_module.InstallationReportIn(
                status="active",
                started_at="2026-08-28T23:45:00+00:00",
                ends_at="2026-08-29T00:15:00+00:00",
                detail="Delayed active report.",
            ),
            "d1",
        )

        with sqlite3.connect(path) as conn:
            conn.row_factory = sqlite3.Row
            request = conn.execute(
                "SELECT status,completed_at,decision_note FROM installation_requests WHERE id=?",
                (request_id,),
            ).fetchone()
            device = conn.execute(
                "SELECT learning_mode,policy_mode FROM devices WHERE id='d1'"
            ).fetchone()

        self.assertTrue(result["ignored"])
        self.assertEqual(result["status"], "completed_with_warnings")
        self.assertEqual(request["status"], "completed_with_warnings")
        self.assertEqual(request["completed_at"], "2026-08-29T00:00:00+00:00")
        self.assertEqual(request["decision_note"], "Enforcement restored with warnings.")
        self.assertEqual(device["learning_mode"], 0)
        self.assertEqual(device["policy_mode"], "enforcement")

    def test_client_retains_valid_rules_when_temporary_files_are_unpreparable(self):
        helper = self.text("windows-agent/src/AppGuard.Service/PolicyHelper.cs")
        store = self.text("windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs")
        manager = self.text("windows-agent/src/AppGuard.Service/InstallationModeManager.cs")
        models = self.text("windows-agent/src/AppGuard.Core/InstallationModeModels.cs")
        finalizer = helper[helper.index("FinalizeInstallationModeAsync"):helper.index("ForceEnforcementAsync")]

        self.assertIn("Task<InstallationFinalizationResult> FinalizeInstallationModeAsync", helper)
        self.assertNotIn("if (prep.Unpreparable > 0)", finalizer)
        self.assertIn("InstallationLearningReconciler.Create", finalizer)
        self.assertIn("SkippedCount = plan.SkippedCount", finalizer)
        self.assertIn("if (!File.Exists(filePath)) { stats.Unpreparable++; continue; }", store)
        self.assertLess(finalizer.index("if (ready.Length > 0)"), finalizer.index("ForceEnforcementCoreAsync"))
        self.assertIn("public sealed class InstallationFinalizationResult", models)
        self.assertIn('"completed_with_warnings"', manager)
        self.assertIn("finalization.HasWarnings", manager)
        self.assertIn("temporary or unverifiable", manager)

    def test_client_fails_when_learning_produces_no_safe_rules(self):
        helper = self.text("windows-agent/src/AppGuard.Service/PolicyHelper.cs")
        finalizer = helper[helper.index("FinalizeInstallationModeAsync"):helper.index("ForceEnforcementAsync")]

        self.assertIn(
            "learned.Count > 0 && ready.Length == 0 && plan.SkippedCount > 0",
            finalizer,
        )
        self.assertIn("none could be converted into safe authorization rules", finalizer)

    def test_client_discards_nonterminal_reports_after_local_completion(self):
        manager = self.text("windows-agent/src/AppGuard.Service/InstallationModeManager.cs")
        report_start = manager.index("private async Task ReportOrQueueAsync")
        retry = manager[manager.index("RetryPendingReportAsync"):report_start]
        report = manager[report_start:]

        self.assertIn("await _gate.WaitAsync(ct);", retry)
        self.assertIn("finally { _gate.Release(); }", retry)
        self.assertIn("!state.Active && IsNonTerminalReport(state.PendingReportStatus)", retry)
        self.assertIn("ClearPendingReport(state);", retry)
        self.assertIn("ClearPendingReport(state);", report)
        self.assertIn("private static bool IsNonTerminalReport", manager)
        self.assertIn("private static void ClearPendingReport", manager)


if __name__ == "__main__":
    unittest.main()
