import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class Release0172DashboardRequestTests(unittest.TestCase):
    def _app_with_temp_db(self):
        server_dir = ROOT / "server"
        if str(server_dir) not in sys.path:
            sys.path.insert(0, str(server_dir))
        import app as app_module

        fd, path = tempfile.mkstemp(prefix="acm-0172-dashboard-", suffix=".db")
        os.close(fd)
        os.unlink(path)
        old_path = app_module.DB_PATH
        app_module.DB_PATH = path
        app_module.init_db()
        self.addCleanup(setattr, app_module, "DB_PATH", old_path)
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return app_module, path

    def test_dashboard_combines_pending_access_and_installation_requests(self):
        app_module, path = self._app_with_temp_db()
        now = app_module.utcnow()
        with sqlite3.connect(path) as conn:
            conn.execute(
                "INSERT INTO organizations(id,name,slug,status,created_at) VALUES(99,'Visible Org','visible','active',?)",
                (now,),
            )
            conn.execute(
                "INSERT INTO organizations(id,name,slug,status,created_at) VALUES(100,'Hidden Org','hidden','active',?)",
                (now,),
            )
            conn.execute(
                "INSERT INTO devices(id,hostname,device_key_hash,created_at,organization_id,policy_mode) VALUES(?,?,?,?,?,'enforcement')",
                ("d1", "visible-pc", "x", now, 99),
            )
            conn.execute(
                "INSERT INTO devices(id,hostname,device_key_hash,created_at,organization_id,policy_mode) VALUES(?,?,?,?,?,'enforcement')",
                ("d2", "hidden-pc", "x", now, 100),
            )
            access_id = conn.execute(
                "INSERT INTO approval_requests(device_id,file_path,product_name,reason,requested_by,status,created_at) VALUES(?,?,?,?,?,'pending',?)",
                ("d1", r"C:\\Tools\\access.exe", "Access Tool", "Need access", r"ORG\\user", now),
            ).lastrowid
            install_id = conn.execute(
                "INSERT INTO installation_requests(device_id,file_path,product_name,reason,requested_by,source,status,duration_minutes,created_at) VALUES(?,?,?,?,?,'user','pending',15,?)",
                ("d1", r"C:\\Downloads\\Firefox Installer.exe", "Firefox Installer", "Install browser", r"ORG\\user", now),
            ).lastrowid
            conn.execute(
                "INSERT INTO installation_requests(device_id,file_path,product_name,reason,requested_by,source,status,duration_minutes,created_at) VALUES(?,?,?,?,?,'user','pending',15,?)",
                ("d2", r"C:\\Downloads\\Hidden Setup.exe", "Hidden Setup", "Other tenant", r"OTHER\\user", now),
            )
            conn.commit()

        principal = app_module.Principal(1, "admin", "Admin", "org_admin", 99)
        html = app_module.dashboard(principal=principal).body.decode("utf-8")

        self.assertIn("<h2>Pending Requests</h2>", html)
        self.assertIn("<span class='stat-label'>Pending Approvals</span><b>2</b>", html)
        self.assertIn("<span class='badge'>Access</span>", html)
        self.assertIn("<span class='badge badge-info'>Installation</span>", html)
        self.assertIn("Access Tool", html)
        self.assertIn("Firefox Installer", html)
        self.assertIn("Install browser", html)
        self.assertIn(f"/admin/requests/{access_id}/approve", html)
        self.assertIn(f"/admin/installations/{install_id}/approve", html)
        self.assertIn(f"/admin/installations/{install_id}/deny", html)
        self.assertIn("name='duration_minutes'", html)
        self.assertNotIn("Hidden Setup", html)
        self.assertNotIn("hidden-pc", html)

    def test_release_notes_include_main_dashboard_installation_requests(self):
        notes = (ROOT / "0.17.2-FIXES.txt").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        self.assertIn("main dashboard", notes.lower())
        self.assertIn("pending installation requests", notes.lower())
        self.assertIn("main dashboard", readme.lower())


if __name__ == "__main__":
    unittest.main()
