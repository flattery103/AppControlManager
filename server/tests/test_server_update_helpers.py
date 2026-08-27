import os
import sys
import tempfile
import unittest
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

os.environ.setdefault("APPCONTROL_DB", str(Path(tempfile.gettempdir()) / "acm-test-server-updates.db"))


class ServerUpdateHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as app_module
        cls.app_module = app_module

    def test_global_admin_navigation_contains_server_updates(self):
        principal = self.app_module.Principal(1, "admin", "Admin", "global_admin", None, False)
        rendered = self.app_module.nav(principal)
        self.assertIn("/server-updates", rendered)
        self.assertIn("Server Updates", rendered)

    def test_non_global_org_admin_navigation_does_not_contain_server_updates(self):
        principal = self.app_module.Principal(2, "org", "Org Admin", "org_admin", 7, False)
        rendered = self.app_module.nav(principal)
        self.assertNotIn("/server-updates", rendered)

    def test_server_update_asset_status_reports_all_six_release_assets(self):
        from release_management import GitHubReleaseInfo

        version = "0.15.0"
        names = self.app_module.server_update_asset_names(version)
        info = GitHubReleaseInfo(
            version=version,
            tag_name="v0.15.0",
            html_url="https://example/release",
            published_at="2026-08-27T20:00:00Z",
            notes="notes",
            assets={name: f"https://api.example/{name}" for name in names.values()},
        )
        state = self.app_module.server_update_asset_status(info)
        self.assertEqual(set(names), set(state))
        self.assertTrue(all(state.values()))

    def test_server_updates_routes_are_registered(self):
        paths = {route.path for route in self.app_module.app.routes}
        self.assertIn("/server-updates", paths)
        self.assertIn("/admin/server-updates/install", paths)


if __name__ == "__main__":
    unittest.main()
