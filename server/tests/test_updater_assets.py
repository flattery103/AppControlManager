import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class UpdaterAssetTests(unittest.TestCase):
    def test_updater_handles_all_agent_release_assets_and_invokes_importer(self):
        text = (ROOT / "server" / "update-from-github.sh").read_text(encoding="utf-8")
        expected = [
            "AppControlManager-${LATEST}-source.zip",
            "AppControlManager-${LATEST}-source.zip.sha256",
            "AppControlManager-Agent-${LATEST}-win-x64.zip",
            "AppControlManager-Agent-${LATEST}-win-x64.zip.sha256",
            "AppControlManager-Installer-${LATEST}.exe",
            "AppControlManager-Installer-${LATEST}.exe.sha256",
        ]
        for item in expected:
            self.assertIn(item, text)
        self.assertIn("import-agent-release.py", text)
        self.assertIn("Agent release ${LATEST}", text)

    def test_install_and_upgrade_scripts_install_release_management_helpers(self):
        for script in ("install-server.sh", "upgrade-server.sh"):
            text = (ROOT / "server" / script).read_text(encoding="utf-8")
            self.assertIn("release_management.py", text, script)
            self.assertIn("import-agent-release.py", text, script)


if __name__ == "__main__":
    unittest.main()
