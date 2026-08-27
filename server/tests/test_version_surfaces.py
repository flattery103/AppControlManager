import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERSION = "0.16.0"


class VersionSurfaceTests(unittest.TestCase):
    def test_server_runtime_and_upgrade_message_use_release_version(self):
        app = (ROOT / "server" / "app.py").read_text(encoding="utf-8")
        upgrade = (ROOT / "server" / "upgrade-server.sh").read_text(encoding="utf-8")
        self.assertIn(f'version="{VERSION}"', app)
        self.assertIn(f'"version": "{VERSION}"', app)
        self.assertIn(f"Server {VERSION}", app)
        self.assertIn(f"server upgraded to {VERSION}", upgrade)
        self.assertNotIn("Reporting in 0.13.0", app)

    def test_windows_build_defaults_and_assemblies_use_release_version(self):
        build = (ROOT / "windows-agent" / "Build.ps1").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "build-windows.yml").read_text(encoding="utf-8")
        self.assertIn(f"[string]$Version='{VERSION}'", build)
        self.assertGreaterEqual(workflow.count(VERSION), 3)
        for rel in (
            "windows-agent/src/AppGuard.Service/AppGuard.Service.csproj",
            "windows-agent/src/AppGuard.Tray/AppGuard.Tray.csproj",
            "windows-agent/src/AppControlManager.Installer/AppControlManager.Installer.csproj",
        ):
            text = (ROOT / rel).read_text(encoding="utf-8")
            self.assertIn(f"<Version>{VERSION}</Version>", text, rel)

    def test_windows_runtime_fallbacks_and_manual_scripts_use_release_version(self):
        files = (
            "windows-agent/src/AppGuard.Core/Models.cs",
            "windows-agent/src/AppGuard.Service/AgentWorker.cs",
            "windows-agent/src/AppControlManager.Installer/Program.cs",
            "windows-agent/Install-Agent.ps1",
            "windows-agent/Upgrade-Agent.ps1",
        )
        for rel in files:
            text = (ROOT / rel).read_text(encoding="utf-8")
            self.assertIn(VERSION, text, rel)
            self.assertNotIn("0.13.0", text, rel)

    def test_release_documentation_describes_integrated_milestone_and_signing_secrets(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        feature_path = ROOT / "0.16.0-FEATURES.txt"
        self.assertTrue(feature_path.is_file())
        self.assertTrue(readme.startswith(f"# AppControl Manager {VERSION}"))
        for secret in (
            "AZURE_CLIENT_ID",
            "AZURE_TENANT_ID",
            "AZURE_SUBSCRIPTION_ID",
            "AZURE_ARTIFACT_SIGNING_ENDPOINT",
            "AZURE_ARTIFACT_SIGNING_ACCOUNT",
            "AZURE_ARTIFACT_SIGNING_PROFILE",
        ):
            self.assertIn(secret, readme)
        features = feature_path.read_text(encoding="utf-8")
        for phrase in (
            "PowerShell 5.1",
            "CRLF",
            "signer cache",
            "Deduplicated application-root scans",
        ):
            self.assertIn(phrase, features)


if __name__ == "__main__":
    unittest.main()
