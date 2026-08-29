import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class ReleaseWorkflowTests(unittest.TestCase):
    def test_build_script_supports_prepare_and_signed_package_stages(self):
        text = (ROOT / "windows-agent" / "Build.ps1").read_text(encoding="utf-8")
        self.assertIn("ValidateSet('Full','Prepare','Package')", text)
        self.assertIn("RequireSignedPayload", text)
        self.assertIn("Get-AuthenticodeSignature", text)
        self.assertIn("$Stage -eq 'Prepare'", text)
        self.assertIn("$Stage -eq 'Package'", text)

    def test_signature_verifier_requires_valid_authenticode(self):
        path = ROOT / "windows-agent" / "Verify-Signatures.ps1"
        self.assertTrue(path.is_file())
        text = path.read_text(encoding="utf-8")
        self.assertIn("Get-AuthenticodeSignature", text)
        self.assertIn("'Valid'", text)
        self.assertIn("throw", text)

    def test_release_workflow_signs_payload_before_packaging_and_installer_before_release(self):
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        for expected in (
            "id-token: write",
            "uses: azure/login@v3",
            "uses: azure/artifact-signing-action@v2",
            "-Stage Prepare",
            "-Stage Package -RequireSignedPayload",
            "Verify-Signatures.ps1",
            "actions/checkout@v6",
            "actions/setup-dotnet@v5",
        ):
            self.assertIn(expected, text)
        self.assertGreaterEqual(text.count("azure/artifact-signing-action@v2"), 2)
        payload_sign = text.index("Sign service and tray")
        package = text.index("Package signed agent")
        installer_sign = text.index("Sign installer")
        publish = text.index("Publish GitHub Release")
        self.assertLess(payload_sign, package)
        self.assertLess(package, installer_sign)
        self.assertLess(installer_sign, publish)

    def test_release_workflow_tests_and_delegates_release_publication(self):
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn("Test-Publish-GitHubRelease.ps1", text)
        self.assertLess(
            text.index("Test-Publish-GitHubRelease.ps1"),
            text.index("Build Windows executables for signing"),
        )
        publish = text[text.index("- name: Publish GitHub Release"):]
        self.assertIn("Publish-GitHubRelease.ps1", publish)
        self.assertNotIn("gh release view", publish)
        self.assertNotIn("gh release create", publish)

    def test_windows_ci_uses_node24_generation_actions(self):
        text = (ROOT / ".github" / "workflows" / "build-windows.yml").read_text(encoding="utf-8")
        self.assertIn("actions/checkout@v6", text)
        self.assertIn("actions/setup-dotnet@v5", text)


if __name__ == "__main__":
    unittest.main()
