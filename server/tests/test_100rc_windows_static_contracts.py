import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class WindowsStaticContractTests(unittest.TestCase):
    def test_tray_is_single_instance_per_interactive_session(self):
        program = (ROOT / "windows-agent/src/AppGuard.Tray/Program.cs").read_text(encoding="utf-8")
        self.assertIn("new Mutex(", program)
        self.assertIn("true,", program)
        self.assertIn("Process.GetCurrentProcess().SessionId", program)
        self.assertIn("if (!createdNew) return;", program)

    def test_service_controller_dependency_is_explicit(self):
        project = (ROOT / "windows-agent/src/AppGuard.Service/AppGuard.Service.csproj").read_text(encoding="utf-8")
        self.assertIn('PackageReference Include="System.ServiceProcess.ServiceController" Version="10.0.0"', project)

    def test_temporary_root_comparison_requires_a_path_boundary(self):
        source = (ROOT / "windows-agent/src/AppGuard.Service/EphemeralExecutionClassifier.cs").read_text(encoding="utf-8")
        self.assertIn("rootWithSeparator", source)
        self.assertIn("DirectorySeparatorChar", source)
        self.assertNotIn("full.StartsWith(Path.GetFullPath(root!)", source)

    def test_heartbeat_reads_summaries_from_the_background_store(self):
        source = (ROOT / "windows-agent/src/AppGuard.Service/AgentWorker.cs").read_text(encoding="utf-8")
        self.assertIn("_backgroundPolicyStore.GetWorkSummaries()", source)
        self.assertNotIn("_backgroundPolicy.GetWorkSummaries()", source)

    def test_release_publisher_does_not_splat_single_flag_strings(self):
        source = (ROOT / ".github/scripts/Publish-GitHubRelease.ps1").read_text(encoding="utf-8")
        self.assertNotIn("@createFlags", source)
        self.assertNotIn("@editFlags", source)

    def test_cross_signed_authenticode_expansion_is_bounded_by_verified_public_keys(self):
        path = ROOT / "windows-agent/src/AppGuard.Core/AuthenticodeCertificateIdentity.cs"
        self.assertTrue(path.is_file())
        source = path.read_text(encoding="utf-8")
        self.assertIn("MaximumCertificateTableBytes", source)
        self.assertIn("MaximumCertificateEntries", source)
        self.assertIn("MaximumEmbeddedCertificates", source)
        self.assertIn("PublicKeyFingerprint", source)
        self.assertIn("SignedCms", source)
        self.assertIn("verifiedPublicKeys.Contains", source)

    def test_approved_request_views_hide_policy_notes_and_install_action(self):
        request_form = (ROOT / "windows-agent/src/AppGuard.Tray/RequestForm.cs").read_text(encoding="utf-8")
        session_form = (ROOT / "windows-agent/src/AppGuard.Tray/SessionRequestForm.cs").read_text(encoding="utf-8")
        decision_form = (ROOT / "windows-agent/src/AppGuard.Tray/DecisionForm.cs").read_text(encoding="utf-8")

        self.assertIn("_install.Visible = false;", request_form)
        self.assertIn("_install.Visible = false;", session_form)
        self.assertIn('"This application is approved. You can run it now."', request_form)
        self.assertIn('"This application is approved. You can run it now."', session_form)
        self.assertIn("Text = approved ? \"\" : request.DecisionNote ?? \"\"", decision_form)
        self.assertIn("Visible = !approved", decision_form)


if __name__ == "__main__":
    unittest.main()
