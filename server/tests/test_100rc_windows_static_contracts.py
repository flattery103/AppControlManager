import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class WindowsStaticContractTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
