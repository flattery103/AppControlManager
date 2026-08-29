import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class Release0180DotNetEphemeralTests(unittest.TestCase):
    def text(self, rel):
        return (ROOT / rel).read_text(encoding="utf-8")

    def test_classifier_is_behavior_tested_with_narrow_positive_and_negative_paths(self):
        classifier = ROOT / "windows-agent/src/AppGuard.Core/LearnedPathClassifier.cs"
        self.assertTrue(classifier.is_file())
        behavior = self.text("windows-agent/tests/AppGuard.Core.BehaviorTests/Program.cs")
        for literal in (
            r"C:\Users\alice\AppData\Local\Temp\.net\MyApp\bundle123\helper.dll",
            r"C:\Windows\Temp\.NET\Svc\bundle456\native.dll",
            r"C:\Users\alice\AppData\Local\Temp\.net\MyApp\bundle123\..\escape.dll",
            r"C:\Users\alice\AppData\Local\Temp\nsh1234.tmp\helper.dll",
            r"C:\Windows\Installer\cache.msi",
            r"C:\Users\alice\AppData\Local\Temp\random\helper.dll",
            r"C:\Users\alice\AppData\Local\Temp\.net\MyApp\bundle123",
            r"C:\Temp\.net\MyApp\bundle123\helper.dll",
        ):
            self.assertIn(literal, behavior)
        self.assertIn("LearnedPathClassifier.IsExpectedDotNetExtraction", behavior)

    def test_learning_ignores_dotnet_children_before_file_availability_checks(self):
        store = self.text("windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs")
        method = store[store.index("PrepareLearningEvents"):store.index("private static void CountQueueDisposition")]
        ignored = method.index("LearnedPathClassifier.IsExpectedDotNetExtraction")
        missing = method.index("!File.Exists(filePath)")
        self.assertLess(ignored, missing)
        self.assertIn("stats.IgnoredEphemeral++", method)
        self.assertIn("IgnoredEphemeral", self.text("windows-agent/src/AppGuard.Core/BackgroundPolicyModels.cs"))

    def test_installation_mixed_result_does_not_warn_but_zero_rule_still_fails(self):
        reconciler = self.text("windows-agent/src/AppGuard.Core/InstallationLearningReconciler.cs")
        models = self.text("windows-agent/src/AppGuard.Core/InstallationModeModels.cs")
        helper = self.text("windows-agent/src/AppGuard.Service/PolicyHelper.cs")
        finalizer = helper[helper.index("FinalizeInstallationModeAsync"):helper.index("ForceEnforcementAsync")]
        self.assertIn("IgnoredEphemeralCount", reconciler)
        self.assertIn("IgnoredEphemeralCount", models)
        self.assertIn("HasWarnings => SkippedCount > 0", models)
        self.assertIn("plan.IgnoredEphemeralCount", finalizer)
        self.assertIn("none could be converted into safe authorization rules", finalizer)

    def test_diagnostics_separate_ignored_from_skipped_and_unpreparable(self):
        agent = self.text("windows-agent/src/AppGuard.Service/AgentWorker.cs")
        helper = self.text("windows-agent/src/AppGuard.Service/PolicyHelper.cs")
        manager = self.text("windows-agent/src/AppGuard.Service/InstallationModeManager.cs")
        self.assertIn("ignoredEphemeral=", agent)
        self.assertIn("ignoredEphemeral=", helper)
        enforcement = helper[helper.index("EnableEnforcementAsync"):helper.index("FinalizeInstallationModeAsync")]
        self.assertIn("!LearnedPathClassifier.IsExpectedDotNetExtraction", enforcement)
        self.assertIn("IgnoredEphemeralCount", manager)


if __name__ == "__main__":
    unittest.main()
