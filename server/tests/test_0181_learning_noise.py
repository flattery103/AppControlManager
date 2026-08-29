import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class Release0181LearningNoiseTests(unittest.TestCase):
    def text(self, rel):
        return (ROOT / rel).read_text(encoding="utf-8")

    def test_learning_events_are_preserved_immediately_in_a_bounded_protected_cache(self):
        cache = self.text("windows-agent/src/AppGuard.Service/LearningFileCache.cs")
        watcher = self.text("windows-agent/src/AppGuard.Service/LearningEventWatcher.cs")
        collector = self.text("windows-agent/src/AppGuard.Service/EventCollector.cs")
        program = self.text("windows-agent/src/AppGuard.Service/Program.cs")
        paths = self.text("windows-agent/src/AppGuard.Core/Paths.cs")
        self.assertIn("MaxCacheFileBytes", cache)
        self.assertIn("FileShare.ReadWrite | FileShare.Delete", cache)
        self.assertIn("TimeSpan.FromDays(2)", cache)
        self.assertIn("EventID=3076", watcher)
        self.assertIn("_cache.Capture", watcher)
        self.assertIn("public static EventUpload FromRecord", collector)
        self.assertIn("AddSingleton<LearningFileCache>", program)
        self.assertIn("AddHostedService<LearningEventWatcher>", program)
        self.assertIn("LearningCacheDirectory", paths)

    def test_learning_preparation_prefers_live_input_then_preserved_copy(self):
        store = self.text("windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs")
        method = store[store.index("PrepareLearningEvents"):store.index("private static void CountQueueDisposition")]
        self.assertIn("_learningCache.Resolve", method)
        self.assertIn("representativePath", method)
        self.assertLess(method.index("_learningCache.Resolve"), method.index("!File.Exists(representativePath)"))
        self.assertIn("representativePath", method[method.index("UpsertProductCandidate"):])

    def test_missing_representatives_expire_without_becoming_failed_or_retryable(self):
        models = self.text("windows-agent/src/AppGuard.Core/BackgroundPolicyModels.cs")
        store = self.text("windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs")
        processor = self.text("windows-agent/src/AppGuard.Service/BackgroundPolicyProcessor.cs")
        self.assertIn('public const string Expired = "expired"', models)
        self.assertIn("MarkRuleExpired", store)
        self.assertIn("LegacyMissingRepresentativeError", store)
        self.assertIn("BackgroundPolicyStatuses.Expired", store)
        self.assertIn("ExpireDependentBundles", store)
        self.assertIn("catch (FileNotFoundException ex)", processor)
        self.assertIn("_store.MarkRuleExpired", processor)
        retry = store[store.index("RetryFailedWork"):store.index("PrepareLearningEvents")]
        self.assertNotIn("BackgroundPolicyStatuses.Expired", retry)

    def test_prompt_noise_is_deduplicated_without_allowing_the_file(self):
        tray = self.text("windows-agent/src/AppGuard.Tray/TrayContext.cs")
        self.assertIn("BlockDedupe", tray)
        self.assertIn("TimeSpan.FromMinutes(2)", tray)
        self.assertIn("IsRepeatedBlock", tray)
        repeated = tray[tray.index("private bool IsRepeatedBlock"):tray.index("private SessionRequestForm CreateSessionForm")]
        self.assertNotIn("disposition", repeated.lower())
        self.assertNotIn("approve", repeated.lower())


if __name__ == "__main__":
    unittest.main()
