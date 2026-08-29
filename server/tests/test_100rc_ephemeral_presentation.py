import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]


class ReleaseCandidateEphemeralPresentationTests(unittest.TestCase):
    def test_classifier_requires_session_and_multiple_non_path_signals(self):
        source=(ROOT/'windows-agent/src/AppGuard.Service/EphemeralExecutionClassifier.cs').read_text(encoding='utf-8')
        self.assertIn('ActiveInstallationSession',source)
        self.assertIn('SignatureValid',source)
        self.assertIn('SignerMatchesInstaller',source)
        self.assertIn('DurableCoverageExists',source)
        self.assertIn('ExplicitlyBlocked',source)
        self.assertIn('corroboratingSignals >= 2',source)
        self.assertNotIn('return true; // TEMP',source)

    def test_expected_ephemeral_is_a_non_authorizing_lifecycle_state(self):
        models=(ROOT/'windows-agent/src/AppGuard.Core/BackgroundPolicyModels.cs').read_text(encoding='utf-8')
        store=(ROOT/'windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs').read_text(encoding='utf-8')
        self.assertIn('SkippedEphemeral = "skipped_ephemeral"',models)
        self.assertIn('EphemeralExecutionClassifier.Classify',store)
        self.assertIn('stats.IgnoredEphemeral++',store)


if __name__=='__main__': unittest.main()
