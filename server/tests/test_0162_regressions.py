import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class Release0162RegressionTests(unittest.TestCase):
    def test_enforcement_uses_dedicated_learned_baseline_builder(self):
        text = (ROOT / 'windows-agent' / 'scripts' / 'End-LearningAndEnforce.ps1').read_text(encoding='utf-8')
        self.assertIn('New-LearnedBaselinePolicy.ps1', text)
        self.assertIn('-LearnedApplications $learned', text)
        self.assertNotIn("New-SupplementalForFiles.ps1\" -FilePath $paths -Name 'AppControl Manager Learned Baseline'", text)

    def test_learned_baseline_groups_safe_publisher_products_and_hashes_unsigned_files(self):
        script = ROOT / 'windows-agent' / 'scripts' / 'New-LearnedBaselinePolicy.ps1'
        self.assertTrue(script.is_file())
        text = script.read_text(encoding='utf-8')
        self.assertIn('Test-AppGuardProductFamilyCandidate', text)
        self.assertIn('SpecificFileNameLevel ProductName', text)
        self.assertIn('New-CIPolicyRule -Level FilePublisher', text)
        self.assertIn('New-CIPolicyRule -Level Hash', text)
        self.assertIn('familyRepresentatives', text)
        self.assertIn('individualSignedFiles', text)
        self.assertIn('hashFiles', text)
        self.assertIn('publisherProductGroups', text)

    def test_learned_baseline_reuses_learning_metadata_instead_of_rescanning_signers(self):
        text = (ROOT / 'windows-agent' / 'scripts' / 'New-LearnedBaselinePolicy.ps1').read_text(encoding='utf-8')
        self.assertIn('[object[]]$LearnedApplications', text)
        self.assertIn('.publisher', text)
        self.assertIn('.product_name', text)
        self.assertIn('.file_version', text)
        self.assertNotIn('Get-FileMetadata', text)
        self.assertNotIn('Get-AuthenticodeSignature', text)

    def test_learned_baseline_prefers_lowest_parseable_version_for_product_family_representative(self):
        text = (ROOT / 'windows-agent' / 'scripts' / 'New-LearnedBaselinePolicy.ps1').read_text(encoding='utf-8')
        self.assertIn('[version]::TryParse', text)
        self.assertIn('parsed_version', text)
        self.assertIn('lowest', text.lower())

    def test_learned_baseline_emits_classification_and_generation_metrics(self):
        text = (ROOT / 'windows-agent' / 'scripts' / 'New-LearnedBaselinePolicy.ps1').read_text(encoding='utf-8')
        for marker in (
            'ACM_STAGE learned-classification',
            'publisherProductGroups=',
            'individualPublisherRules=',
            'hashRules=',
            'ACM_STAGE learned-family-rules',
            'ACM_STAGE learned-individual-rules',
            'ACM_STAGE learned-hash-rules',
            'ACM_STAGE rule-generation',
            'ACM_STAGE policy-xml',
            'ACM_STAGE policy-convert',
            'ACM_STAGE policy-install',
        ):
            self.assertIn(marker, text)

    def test_policy_helper_cleans_configci_noise_from_stderr_on_failure(self):
        text = (ROOT / 'windows-agent' / 'src' / 'AppGuard.Service' / 'PolicyHelper.cs').read_text(encoding='utf-8')
        self.assertIn('var stderr = CleanPolicyHelperOutput(await stderrTask);', text)
        # ConfigCI sometimes serializes the status message as a quoted string, exactly as seen
        # in the 0.16.1 forced-cancellation log. Normalize the quotes before comparison.
        self.assertIn("Trim().Trim('\"')", text)


if __name__ == '__main__':
    unittest.main()
