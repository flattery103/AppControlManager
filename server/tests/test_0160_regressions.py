import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class Release0160RegressionTests(unittest.TestCase):
    def test_powershell_helper_avoids_json_switch_collision_and_flattens_json_array(self):
        text = (ROOT / 'windows-agent' / 'scripts' / 'New-SupplementalForFiles.ps1').read_text(encoding='utf-8')
        self.assertIn('$fileListJson=Get-Content', text)
        self.assertIn('$inputPaths=[string[]](ConvertFrom-Json -InputObject $fileListJson)', text)
        self.assertNotIn('$json=Get-Content', text)
        self.assertNotIn('$inputPaths=@($json | ConvertFrom-Json)', text)

    def test_shell_scripts_are_forced_to_lf_in_git_and_source_archive(self):
        attributes = (ROOT / '.gitattributes').read_text(encoding='utf-8')
        self.assertIn('*.sh text eol=lf', attributes)
        workflow = (ROOT / '.github' / 'workflows' / 'release.yml').read_text(encoding='utf-8')
        self.assertIn('environment: release', workflow)
        self.assertIn('git -c core.autocrlf=false archive', workflow)

    def test_server_updater_normalizes_extracted_shell_scripts_before_execution(self):
        text = (ROOT / 'server' / 'update-from-github.sh').read_text(encoding='utf-8')
        unzip_pos = text.index('unzip -q "$ZIP" -d "$TMP/extracted"')
        normalize_pos = text.index("find \"$TMP/extracted\" -type f -name '*.sh' -exec sed -i 's/\\r$//' {} +")
        upgrade_pos = text.index('./upgrade-server.sh')
        self.assertLess(unzip_pos, normalize_pos)
        self.assertLess(normalize_pos, upgrade_pos)

    def test_policy_helper_has_deduplicated_bundle_scans_and_signer_cache_metrics(self):
        text = (ROOT / 'windows-agent' / 'src' / 'AppGuard.Service' / 'PolicyHelper.cs').read_text(encoding='utf-8')
        for expected in (
            'ConcurrentDictionary<string, PublisherCacheEntry>',
            'LastWriteUtcTicks',
            'cached.Size == size && cached.LastWriteUtcTicks == lastWriteUtcTicks',
            'GetPublisherCached',
            'scanKeys',
            'cacheHits',
            'signerReads',
            'filesExamined',
            'scanElapsed',
            'bundle-scan summary',
        ):
            self.assertIn(expected, text)
        self.assertIn('if (!scanKeys.Add(scanKey))', text)


if __name__ == '__main__':
    unittest.main()
