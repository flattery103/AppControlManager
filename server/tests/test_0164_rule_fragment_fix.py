import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class RuleFragmentFixTests(unittest.TestCase):
    def test_rule_fragment_flattens_configci_rule_collections_before_new_cipolicy(self):
        text = (ROOT / 'windows-agent' / 'scripts' / 'New-RuleFragment.ps1').read_text(encoding='utf-8')
        self.assertIn('$rules=@()', text)
        self.assertGreaterEqual(text.count('$rules += New-CIPolicyRule'), 2)
        self.assertNotIn('$rules=@(New-CIPolicyRule', text)
        self.assertIn('New-CIPolicy -MultiplePolicyFormat -FilePath $OutputPath -Rules $rules -UserPEs', text)


class Release0164Tests(unittest.TestCase):
    def test_release_notes_preserve_0164_fragment_binding_fix_and_rollback_baseline(self):
        fixes = ROOT / '0.16.4-FIXES.txt'
        self.assertTrue(fixes.is_file())
        text = fixes.read_text(encoding='utf-8')
        self.assertIn('New-RuleFragment.ps1', text)
        self.assertIn('nested', text.lower())
        self.assertIn('0.16.2', text)
        self.assertIn('rollback', text.lower())


if __name__ == '__main__':
    unittest.main()
