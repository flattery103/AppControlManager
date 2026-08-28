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
    VERSION = '0.16.4'

    def test_release_surfaces_move_to_0164_and_document_fragment_binding_fix(self):
        app = (ROOT / 'server' / 'app.py').read_text(encoding='utf-8')
        build = (ROOT / 'windows-agent' / 'Build.ps1').read_text(encoding='utf-8')
        self.assertIn(f'version="{self.VERSION}"', app)
        self.assertIn(f"[string]$Version='{self.VERSION}'", build)
        for rel in (
            'windows-agent/src/AppGuard.Service/AppGuard.Service.csproj',
            'windows-agent/src/AppGuard.Tray/AppGuard.Tray.csproj',
            'windows-agent/src/AppControlManager.Installer/AppControlManager.Installer.csproj',
        ):
            self.assertIn(f'<Version>{self.VERSION}</Version>', (ROOT / rel).read_text(encoding='utf-8'), rel)
        fixes = ROOT / '0.16.4-FIXES.txt'
        self.assertTrue(fixes.is_file())
        text = fixes.read_text(encoding='utf-8')
        self.assertIn('New-RuleFragment.ps1', text)
        self.assertIn('nested', text.lower())
        self.assertIn('0.16.2', text)
        self.assertIn('rollback', text.lower())


if __name__ == '__main__':
    unittest.main()
