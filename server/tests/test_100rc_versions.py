import sys, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'server'))
import app


class ReleaseCandidateVersionTests(unittest.TestCase):
    def test_prerelease_precedence(self):
        ordered=['0.18.3','1.0.0-rc.1','1.0.0-rc.2','1.0.0']
        self.assertEqual(sorted(ordered,key=app.version_key),ordered)
        self.assertTrue(app.version_at_least('1.0.0','1.0.0-rc.2'))
        self.assertFalse(app.version_at_least('1.0.0-rc.2','1.0.0'))

    def test_version_parser_rejects_uncontrolled_labels(self):
        for value in ('1.0','1.0.0-beta.1','latest','1.0.0-rc.x'):
            with self.assertRaises(ValueError): app.version_key(value)


if __name__=='__main__': unittest.main()
