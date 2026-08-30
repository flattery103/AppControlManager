import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class Release0183Sha384SignerValidationTests(unittest.TestCase):
    def text(self, rel):
        return (ROOT / rel).read_text(encoding="utf-8")

    def test_worker_identity_calculates_sha384_tbs_certificate_digests(self):
        identity = self.text("windows-agent/src/AppGuard.Core/WorkerPolicyInputIdentity.cs")
        certificate_identity = self.text(
            "windows-agent/src/AppGuard.Core/AuthenticodeCertificateIdentity.cs"
        )
        self.assertIn("SHA384.HashData(tbsCertificate)", certificate_identity)
        self.assertIn("40 or 64 or 96", identity)

    def test_behavior_suite_covers_sha384_and_unrelated_signers(self):
        behavior = self.text(
            "windows-agent/tests/AppGuard.Core.BehaviorTests/WorkerPolicyValidationBehavior.cs"
        )
        self.assertIn("exact SHA-384 ProductName signer identity", behavior)
        self.assertIn("mutation: unrelated signer is accepted", behavior)


if __name__ == "__main__":
    unittest.main()
