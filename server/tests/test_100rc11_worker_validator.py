from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_rc11_prunes_unvalidated_companion_signers_before_publication():
    validator = (
        ROOT / "windows-agent/src/AppGuard.Core/WorkerPolicyValidator.cs"
    ).read_text(encoding="utf-8")

    assert "RemoveUnvalidatedCompanionSigners" in validator
    assert "validatedSignerIds" in validator
    assert "signer.Remove()" in validator
    assert "signerReference.Remove()" in validator
