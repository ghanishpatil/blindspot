"""Classification engine tests.

Verifies the classifier assigns correct artefact types, security goals,
data lifetimes, and criticality levels — and that the confidentiality vs
authenticity split works correctly for the five headline cases.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.classifier.classifier import classify
from app.evidence.extractor import normalize
from app.models.finding import Classification, NormalizedFinding
from app.scanner.dependency_parser import parse_dependencies
from app.scanner.semgrep import run_semgrep

DEMO_REPO = Path(__file__).resolve().parent.parent.parent / "demo-repo"

pytestmark = pytest.mark.skipif(
    not DEMO_REPO.is_dir(),
    reason="demo-repo not present",
)


@pytest.fixture(scope="module")
def source_findings() -> list[NormalizedFinding]:
    matches = run_semgrep(DEMO_REPO)
    deps = parse_dependencies(DEMO_REPO)
    all_findings = normalize(matches, deps, DEMO_REPO)
    return [
        f for f in all_findings
        if f.evidence.detection_method.value != "dependency_manifest"
    ]


def _find(findings: list[NormalizedFinding], **kwargs) -> NormalizedFinding:
    """Find a finding matching all keyword filters."""
    for f in findings:
        match = True
        for key, val in kwargs.items():
            if key == "file_endswith":
                if not f.evidence.file_path.endswith(val):
                    match = False
            elif key == "algorithm":
                if f.algorithm != val:
                    match = False
            elif key == "usage":
                if f.usage.value != val:
                    match = False
        if match:
            return f
    raise AssertionError(f"No finding matching {kwargs}")


def _classify(findings: list[NormalizedFinding], **kwargs) -> Classification:
    finding = _find(findings, **kwargs)
    return classify(finding)


# ── Case 1: RSA-2048 long-lived encryption → CONFIDENTIALITY ─────────────

def test_case1_rsa_classified_as_confidentiality(
    source_findings: list[NormalizedFinding],
) -> None:
    c = _classify(source_findings, file_endswith="high_risk_rsa.py", usage="key_generation")

    assert c.security_goal.value == "confidentiality"
    assert c.artefact_type.value in ("encryption", "key-exchange")
    assert c.data_lifetime_years >= 10.0
    assert c.criticality.value == "high"
    assert "confidentiality" in c.rationale.lower()


# ── Case 2: ECDH key establishment → CONFIDENTIALITY ─────────────────────

def test_case2_ecdh_classified_as_confidentiality(
    source_findings: list[NormalizedFinding],
) -> None:
    c = _classify(source_findings, file_endswith="transitional_tls.py", algorithm="ECDH")

    assert c.security_goal.value == "confidentiality"
    assert c.artefact_type.value == "key-exchange"
    assert c.data_lifetime_years >= 3.0


# ── Case 3: ECDSA session signature → AUTHENTICITY, short-lived ──────────

def test_case3_ecdsa_classified_as_authenticity(
    source_findings: list[NormalizedFinding],
) -> None:
    c = _classify(source_findings, file_endswith="low_risk_token.py", algorithm="ECDSA")

    assert c.security_goal.value == "authenticity"
    assert c.artefact_type.value == "signature"
    # Policy default for digital_signature is 3 years. The scanner can't
    # distinguish session vs general signatures from the API call alone.
    # What matters for the demo: 3 + 3 = 6 < 10, so Mosca still says low-risk.
    assert c.data_lifetime_years <= 5.0, "signature should have moderate-to-short lifetime"
    assert c.criticality.value in ("low", "medium")
    assert not c.is_long_lived_trust_anchor


def test_case3_rationale_explains_why_short_lived_is_low_risk(
    source_findings: list[NormalizedFinding],
) -> None:
    """The rationale must explain the reasoning, not just state the conclusion."""
    c = _classify(source_findings, file_endswith="low_risk_token.py", algorithm="ECDSA")
    rationale = c.rationale.lower()

    assert "harvest" in rationale or "expired" in rationale or "short" in rationale, (
        "Rationale should explain why short-lived signatures are low risk"
    )


# ── Case 4: MD5 → INTEGRITY, high criticality ────────────────────────────

def test_case4_md5_classified_as_integrity(
    source_findings: list[NormalizedFinding],
) -> None:
    c = _classify(source_findings, file_endswith="weak_crypto_md5.py", algorithm="MD5")

    assert c.security_goal.value == "integrity"
    assert c.artefact_type.value == "hash"
    assert c.criticality.value == "high"


# ── Case 5: Unresolvable RSA → confidence mentioned in rationale ─────────

def test_case5_unresolvable_rationale_mentions_uncertainty(
    source_findings: list[NormalizedFinding],
) -> None:
    c = _classify(source_findings, file_endswith="unresolvable_keygen.py", algorithm="RSA")

    assert "unresolved" in c.rationale.lower() or "not be resolved" in c.rationale.lower()


# ── Case 6: AES-256 → CONFIDENTIALITY, high criticality ──────────────────

def test_case6_aes_classified_as_confidentiality(
    source_findings: list[NormalizedFinding],
) -> None:
    c = _classify(source_findings, file_endswith="field_encryption_aes.py", algorithm="AES")

    assert c.security_goal.value == "confidentiality"
    assert c.artefact_type.value == "encryption"


# ── Case 7: 3DES → high criticality from weak algorithm ──────────────────

def test_case7_3des_high_criticality(
    source_findings: list[NormalizedFinding],
) -> None:
    c = _classify(source_findings, file_endswith="legacy_tape_3des.py", algorithm="3DES")

    assert c.criticality.value == "high"


# ── Case 8: DES → high criticality from weak algorithm ───────────────────

def test_case8_des_high_criticality(
    source_findings: list[NormalizedFinding],
) -> None:
    c = _classify(source_findings, file_endswith="legacy_pin_des.py", algorithm="DES")

    assert c.criticality.value == "high"


# ── Case 9: SHA-1 → high criticality ─────────────────────────────────────

def test_case9_sha1_high_criticality(
    source_findings: list[NormalizedFinding],
) -> None:
    c = _classify(source_findings, file_endswith="partner_manifest_sha1.py", algorithm="SHA-1")

    assert c.criticality.value == "high"
    assert c.security_goal.value == "integrity"


# ── Every finding classifiable ────────────────────────────────────────────

def test_every_source_finding_is_classifiable(
    source_findings: list[NormalizedFinding],
) -> None:
    for f in source_findings:
        c = classify(f)
        assert c.artefact_type is not None
        assert c.security_goal is not None
        assert c.data_lifetime_years >= 0
        assert c.criticality is not None
        assert c.rationale, f"Finding {f.id} has empty rationale"


# ── Confidentiality vs authenticity split ─────────────────────────────────

def test_confidentiality_authenticity_split_is_correct(
    source_findings: list[NormalizedFinding],
) -> None:
    """The spec requires this distinction. Encryption/key-exchange must map to
    confidentiality. Signatures must map to authenticity. Hashes to integrity."""
    for f in source_findings:
        c = classify(f)
        if f.artefact_type.value in ("encryption", "key-exchange"):
            assert c.security_goal.value == "confidentiality", (
                f"{f.display_name} ({f.artefact_type.value}) should be confidentiality"
            )
        elif f.artefact_type.value == "signature":
            assert c.security_goal.value == "authenticity", (
                f"{f.display_name} ({f.artefact_type.value}) should be authenticity"
            )
        elif f.artefact_type.value == "hash":
            assert c.security_goal.value == "integrity", (
                f"{f.display_name} ({f.artefact_type.value}) should be integrity"
            )
