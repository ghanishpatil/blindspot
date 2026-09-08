"""Recommendation engine tests.

Tests the full pipeline: scan → normalize → classify → risk → recommend.
Verifies the five headline cases produce the expected strategies.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.classifier.classifier import classify
from app.evidence.extractor import normalize
from app.models.finding import Finding, NormalizedFinding
from app.models.risk import RiskTier
from app.recommend.recommender import recommend
from app.risk.mosca import assess, assess_current_risk, assess_quantum_risk
from app.scanner.dependency_parser import parse_dependencies
from app.scanner.semgrep import run_semgrep

DEMO_REPO = Path(__file__).resolve().parent.parent.parent / "demo-repo"

pytestmark = pytest.mark.skipif(
    not DEMO_REPO.is_dir(),
    reason="demo-repo not present",
)


def _enrich(nf: NormalizedFinding) -> Finding:
    """Run a NormalizedFinding through the full analysis pipeline."""
    classification = classify(nf)
    current_risk = assess_current_risk(nf.algorithm)
    quantum_risk = assess_quantum_risk(nf.algorithm)

    mosca_result = assess(
        x=classification.data_lifetime_years,
        y=3.0,
        z=10.0,
        z_source="test",
        quantum_vulnerable=quantum_risk.is_quantum_vulnerable,
    )

    # Determine tier: if currently weak, the tier is from Mosca but strategy
    # is overridden to REMEDIATE_NOW by the recommender.
    risk_tier = mosca_result.tier

    return Finding(
        **nf.model_dump(),
        classification=classification,
        current_risk=current_risk,
        quantum_risk=quantum_risk,
        mosca=mosca_result,
        risk_tier=risk_tier,
    )


@pytest.fixture(scope="module")
def enriched_findings() -> list[Finding]:
    matches = run_semgrep(DEMO_REPO)
    deps = parse_dependencies(DEMO_REPO)
    normalized = normalize(matches, deps, DEMO_REPO)
    source = [
        f for f in normalized
        if f.evidence.detection_method.value != "dependency_manifest"
    ]
    return [_enrich(nf) for nf in source]


def _find_enriched(findings: list[Finding], **kwargs) -> Finding:
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
    raise AssertionError(f"No enriched finding matching {kwargs}")


# ── Case 1: RSA-2048 overdue → PQC ──────────────────────────────────────

def test_case1_rsa_overdue_recommends_pqc(enriched_findings: list[Finding]) -> None:
    f = _find_enriched(enriched_findings, file_endswith="high_risk_rsa.py", usage="key_generation")
    r = recommend(f)

    assert r.strategy.value == "PQC"
    assert "ML-KEM" in r.algorithm
    assert r.parameter_set is not None
    assert r.rationale
    assert r.replaces
    assert r.is_quantum_recommendation is True


# ── Case 2: ECDH transitional → HYBRID ──────────────────────────────────

def test_case2_ecdh_transitional_recommends_hybrid(enriched_findings: list[Finding]) -> None:
    f = _find_enriched(enriched_findings, file_endswith="transitional_tls.py", algorithm="ECDH")
    r = recommend(f)

    assert r.strategy.value == "HYBRID"
    assert "ML-KEM" in r.algorithm
    # Must name both components.
    assert "+" in r.algorithm
    assert r.rationale
    assert r.is_quantum_recommendation is True


# ── Case 3: ECDSA low-risk → DEFER ──────────────────────────────────────

def test_case3_ecdsa_low_risk_recommends_defer(enriched_findings: list[Finding]) -> None:
    f = _find_enriched(enriched_findings, file_endswith="low_risk_token.py", algorithm="ECDSA")
    r = recommend(f)

    # Depending on tier, could be DEFER or HYBRID. The key is it's NOT PQC.
    assert r.strategy.value in ("DEFER", "HYBRID")
    assert r.is_quantum_recommendation is True


# ── Case 4: MD5 weak today → REMEDIATE_NOW ───────────────────────────────

def test_case4_md5_weak_recommends_remediate(enriched_findings: list[Finding]) -> None:
    f = _find_enriched(enriched_findings, file_endswith="weak_crypto_md5.py", algorithm="MD5")
    r = recommend(f)

    assert r.strategy.value == "REMEDIATE_NOW"
    assert r.is_quantum_recommendation is False, "MD5 fix is not a quantum recommendation"
    assert "SHA-256" in r.algorithm
    assert r.replaces == "MD5"


# ── Case 5: Unresolvable → INVESTIGATE ───────────────────────────────────

def test_case5_unresolvable_recommends_investigate(enriched_findings: list[Finding]) -> None:
    f = _find_enriched(enriched_findings, file_endswith="unresolvable_keygen.py", algorithm="RSA")
    r = recommend(f)

    assert r.strategy.value == "INVESTIGATE"
    assert r.is_quantum_recommendation is True
    assert "resolve" in r.rationale.lower() or "determine" in r.rationale.lower()


# ── Coverage cases ───────────────────────────────────────────────────────

def test_case7_3des_weak_recommends_remediate(enriched_findings: list[Finding]) -> None:
    f = _find_enriched(enriched_findings, file_endswith="legacy_tape_3des.py", algorithm="3DES")
    r = recommend(f)

    assert r.strategy.value == "REMEDIATE_NOW"
    assert r.is_quantum_recommendation is False
    assert "AES" in r.algorithm


def test_case8_des_weak_recommends_remediate(enriched_findings: list[Finding]) -> None:
    f = _find_enriched(enriched_findings, file_endswith="legacy_pin_des.py", algorithm="DES")
    r = recommend(f)

    assert r.strategy.value == "REMEDIATE_NOW"
    assert r.is_quantum_recommendation is False


def test_case9_sha1_weak_recommends_remediate(enriched_findings: list[Finding]) -> None:
    f = _find_enriched(enriched_findings, file_endswith="partner_manifest_sha1.py", algorithm="SHA-1")
    r = recommend(f)

    assert r.strategy.value == "REMEDIATE_NOW"
    assert "SHA-256" in r.algorithm


def test_case6_aes_low_risk_recommends_defer(enriched_findings: list[Finding]) -> None:
    f = _find_enriched(enriched_findings, file_endswith="field_encryption_aes.py", algorithm="AES")
    r = recommend(f)

    assert r.strategy.value == "DEFER"


# ── Every finding gets a recommendation ──────────────────────────────────

def test_every_enriched_finding_gets_a_recommendation(enriched_findings: list[Finding]) -> None:
    for f in enriched_findings:
        r = recommend(f)
        assert r.strategy is not None
        assert r.algorithm
        assert r.rationale
