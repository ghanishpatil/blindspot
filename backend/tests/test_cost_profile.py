"""Cost/size profile tests (PS outcome iv: "latency, cost").

The recommender attaches published FIPS parameter sizes to PQC/hybrid targets.
These tests pin the real numbers, the classical comparison, and — critically —
that we express cost as *sizes*, never as fabricated latency.
"""

from __future__ import annotations

from app.models.asset import CryptoUsage, ParameterStatus
from app.models.finding import (
    Classification,
    Criticality,
    DetectionMethod,
    Evidence,
    Finding,
)
from app.models.risk import RiskTier
from app.recommend.recommender import recommend
from app.risk import mosca


def make(
    algorithm: str,
    usage: CryptoUsage,
    tier: RiskTier,
    *,
    parameter: str | None = "2048",
) -> Finding:
    evidence = Evidence(
        file_path="a.py",
        line_number=1,
        code_snippet="x",
        detection_method=DetectionMethod.SEMGREP_API_PATTERN,
        confidence=0.9,
    )
    classification = Classification(data_lifetime_years=10.0, criticality=Criticality.HIGH)
    return Finding(
        id=f"C-{algorithm}",
        algorithm=algorithm,
        parameter=parameter,
        parameter_status=ParameterStatus.RESOLVED,
        usage=usage,
        evidence=evidence,
        classification=classification,
        quantum_risk=mosca.assess_quantum_risk(algorithm),
        current_risk=mosca.assess_current_risk(algorithm),
        mosca=mosca.assess(10.0, 3.0, 10.0, quantum_vulnerable=True),
        risk_tier=tier,
    )


# ── KEM cost profile ─────────────────────────────────────────────────────────

def test_rsa_kex_pqc_has_kem_cost_profile() -> None:
    r = recommend(make("RSA", CryptoUsage.KEY_ESTABLISHMENT, RiskTier.OVERDUE, parameter="2048"))
    assert r.strategy.value == "PQC"
    assert r.algorithm == "ML-KEM-1024"

    cost = r.cost_profile
    assert cost is not None
    assert cost.public_key_bytes == 1568       # FIPS 203 ML-KEM-1024
    assert cost.ciphertext_bytes == 1568
    assert cost.signature_bytes is None
    assert cost.classical_public_key_bytes == 256   # RSA-2048 modulus (2048/8)
    assert "NIST FIPS 203" in cost.sources
    assert cost.relative_cost in {"low", "moderate", "high"}


# ── Signature cost profile ───────────────────────────────────────────────────

def test_ecdsa_signature_pqc_has_sig_cost_profile() -> None:
    r = recommend(
        make("ECDSA", CryptoUsage.DIGITAL_SIGNATURE, RiskTier.OVERDUE, parameter="P-256")
    )
    assert r.strategy.value == "PQC"
    assert r.algorithm == "ML-DSA-65"

    cost = r.cost_profile
    assert cost is not None
    assert cost.signature_bytes == 3309        # FIPS 204 ML-DSA-65
    assert cost.public_key_bytes == 1952
    assert cost.ciphertext_bytes is None
    assert cost.classical_signature_bytes == 72
    assert "NIST FIPS 204" in cost.sources
    assert cost.relative_cost == "high"        # 3309 B ≥ 2400


# ── Hybrid carries a cost profile too ────────────────────────────────────────

def test_hybrid_has_cost_profile() -> None:
    r = recommend(make("ECDH", CryptoUsage.KEY_ESTABLISHMENT, RiskTier.TRANSITIONAL, parameter="P-256"))
    assert r.strategy.value == "HYBRID"
    assert r.cost_profile is not None
    assert r.cost_profile.public_key_bytes == 1184   # ML-KEM-768


# ── Defer / remediate have no PQC cost profile ───────────────────────────────

def test_defer_has_no_cost_profile() -> None:
    r = recommend(make("ECDSA", CryptoUsage.DIGITAL_SIGNATURE, RiskTier.LOW_RISK, parameter="P-256"))
    assert r.strategy.value == "DEFER"
    assert r.cost_profile is None


# ── Honesty: sizes, not fabricated latency ───────────────────────────────────

def test_cost_basis_is_published_sizes_not_latency() -> None:
    r = recommend(make("RSA", CryptoUsage.KEY_ESTABLISHMENT, RiskTier.OVERDUE))
    cost = r.cost_profile
    assert cost is not None
    assert "not measured" in cost.basis.lower()
    assert "size" in cost.size_summary.lower() or "key" in cost.size_summary.lower()


def test_cost_profile_serialises_camelcase() -> None:
    r = recommend(make("RSA", CryptoUsage.KEY_ESTABLISHMENT, RiskTier.OVERDUE))
    data = r.serialise()
    assert data["costProfile"]["publicKeyBytes"] == 1568
    assert data["costProfile"]["classicalPublicKeyBytes"] == 256
