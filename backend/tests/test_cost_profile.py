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
    # Post security-level rewrite: RSA-2048 (~112-bit classical) resolves
    # to NIST Category 1, so the KEM target is ML-KEM-512, not the
    # blanket ML-KEM-1024 the old algorithm-name mapping used to pick.
    # Larger RSA sizes (see the security-level suite) now correctly land
    # at ML-KEM-768 / ML-KEM-1024.
    assert r.algorithm == "ML-KEM-512"

    cost = r.cost_profile
    assert cost is not None
    assert cost.public_key_bytes == 800        # FIPS 203 ML-KEM-512
    assert cost.ciphertext_bytes == 768
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
    # ECDSA on P-256 is ~128-bit -> Cat 1 -> ML-DSA-44 (the closest
    # FIPS 204 signature parameter set; formally FIPS 204 labels it
    # Category 2, and every migration guide pairs it with a Category 1
    # KEM). The old mapping locked every ECDSA finding to ML-DSA-65
    # regardless of curve.
    assert r.algorithm == "ML-DSA-44"

    cost = r.cost_profile
    assert cost is not None
    assert cost.signature_bytes == 2420        # FIPS 204 ML-DSA-44
    assert cost.public_key_bytes == 1312
    assert cost.ciphertext_bytes is None
    assert cost.classical_signature_bytes == 72
    assert "NIST FIPS 204" in cost.sources
    assert cost.relative_cost == "high"        # 2420 B >= 2400


# ── Hybrid carries a cost profile too ────────────────────────────────────────

def test_hybrid_has_cost_profile() -> None:
    r = recommend(make("ECDH", CryptoUsage.KEY_ESTABLISHMENT, RiskTier.TRANSITIONAL, parameter="P-256"))
    assert r.strategy.value == "HYBRID"
    assert r.cost_profile is not None
    # ECDH on P-256 -> Cat 1 -> ML-KEM-512 (pk=800). The old mapping
    # locked every ECDH to ML-KEM-768 (pk=1184).
    assert r.cost_profile.public_key_bytes == 800


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
    # make() defaults parameter="2048" -> Cat 1 -> ML-KEM-512.
    assert data["costProfile"]["publicKeyBytes"] == 800
    assert data["costProfile"]["classicalPublicKeyBytes"] == 256
