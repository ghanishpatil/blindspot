"""End-to-end recommender tests for the security-level-driven target.

The user-reported problem this closes: the old recommender picked the
PQC target by algorithm name, so RSA-2048 and RSA-4096 both landed at
``ML-KEM-1024`` (repetitive, wrong), while ECDH-P256 landed at Cat 3
(inconsistent with RSA at Cat 5).

These tests assert the new behaviour: the target is a function of the
derived NIST security category, so different key sizes / different
curves produce different targets. Rationale strings quote the
derivation so the choice is auditable.
"""

from __future__ import annotations

import pytest

from app.config import Settings
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


# ---------------------------------------------------------------------------
# Finding builder -- minimum surface needed to drive the recommender
# ---------------------------------------------------------------------------

def _finding(
    fid: str,
    algorithm: str,
    *,
    parameter: str | None = None,
    curve: str | None = None,
    usage: CryptoUsage = CryptoUsage.KEY_ESTABLISHMENT,
    tier: RiskTier = RiskTier.OVERDUE,
) -> Finding:
    evidence = Evidence(
        file_path="src/demo.py",
        line_number=1,
        code_snippet="x",
        detection_method=DetectionMethod.SEMGREP_API_PATTERN,
        confidence=0.9,
    )
    classification = Classification(
        data_lifetime_years=10.0,
        criticality=Criticality.HIGH,
    )
    quantum_risk = mosca.assess_quantum_risk(algorithm)
    return Finding(
        id=fid,
        algorithm=algorithm,
        parameter=parameter,
        parameter_status=(
            ParameterStatus.RESOLVED if parameter else ParameterStatus.NOT_APPLICABLE
        ),
        curve=curve,
        usage=usage,
        evidence=evidence,
        classification=classification,
        quantum_risk=quantum_risk,
        risk_tier=tier,
    )


def _local_settings(*, high_assurance: bool = False) -> Settings:
    """Standalone Settings that skip the developer's .env so
    high_assurance_mode is exactly what the test asked for."""
    return Settings(_env_file=None, high_assurance_mode=high_assurance)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# THE CORE FIX: RSA-2048 and RSA-4096 must resolve to different targets
# ---------------------------------------------------------------------------

def test_rsa_2048_and_rsa_4096_get_different_pqc_targets() -> None:
    """The smoking-gun regression test for the reported bug.

    Under the old algorithm-name-only recommender, both of these
    findings resolved to ``ML-KEM-1024``. Under the new
    category-driven recommender the target follows the derived
    security level, so RSA-2048 (Cat 1) picks a smaller target than
    RSA-4096 (Cat 3)."""
    r2048 = recommend(_finding("F1", "RSA", parameter="2048"), _local_settings())
    r4096 = recommend(_finding("F2", "RSA", parameter="4096"), _local_settings())

    assert r2048.algorithm == "ML-KEM-512"
    assert r4096.algorithm == "ML-KEM-768"
    assert r2048.algorithm != r4096.algorithm


def test_rsa_15360_resolves_to_ml_kem_1024() -> None:
    """Long-key RSA lands at the strongest KEM. Proves the top of the
    ladder is reachable and not clamped."""
    r = recommend(_finding("F3", "RSA", parameter="15360"), _local_settings())
    assert r.algorithm == "ML-KEM-1024"


# ---------------------------------------------------------------------------
# ECC across curves -- same principle
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("curve, expected_target", [
    ("P-256", "ML-KEM-512"),
    ("P-384", "ML-KEM-768"),
    ("P-521", "ML-KEM-1024"),
])
def test_ecdh_target_follows_curve_strength(curve: str, expected_target: str) -> None:
    f = _finding("F4", "ECDH", curve=curve)
    r = recommend(f, _local_settings())
    assert r.algorithm == expected_target


@pytest.mark.parametrize("curve, expected_target", [
    ("P-256", "ML-DSA-44"),
    ("P-384", "ML-DSA-65"),
    ("P-521", "ML-DSA-87"),
])
def test_ecdsa_target_follows_curve_strength(curve: str, expected_target: str) -> None:
    f = _finding(
        "F5", "ECDSA", curve=curve, usage=CryptoUsage.DIGITAL_SIGNATURE,
    )
    r = recommend(f, _local_settings())
    assert r.algorithm == expected_target


# ---------------------------------------------------------------------------
# Rationale must quote the derivation
# ---------------------------------------------------------------------------

def test_rationale_names_the_derivation_verbatim() -> None:
    """A judge / auditor reading the report should see the logic:
    algorithm -> approximate bits -> NIST category -> concrete target."""
    r = recommend(_finding("F6", "RSA", parameter="2048"), _local_settings())
    # The rationale must trace the classification chain end to end.
    assert "RSA-2048" in r.rationale
    assert "112-bit" in r.rationale
    assert "Category 1" in r.rationale
    assert "ML-KEM-512" in r.rationale


def test_rationale_for_ecdsa_p521_signature() -> None:
    r = recommend(
        _finding("F7", "ECDSA", curve="P-521", usage=CryptoUsage.DIGITAL_SIGNATURE),
        _local_settings(),
    )
    assert "P-521" in r.rationale
    assert "256-bit" in r.rationale
    assert "Category 5" in r.rationale
    assert "ML-DSA-87" in r.rationale


# ---------------------------------------------------------------------------
# Hybrid names both classical and PQC components
# ---------------------------------------------------------------------------

def test_hybrid_names_classical_and_pqc_components() -> None:
    """Transitional-tier RSA-2048 should produce a hybrid name of the
    form ``RSA-2048 + ML-KEM-512``. Both must appear."""
    f = _finding("F8", "RSA", parameter="2048", tier=RiskTier.TRANSITIONAL)
    r = recommend(f, _local_settings())
    assert r.strategy.value == "HYBRID"
    assert "RSA-2048" in r.algorithm
    assert "ML-KEM-512" in r.algorithm
    assert "+" in r.algorithm


def test_hybrid_ecdsa_p256_signature() -> None:
    f = _finding(
        "F9", "ECDSA", curve="P-256",
        usage=CryptoUsage.DIGITAL_SIGNATURE, tier=RiskTier.TRANSITIONAL,
    )
    r = recommend(f, _local_settings())
    assert r.strategy.value == "HYBRID"
    # Hybrid label strips the parenthesised curve so the string reads
    # cleanly (``ECDSA + ML-DSA-44``), not ``ECDSA (secp256r1) + ...``.
    assert r.algorithm == "ECDSA + ML-DSA-44"


# ---------------------------------------------------------------------------
# high_assurance_mode override
# ---------------------------------------------------------------------------

def test_high_assurance_mode_upgrades_every_target_to_cat_5() -> None:
    """When the operator opts into high-assurance mode, RSA-2048 stops
    resolving to ML-KEM-512 and is upgraded to ML-KEM-1024. The
    derivation still names the underlying reason plus the override."""
    high = _local_settings(high_assurance=True)
    r = recommend(_finding("F10", "RSA", parameter="2048"), high)

    assert r.algorithm == "ML-KEM-1024"
    assert "high_assurance_mode" in r.rationale
    # Original derivation must still be visible for auditability.
    assert "112-bit" in r.rationale


def test_high_assurance_mode_default_off_produces_the_natural_target() -> None:
    """Sanity check the paired test: without the override, RSA-2048
    should NOT jump to Cat 5."""
    r = recommend(_finding("F11", "RSA", parameter="2048"), _local_settings())
    assert r.algorithm == "ML-KEM-512"
    assert "high_assurance_mode" not in r.rationale
