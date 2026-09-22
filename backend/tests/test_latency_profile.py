"""Reference-latency profile tests -- R5.

The recommender must attach cited reference-latency data to every PQC and
hybrid recommendation. Tests here guarantee three things:

1. **Every latency value is cited.** A profile with no source is
    inadmissible - the whole point of R5 is to answer the PS clause
    ``based on ... latency`` with published benchmarks, not made-up
    numbers.
2. **The scanned system is never claimed.** ``platform_note`` must be
    present on every profile and must NOT read like the numbers were
    measured locally.
3. **The recommender attaches profiles.** PQC and HYBRID recommendations
    must carry a ``latency_profile`` whenever a matching profile exists;
    DEFER and REMEDIATE_NOW do not.
"""

from __future__ import annotations

import pytest

from app.models.finding import (
    Classification,
    Evidence,
    Finding,
)
from app.models.asset import (
    ArtefactType,
    CryptoPrimitive,
    CryptoUsage,
    ParameterStatus,
    SecurityGoal,
)
from app.models.finding import ConfidenceLevel, Criticality, DetectionMethod
from app.models.recommendation import LatencyProfile, MigrationStrategy
from app.models.risk import (
    CurrentRisk,
    MoscaAssessment,
    QuantumRisk,
    QuantumThreat,
    RiskTier,
    Severity,
)
from app.recommend.latency import available_targets, get_latency_profile
from app.recommend.recommender import recommend


# ── Shared helpers ────────────────────────────────────────────────────────

def _finding(
    algorithm: str,
    *,
    parameter: str | None,
    usage: CryptoUsage,
    lifetime_years: float,
    quantum_vulnerable: bool = True,
) -> Finding:
    """Build a Finding wired up enough to reach the recommender."""
    ev = Evidence(
        file_path="fake.py",
        line_number=1,
        code_snippet=algorithm,
        detection_method=DetectionMethod.SEMGREP_API_PATTERN,
        confidence=0.9,
    )
    classification = Classification(
        artefact_type=ArtefactType.SIGNATURE if "sign" in usage.value else ArtefactType.KEY_EXCHANGE,
        security_goal=SecurityGoal.AUTHENTICITY if "sign" in usage.value else SecurityGoal.CONFIDENTIALITY,
        data_lifetime_years=lifetime_years,
        criticality=Criticality.HIGH,
        rationale="test",
    )
    # Mosca tier: LOW_RISK when quantum-inapplicable (Grover-weakenable
    # symmetric like AES), otherwise driven by X + Y > Z.
    if not quantum_vulnerable:
        tier = RiskTier.LOW_RISK
    elif lifetime_years + 3.0 > 10.0:
        tier = RiskTier.OVERDUE
    else:
        tier = RiskTier.TRANSITIONAL
    mosca = MoscaAssessment(
        x=lifetime_years,
        y=3.0,
        z=10.0,
        equation=f"{lifetime_years} + 3 > 10",
        result=lifetime_years + 3.0 > 10.0,
        tier=tier,
        margin_years=(lifetime_years + 3.0) - 10.0,
        z_source="test",
        applicable=quantum_vulnerable,
    )
    current = CurrentRisk(is_currently_weak=False, severity=Severity.NONE, reason="ok")
    quantum = QuantumRisk(
        is_quantum_vulnerable=quantum_vulnerable,
        threat=QuantumThreat.SHOR_BREAKS if quantum_vulnerable else QuantumThreat.NONE_KNOWN,
        reason=(
            f"{algorithm} is Shor-breakable."
            if quantum_vulnerable
            else f"No quantum advantage against {algorithm}."
        ),
    )
    return Finding(
        id="test-latency",
        algorithm=algorithm,
        primitive=CryptoPrimitive.SIGNATURE if "sign" in usage.value else CryptoPrimitive.PKE,
        parameter=parameter,
        parameter_status=ParameterStatus.RESOLVED if parameter else ParameterStatus.NOT_APPLICABLE,
        usage=usage,
        artefact_type=classification.artefact_type,
        evidence=ev,
        classification=classification,
        current_risk=current,
        quantum_risk=quantum,
        mosca=mosca,
        risk_tier=mosca.tier,
    )


# ═════════════════════════════════════════════════════════════════════════
# The latency table itself
# ═════════════════════════════════════════════════════════════════════════

def test_latency_table_covers_headline_targets() -> None:
    """The three ML-KEM parameter sets and three ML-DSA parameter sets are
    the six targets the recommender routes to. All six must be covered."""
    covered = set(available_targets())
    assert {
        "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
    }.issubset(covered)


@pytest.mark.parametrize("target", [
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
])
def test_every_profile_names_a_source(target: str) -> None:
    """Every latency value must be backed by a citation. A profile with an
    empty ``sources`` list defeats the whole R5 discipline."""
    profile = get_latency_profile(target)
    assert profile is not None
    assert profile.sources, f"{target} has no sources"
    for source in profile.sources:
        assert source.strip(), f"{target} has an empty source string"


@pytest.mark.parametrize("target", [
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
])
def test_every_profile_names_a_platform(target: str) -> None:
    """``platform_note`` must be present and must explicitly disclaim that
    the numbers were not measured on the scanned system."""
    profile = get_latency_profile(target)
    assert profile is not None
    assert profile.platform_note
    disclaimer = profile.platform_note.lower()
    assert "not measured" in disclaimer, (
        f"{target} platform_note does not disclaim local measurement: "
        f"{profile.platform_note}"
    )


@pytest.mark.parametrize("target", [
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
])
def test_basis_labels_reference_only(target: str) -> None:
    profile = get_latency_profile(target)
    assert profile is not None
    assert "not runtime latency" in profile.basis.lower()


def test_kem_profiles_have_kem_operations() -> None:
    """ML-KEM profiles need keygen/encaps/decaps; ML-DSA profiles need
    sign/verify. Mixing them signals a data-entry error."""
    kem = get_latency_profile("ML-KEM-768")
    assert kem is not None
    assert kem.keygen_cycles is not None
    assert kem.encapsulate_cycles is not None
    assert kem.decapsulate_cycles is not None
    assert kem.sign_cycles is None
    assert kem.verify_cycles is None


def test_signature_profiles_have_signature_operations() -> None:
    sig = get_latency_profile("ML-DSA-65")
    assert sig is not None
    assert sig.sign_cycles is not None
    assert sig.verify_cycles is not None
    assert sig.encapsulate_cycles is None
    assert sig.decapsulate_cycles is None


def test_hybrid_target_string_matches_pqc_component() -> None:
    """Hybrid recommendations produce names like ``'X25519 + ML-KEM-768'``.
    The lookup must isolate the PQC component and return its profile."""
    profile = get_latency_profile("X25519 + ML-KEM-768")
    assert profile is not None
    assert profile.target == "ML-KEM-768"


def test_unknown_target_returns_none() -> None:
    assert get_latency_profile("NONESUCH-1024") is None
    assert get_latency_profile("") is None


def test_handshake_overhead_carries_own_citation() -> None:
    """TLS handshake byte estimates come from a different paper than the
    core cycle counts, so they carry their own source string. When
    ``handshake_extra_bytes`` is set, ``handshake_extra_bytes_source``
    must accompany it."""
    profile = get_latency_profile("ML-KEM-768")
    assert profile is not None
    assert profile.handshake_extra_bytes is not None
    assert profile.handshake_extra_bytes_source, (
        "handshake_extra_bytes set without a source citation"
    )


# ═════════════════════════════════════════════════════════════════════════
# Recommender integration
# ═════════════════════════════════════════════════════════════════════════

def test_pqc_recommendation_carries_latency_profile() -> None:
    """A pure-PQC migration for ECDSA-P-256 must carry a matching
    latency profile.

    ECDSA on P-256 is ~128-bit classical -> NIST Cat 1 -> ML-DSA-44
    (the security-level rewrite. The old algorithm-name mapping used to
    lock every ECDSA to ML-DSA-65 regardless of curve.)"""
    finding = _finding(
        "ECDSA",
        parameter="P-256",
        usage=CryptoUsage.DIGITAL_SIGNATURE,
        lifetime_years=15.0,
    )
    rec = recommend(finding)
    assert rec.strategy == MigrationStrategy.PQC
    assert rec.latency_profile is not None
    assert rec.latency_profile.target == "ML-DSA-44"
    assert rec.latency_profile.sources


def test_hybrid_recommendation_carries_latency_profile() -> None:
    """A hybrid recommendation for ECDH in the transitional window must
    carry a latency profile keyed on the PQC component.

    ECDH on P-256 is ~128-bit classical -> Cat 1 -> ML-KEM-512."""
    finding = _finding(
        "ECDH",
        parameter="P-256",
        usage=CryptoUsage.KEY_ESTABLISHMENT,
        lifetime_years=4.0,   # X + Y = 4 + 3 = 7 > 10/2 = 5 -> transitional
    )
    # Force TRANSITIONAL to exercise the hybrid branch specifically.
    finding = finding.model_copy(update={"risk_tier": RiskTier.TRANSITIONAL})
    rec = recommend(finding)
    assert rec.strategy == MigrationStrategy.HYBRID
    assert rec.latency_profile is not None
    assert rec.latency_profile.target == "ML-KEM-512"


def test_defer_recommendation_has_no_latency_profile() -> None:
    """Deferred recommendations do not need a latency profile - there is
    no migration target to profile."""
    finding = _finding(
        "AES",
        parameter="256",
        usage=CryptoUsage.DATA_ENCRYPTION,
        lifetime_years=1.0,
        quantum_vulnerable=False,
    )
    rec = recommend(finding)
    assert rec.strategy == MigrationStrategy.DEFER
    assert rec.latency_profile is None


def test_remediate_now_has_no_latency_profile() -> None:
    """A currently-weak algorithm (MD5) triggers REMEDIATE_NOW - it is
    not a quantum-migration recommendation, so the latency profile is
    intentionally absent."""
    finding = _finding(
        "MD5",
        parameter=None,
        usage=CryptoUsage.INTEGRITY_HASH,
        lifetime_years=1.0,
        quantum_vulnerable=False,
    )
    # Override current_risk to reflect a weak algorithm; also give MD5 a
    # non-empty parameter marker so the recommender does not route it to
    # INVESTIGATE. MD5 has no key size so ``NOT_APPLICABLE`` is the honest
    # parameter status.
    finding = finding.model_copy(update={
        "current_risk": CurrentRisk(
            is_currently_weak=True,
            severity=Severity.HIGH,
            reason="MD5 is collision-broken.",
        ),
        "parameter_status": ParameterStatus.NOT_APPLICABLE,
    })
    rec = recommend(finding)
    assert rec.strategy == MigrationStrategy.REMEDIATE_NOW
    assert rec.latency_profile is None


def test_latency_profile_serialises_cleanly() -> None:
    """The full pipeline persists findings as JSON; the latency profile
    round-trips without loss."""
    profile = get_latency_profile("ML-KEM-768")
    assert profile is not None
    dumped = profile.model_dump()
    round_tripped = LatencyProfile.model_validate(dumped)
    assert round_tripped == profile
