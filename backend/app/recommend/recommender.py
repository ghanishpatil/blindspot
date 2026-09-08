"""Recommendation engine.

Deterministic and explainable. Every recommendation names a strategy, a
concrete target algorithm, a parameter set, and the reasoning that produced it.

Base strategy by tier:

===============  ===============================
Tier             Strategy
===============  ===============================
overdue          Pure / urgent PQC migration
transitional     Hybrid classical + PQC
low-risk         Defer and monitor
===============  ===============================

Two things this must not do:

* collapse into a single ``if RSA then ML-KEM`` rule that ignores usage
* present a present-day weakness (MD5) as a quantum migration recommendation —
  those get ``REMEDIATE_NOW`` instead
"""

from __future__ import annotations

import logging

from app.models.asset import CryptoUsage
from app.models.finding import Classification, Finding
from app.models.recommendation import MigrationStrategy, Recommendation
from app.models.risk import CurrentRisk, MoscaAssessment, QuantumRisk, RiskTier

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# PQC target tables — usage-aware, not just algorithm-aware
# ═══════════════════════════════════════════════════════════════════════════

# Key establishment / key transport / encryption with asymmetric crypto.
_KEX_PQC_TARGETS: dict[str, dict] = {
    "RSA": {
        "pqc": "ML-KEM-1024",
        "pqc_set": "ML-KEM-1024 (NIST FIPS 203, Category 5)",
        "hybrid": "ML-KEM-768",
        "hybrid_set": "ML-KEM-768 (NIST FIPS 203, Category 3)",
        "references": ["NIST FIPS 203"],
    },
    "ECDH": {
        "pqc": "ML-KEM-768",
        "pqc_set": "ML-KEM-768 (NIST FIPS 203, Category 3)",
        "hybrid_prefix": True,  # hybrid names both: classical + PQC
        "hybrid_set": "ML-KEM-768 (NIST FIPS 203, Category 3)",
        "references": ["NIST FIPS 203"],
    },
    "ECC": {
        "pqc": "ML-KEM-768",
        "pqc_set": "ML-KEM-768 (NIST FIPS 203, Category 3)",
        "hybrid_prefix": True,
        "hybrid_set": "ML-KEM-768 (NIST FIPS 203, Category 3)",
        "references": ["NIST FIPS 203"],
    },
}

# Signature algorithms.
_SIG_PQC_TARGETS: dict[str, dict] = {
    "ECDSA": {
        "pqc": "ML-DSA-65",
        "pqc_set": "ML-DSA-65 (NIST FIPS 204, Category 3)",
        "hybrid_prefix": True,
        "hybrid_set": "ML-DSA-65 (NIST FIPS 204, Category 3)",
        "references": ["NIST FIPS 204"],
    },
    "RSA": {
        "pqc": "ML-DSA-87",
        "pqc_set": "ML-DSA-87 (NIST FIPS 204, Category 5)",
        "hybrid_set": "ML-DSA-87 (NIST FIPS 204, Category 5)",
        "references": ["NIST FIPS 204"],
    },
}

# Remediation targets for current-day weak algorithms.
_REMEDIATION_TARGETS: dict[str, dict] = {
    "MD5": {
        "replacement": "SHA-256",
        "rationale": "MD5 is collision-broken. Replace with SHA-256 for integrity checks.",
    },
    "SHA-1": {
        "replacement": "SHA-256",
        "rationale": "SHA-1 has practical collision attacks. Replace with SHA-256.",
    },
    "DES": {
        "replacement": "AES-256",
        "rationale": "Single DES has a 56-bit key exhaustively searchable in hours. Replace with AES-256.",
    },
    "3DES": {
        "replacement": "AES-256",
        "rationale": "Triple DES has 64-bit blocks vulnerable to Sweet32. Replace with AES-256.",
    },
}


def recommend(finding: Finding) -> Recommendation:
    """Produce a recommendation for a classified, risk-assessed finding.

    The logic:
    1. If currently weak → REMEDIATE_NOW (not a quantum recommendation).
    2. If unresolved parameter → INVESTIGATE (can't size a replacement).
    3. Based on Mosca tier + usage → PQC / HYBRID / DEFER.
    """
    algorithm = finding.algorithm
    classification = finding.classification
    current_risk = finding.current_risk
    quantum_risk = finding.quantum_risk
    mosca = finding.mosca
    risk_tier = finding.risk_tier

    # ── Priority 1: Present-day weakness → REMEDIATE_NOW ──────────────
    if current_risk and current_risk.is_currently_weak:
        target = _REMEDIATION_TARGETS.get(algorithm, {})
        replacement = target.get("replacement", "a modern alternative")
        rationale = target.get(
            "rationale",
            f"{algorithm} has known present-day weaknesses. "
            "Replace regardless of quantum migration timelines.",
        )
        return Recommendation(
            strategy=MigrationStrategy.REMEDIATE_NOW,
            algorithm=replacement,
            parameter_set=None,
            rationale=rationale,
            replaces=algorithm,
            priority=1,
            effort="low" if algorithm in ("MD5", "SHA-1") else "moderate",
            is_quantum_recommendation=False,
            references=["NIST SP 800-131A Rev.2"],
        )

    # ── Priority 2: Unresolved parameter → INVESTIGATE ────────────────
    if finding.parameter_status.value == "unresolved":
        return Recommendation(
            strategy=MigrationStrategy.INVESTIGATE,
            algorithm=f"Determine {algorithm} parameters first",
            parameter_set=None,
            rationale=(
                f"{algorithm} was detected but the key size could not be resolved "
                f"({', '.join(finding.unresolved_parameters)}). "
                "A migration target cannot be sized without knowing the current parameter. "
                "Investigate and resolve before selecting a PQC replacement."
            ),
            replaces=algorithm,
            priority=2,
            effort="investigation",
            is_quantum_recommendation=True,
            references=[],
        )

    # ── Priority 3: Tier-based recommendation ─────────────────────────
    if risk_tier == RiskTier.OVERDUE:
        return _recommend_pqc(finding)
    elif risk_tier == RiskTier.TRANSITIONAL:
        return _recommend_hybrid(finding)
    else:
        return _recommend_defer(finding)


def _recommend_pqc(finding: Finding) -> Recommendation:
    """Pure PQC migration for overdue findings."""
    algorithm = finding.algorithm
    usage = finding.usage

    # Choose target based on usage, not just algorithm name.
    if _is_signature_usage(usage):
        targets = _SIG_PQC_TARGETS.get(algorithm, _SIG_PQC_TARGETS.get("RSA", {}))
    else:
        targets = _KEX_PQC_TARGETS.get(algorithm, _KEX_PQC_TARGETS.get("RSA", {}))

    pqc_algo = targets.get("pqc", "ML-KEM-768")
    pqc_set = targets.get("pqc_set", pqc_algo)
    refs = targets.get("references", [])

    usage_label = usage.value.replace("_", " ")
    return Recommendation(
        strategy=MigrationStrategy.PQC,
        algorithm=pqc_algo,
        parameter_set=pqc_set,
        rationale=(
            f"{finding.display_name} used for {usage_label} is overdue for "
            f"quantum migration (Mosca: {finding.mosca.equation if finding.mosca else 'N/A'}). "
            f"Migrate to {pqc_algo} for post-quantum security."
        ),
        replaces=finding.display_name,
        priority=1,
        effort="high",
        is_quantum_recommendation=True,
        references=refs,
        migration_notes=[
            f"Verify {pqc_algo} is supported by your deployment targets.",
            "Plan for larger key/ciphertext sizes in protocol buffers and storage.",
        ],
    )


def _recommend_hybrid(finding: Finding) -> Recommendation:
    """Hybrid classical + PQC for transitional findings."""
    algorithm = finding.algorithm
    usage = finding.usage
    param = finding.parameter or algorithm

    if _is_signature_usage(usage):
        targets = _SIG_PQC_TARGETS.get(algorithm, _SIG_PQC_TARGETS.get("RSA", {}))
        pqc_component = targets.get("pqc", "ML-DSA-65")
    else:
        targets = _KEX_PQC_TARGETS.get(algorithm, _KEX_PQC_TARGETS.get("RSA", {}))
        pqc_component = targets.get("hybrid", targets.get("pqc", "ML-KEM-768"))

    # Build the hybrid name: classical + PQC.
    if targets.get("hybrid_prefix"):
        # For ECC-based: use the detected curve/param + PQC.
        classical = param if param != algorithm else algorithm
        hybrid_name = f"{classical} + {pqc_component}"
    else:
        hybrid_name = f"{param} + {pqc_component}"

    hybrid_set = targets.get("hybrid_set", pqc_component)
    refs = targets.get("references", [])

    usage_label = usage.value.replace("_", " ")
    return Recommendation(
        strategy=MigrationStrategy.HYBRID,
        algorithm=hybrid_name,
        parameter_set=hybrid_set,
        rationale=(
            f"{finding.display_name} used for {usage_label} is in the transitional "
            "window. A hybrid approach preserves classical security while adding "
            f"post-quantum protection via {pqc_component}."
        ),
        replaces=finding.display_name,
        priority=2,
        effort="moderate",
        is_quantum_recommendation=True,
        references=refs,
        migration_notes=[
            "Hybrid mode increases handshake/signature size but provides defense in depth.",
            "Both components must be validated independently.",
        ],
    )


def _recommend_defer(finding: Finding) -> Recommendation:
    """Defer and monitor for low-risk findings."""
    mosca_note = ""
    if finding.mosca and finding.mosca.applicable:
        mosca_note = f" (Mosca: {finding.mosca.equation}, margin {finding.mosca.margin_years:.1f} years)."
    elif finding.mosca and not finding.mosca.applicable:
        mosca_note = " Mosca does not apply to this algorithm."

    return Recommendation(
        strategy=MigrationStrategy.DEFER,
        algorithm="No change required at this time",
        parameter_set=None,
        rationale=(
            f"{finding.display_name} does not require immediate migration.{mosca_note} "
            "Monitor quantum computing progress and re-evaluate periodically."
        ),
        replaces=None,
        priority=5,
        effort="none",
        is_quantum_recommendation=True,
        references=[],
    )


def _is_signature_usage(usage: CryptoUsage) -> bool:
    """Whether this usage is signature/authenticity-oriented."""
    return usage in {
        CryptoUsage.DIGITAL_SIGNATURE,
        CryptoUsage.SESSION_SIGNATURE,
        CryptoUsage.CERTIFICATE_SIGNING,
        CryptoUsage.CODE_SIGNING,
    }
