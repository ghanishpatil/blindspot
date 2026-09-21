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
from app.models.recommendation import (
    CostProfile,
    LatencyProfile,
    MigrationStrategy,
    Recommendation,
)
from app.models.risk import CurrentRisk, MoscaAssessment, QuantumRisk, RiskTier
from app.recommend.latency import get_latency_profile

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
    # X25519 / X448 — Montgomery-curve ECDH. Same PQ target as NIST-curve ECDH.
    "X25519": {
        "pqc": "ML-KEM-768",
        "pqc_set": "ML-KEM-768 (NIST FIPS 203, Category 3)",
        "hybrid_prefix": True,
        "hybrid_set": "ML-KEM-768 (NIST FIPS 203, Category 3)",
        "references": ["NIST FIPS 203"],
    },
    "X448": {
        "pqc": "ML-KEM-1024",
        "pqc_set": "ML-KEM-1024 (NIST FIPS 203, Category 5)",
        "hybrid_prefix": True,
        "hybrid_set": "ML-KEM-1024 (NIST FIPS 203, Category 5)",
        "references": ["NIST FIPS 203"],
    },
    # Legacy DH — treat as classical KEM candidate for hybrid transitions.
    "DH": {
        "pqc": "ML-KEM-1024",
        "pqc_set": "ML-KEM-1024 (NIST FIPS 203, Category 5)",
        "hybrid": "ML-KEM-768",
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
    # EdDSA — same NIST category as Ed25519 (128-bit) / Ed448 (192-bit).
    "Ed25519": {
        "pqc": "ML-DSA-65",
        "pqc_set": "ML-DSA-65 (NIST FIPS 204, Category 3)",
        "hybrid_prefix": True,
        "hybrid_set": "ML-DSA-65 (NIST FIPS 204, Category 3)",
        "references": ["NIST FIPS 204"],
    },
    "Ed448": {
        "pqc": "ML-DSA-87",
        "pqc_set": "ML-DSA-87 (NIST FIPS 204, Category 5)",
        "hybrid_prefix": True,
        "hybrid_set": "ML-DSA-87 (NIST FIPS 204, Category 5)",
        "references": ["NIST FIPS 204"],
    },
    # Legacy DSA — signature-only, quantum-vulnerable, deprecated by NIST.
    "DSA": {
        "pqc": "ML-DSA-65",
        "pqc_set": "ML-DSA-65 (NIST FIPS 204, Category 3)",
        "hybrid_set": "ML-DSA-65 (NIST FIPS 204, Category 3)",
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


# ═══════════════════════════════════════════════════════════════════════════
# Published PQC artefact sizes (bytes) — the honest "cost" signal
# ═══════════════════════════════════════════════════════════════════════════
# ML-KEM sizes from NIST FIPS 203; ML-DSA sizes from NIST FIPS 204. These are
# standardised parameter sizes, not measured latency.
_KEM_SIZES: dict[str, dict[str, int]] = {
    "ML-KEM-512": {"pk": 800, "ct": 768, "sk": 1632},
    "ML-KEM-768": {"pk": 1184, "ct": 1088, "sk": 2400},
    "ML-KEM-1024": {"pk": 1568, "ct": 1568, "sk": 3168},
}
_SIG_SIZES: dict[str, dict[str, int]] = {
    "ML-DSA-44": {"pk": 1312, "sig": 2420, "sk": 2560},
    "ML-DSA-65": {"pk": 1952, "sig": 3309, "sk": 4032},
    "ML-DSA-87": {"pk": 2592, "sig": 4627, "sk": 4896},
}

# Approximate classical sizes being replaced (bytes). Coarse, labelled approximate.
_CLASSICAL_KEY_BYTES: dict[str, int] = {
    "RSA": 256,      # RSA-2048 modulus; scaled below by key size when known
    "ECDH": 65,      # uncompressed P-256 point
    "ECC": 65,
    "ECDSA": 65,
    "DH": 256,
    "X25519": 32,    # 32-byte Curve25519 public key
    "X448": 56,      # 56-byte Curve448 public key
    "Ed25519": 32,   # 32-byte Ed25519 public key
    "Ed448": 57,     # 57-byte Ed448 public key
    "DSA": 128,      # DSA-1024 y-value, coarse
}
_CLASSICAL_SIG_BYTES: dict[str, int] = {
    "RSA": 256,
    "ECDSA": 72,     # DER-encoded P-256 signature (approx)
    "Ed25519": 64,   # 64-byte fixed EdDSA signature
    "Ed448": 114,    # 114-byte Ed448 signature
    "DSA": 64,       # DSA-1024 signature, coarse
}


def _classical_key_bytes(finding: Finding) -> int | None:
    """Approximate classical public-key size for the finding's algorithm."""
    algo = finding.algorithm
    base = _CLASSICAL_KEY_BYTES.get(algo)
    if base is None:
        return None
    # Scale RSA by the resolved modulus size when we know it (2048 → 256 B, etc.).
    if algo in ("RSA", "DH") and finding.parameter and finding.parameter.isdigit():
        return max(1, int(finding.parameter) // 8)
    return base


def _cost_band(largest_bytes: int) -> str:
    """Coarse cost band from the largest PQC artefact size."""
    if largest_bytes >= 2400:
        return "high"
    if largest_bytes >= 1000:
        return "moderate"
    return "low"


def _build_cost_profile(
    pqc_component: str, finding: Finding, *, is_signature: bool, hybrid: bool
) -> CostProfile | None:
    """Build a size/cost profile for a PQC target, versus the classical algorithm."""
    table = _SIG_SIZES if is_signature else _KEM_SIZES
    sizes = table.get(pqc_component)
    if sizes is None:
        return None

    source = "NIST FIPS 204" if is_signature else "NIST FIPS 203"
    classical_key = _classical_key_bytes(finding)

    if is_signature:
        pqc_main = sizes["sig"]
        classical_sig = _CLASSICAL_SIG_BYTES.get(finding.algorithm)
        ratio = f"~{pqc_main / classical_sig:.0f}x" if classical_sig else "substantially larger"
        summary = (
            f"{pqc_component} signature is {pqc_main} B"
            + (f" vs ~{classical_sig} B for {finding.display_name}" if classical_sig else "")
            + f" ({ratio}); public key {sizes['pk']} B. "
            + ("Hybrid carries both a classical and a PQC signature. " if hybrid else "")
            + "Size drives bandwidth/storage cost."
        )
        largest = max(pqc_main, sizes["pk"])
        return CostProfile(
            target=pqc_component,
            public_key_bytes=sizes["pk"],
            signature_bytes=pqc_main,
            private_key_bytes=sizes.get("sk"),
            classical_signature_bytes=classical_sig,
            classical_public_key_bytes=classical_key,
            relative_cost=_cost_band(largest),
            size_summary=summary,
            sources=[source],
        )

    # KEM
    pqc_main = sizes["ct"]
    ratio = f"~{sizes['pk'] / classical_key:.1f}x" if classical_key else "substantially larger"
    summary = (
        f"{pqc_component} public key is {sizes['pk']} B"
        + (f" vs ~{classical_key} B for {finding.display_name}" if classical_key else "")
        + f" ({ratio}); ciphertext {sizes['ct']} B. "
        + ("Hybrid sends a classical share plus the PQC key share. " if hybrid else "")
        + "Larger handshakes mean more bandwidth per connection."
    )
    largest = max(sizes["pk"], sizes["ct"])
    return CostProfile(
        target=pqc_component,
        public_key_bytes=sizes["pk"],
        ciphertext_bytes=sizes["ct"],
        private_key_bytes=sizes.get("sk"),
        classical_public_key_bytes=classical_key,
        relative_cost=_cost_band(largest),
        size_summary=summary,
        sources=[source],
    )


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
    is_sig = _is_signature_usage(usage)
    cost = _build_cost_profile(pqc_algo, finding, is_signature=is_sig, hybrid=False)
    latency = get_latency_profile(pqc_algo)

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
        cost_profile=cost,
        latency_profile=latency,
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
    is_sig = _is_signature_usage(usage)
    cost = _build_cost_profile(pqc_component, finding, is_signature=is_sig, hybrid=True)
    latency = get_latency_profile(pqc_component)

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
        cost_profile=cost,
        latency_profile=latency,
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
