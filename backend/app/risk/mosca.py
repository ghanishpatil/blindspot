"""Mosca's inequality — quantum migration urgency.

    X + Y > Z

* ``X`` — how long the data must stay secret (from the classifier)
* ``Y`` — how long migration takes (from config, default 3 years)
* ``Z`` — years until a cryptographically relevant quantum computer (from config)

When the inequality holds, migration should already be underway.

Two rules:

1. ``Z`` is an assumption. It comes from configuration and every result carries
   its provenance. No unsupported claim about quantum timelines is hard-coded.
2. Mosca measures *migration urgency only*. A finding that is weak today (MD5)
   is reported as a present-day defect regardless of what the inequality says.

The tier assignment:

==========  ============  =============================================
Condition   Tier          Meaning
==========  ============  =============================================
X + Y > Z   overdue       Migration should have started already
X + Y > Z/2 transitional  Migration window is approaching
otherwise   low-risk      No immediate quantum migration pressure
==========  ============  =============================================

The transitional band uses Z/2 as the threshold: if the sum reaches half the
horizon, the finding is close enough to warrant planning even if not yet overdue.
"""

from __future__ import annotations

import logging

from app.config import Settings, get_settings
from app.models.risk import (
    CurrentRisk,
    MoscaAssessment,
    QuantumRisk,
    QuantumThreat,
    RiskTier,
    Severity,
)

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# Quantum threat assessment — independent of Mosca
# ═══════════════════════════════════════════════════════════════════════════

# Algorithms fully broken by Shor's algorithm.
_SHOR_BREAKS: set[str] = {"RSA", "ECDH", "ECDSA", "ECC", "DSA", "DH", "ElGamal"}

# Algorithms weakened by Grover (symmetric/hash: effective security halved).
_GROVER_WEAKENS: set[str] = {"AES", "3DES", "DES", "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"}

# Algorithms with known present-day weaknesses.
_CURRENTLY_WEAK: dict[str, tuple[Severity, str]] = {
    "MD5": (
        Severity.HIGH,
        "MD5 is collision-vulnerable (practical attacks since 2004) and "
        "unsuitable for any security purpose.",
    ),
    "SHA-1": (
        Severity.HIGH,
        "SHA-1 has practical collision attacks (SHAttered, 2017) and is "
        "unsuitable where collision resistance matters.",
    ),
    "DES": (
        Severity.CRITICAL,
        "Single DES has a 56-bit key exhaustively searchable in hours. "
        "Broken since the late 1990s.",
    ),
    "3DES": (
        Severity.HIGH,
        "Triple DES has a 64-bit block size vulnerable to Sweet32 birthday "
        "attacks. NIST SP 800-131A Rev.2 disallowed it after 2023.",
    ),
}


def assess_current_risk(algorithm: str) -> CurrentRisk:
    """Assess whether the algorithm is broken TODAY, independent of quantum."""
    if algorithm in _CURRENTLY_WEAK:
        severity, reason = _CURRENTLY_WEAK[algorithm]
        return CurrentRisk(
            is_currently_weak=True,
            severity=severity,
            reason=reason,
        )
    return CurrentRisk(
        is_currently_weak=False,
        severity=Severity.NONE,
        reason=f"{algorithm} remains classically sound today.",
    )


def assess_quantum_risk(algorithm: str) -> QuantumRisk:
    """Assess quantum exposure of the algorithm, independent of timing."""
    if algorithm in _SHOR_BREAKS:
        return QuantumRisk(
            is_quantum_vulnerable=True,
            threat=QuantumThreat.SHOR_BREAKS,
            effective_security_loss="Fully broken by Shor's algorithm.",
            reason=(
                f"{algorithm} is asymmetric cryptography that Shor's algorithm "
                "breaks outright. A cryptographically relevant quantum computer "
                "would defeat it completely."
            ),
        )
    if algorithm in _GROVER_WEAKENS:
        # Grover halves effective security but doesn't break it.
        return QuantumRisk(
            is_quantum_vulnerable=False,
            threat=QuantumThreat.GROVER_WEAKENS,
            effective_security_loss=f"{algorithm} effective security reduced by half (Grover).",
            reason=(
                f"{algorithm} is symmetric/hash cryptography. Grover's algorithm "
                "halves the effective security level but does not break it outright. "
                "AES-256 reduced to ~128-bit security remains adequate."
            ),
        )
    return QuantumRisk(
        is_quantum_vulnerable=False,
        threat=QuantumThreat.NONE_KNOWN,
        reason=f"No known practical quantum advantage against {algorithm}.",
    )


# ═══════════════════════════════════════════════════════════════════════════
# Mosca inequality
# ═══════════════════════════════════════════════════════════════════════════

def assess(
    x: float,
    y: float,
    z: float,
    *,
    z_source: str | None = None,
    quantum_vulnerable: bool = True,
    settings: Settings | None = None,
) -> MoscaAssessment:
    """Evaluate ``X + Y > Z`` and derive the urgency tier.

    Args:
        x: Data secrecy / trust lifetime in years (from classifier).
        y: Migration time in years.
        z: Quantum horizon in years.
        z_source: Provenance of Z (from config).
        quantum_vulnerable: Whether Shor breaks this algorithm.
        settings: Configuration for default Z source string.
    """
    settings = settings or get_settings()
    if z_source is None:
        z_source = settings.quantum_horizon_source

    margin = (x + y) - z
    result = margin > 0
    equation = f"{x} + {y} > {z}"

    # Mosca does not meaningfully apply to algorithms Shor doesn't break.
    if not quantum_vulnerable:
        return MoscaAssessment(
            x=x,
            y=y,
            z=z,
            equation=equation,
            result=result,
            tier=RiskTier.LOW_RISK,
            margin_years=margin,
            z_source=z_source,
            applicable=False,
            notes=(
                "Mosca does not meaningfully apply: this algorithm is not "
                "vulnerable to Shor's algorithm. Grover at most halves the "
                "effective security level."
            ),
        )

    # Determine tier.
    if result:
        tier = RiskTier.OVERDUE
    elif (x + y) > (z / 2):
        tier = RiskTier.TRANSITIONAL
    else:
        tier = RiskTier.LOW_RISK

    notes = None
    if tier == RiskTier.OVERDUE:
        notes = (
            f"Migration is overdue: the data must remain secure for {x} years "
            f"and migration takes {y} years, but the quantum horizon is only "
            f"{z} years away."
        )
    elif tier == RiskTier.TRANSITIONAL:
        notes = (
            f"Migration window is approaching: X + Y = {x + y} exceeds "
            f"half the quantum horizon (Z/2 = {z / 2})."
        )

    return MoscaAssessment(
        x=x,
        y=y,
        z=z,
        equation=equation,
        result=result,
        tier=tier,
        margin_years=margin,
        z_source=z_source,
        applicable=True,
        notes=notes,
    )
