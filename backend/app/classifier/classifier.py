"""Classification engine.

Produces a :class:`~app.models.finding.Classification` for every finding:

* **artefact type** — key-exchange, signature, encryption, hash, …
* **security goal** — confidentiality, authenticity, integrity
* **data lifetime** (Mosca ``X``) — configuration-declared for the demo
* **business criticality** — low / medium / high
* **long-lived trust anchor** flag — root CA, code signing, firmware signing

The distinction that matters most:

*Confidentiality* cryptography (key establishment, encryption) is dominated by
data lifetime — harvest-now-decrypt-later means data recorded today can be
decrypted once a quantum computer exists.

*Authenticity* cryptography (signatures) is judged differently. A short-lived
session signature carries little quantum urgency; a root CA, code-signing, or
firmware-signing key anchors trust for years and gets special handling.

For the demo, lifetimes come from a policy table keyed on usage. The metadata
file's ``declared`` values are the TEST ORACLE, not a runtime input — the
classifier must work on any repo, not just the seed.
"""

from __future__ import annotations

import logging

from app.models.asset import ArtefactType, CryptoUsage, SecurityGoal
from app.models.finding import (
    Classification,
    Criticality,
    NormalizedFinding,
)

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# Policy tables — the classifier's knowledge, separate from any seed
# ═══════════════════════════════════════════════════════════════════════════

# Usage → security goal. This is the confidentiality-vs-authenticity split.
_USAGE_TO_GOAL: dict[CryptoUsage, SecurityGoal] = {
    CryptoUsage.KEY_ESTABLISHMENT: SecurityGoal.CONFIDENTIALITY,
    CryptoUsage.KEY_TRANSPORT: SecurityGoal.CONFIDENTIALITY,
    CryptoUsage.DATA_ENCRYPTION: SecurityGoal.CONFIDENTIALITY,
    CryptoUsage.DATA_AT_REST_ENCRYPTION: SecurityGoal.CONFIDENTIALITY,
    CryptoUsage.TRANSPORT_ENCRYPTION: SecurityGoal.CONFIDENTIALITY,
    CryptoUsage.KEY_GENERATION: SecurityGoal.CONFIDENTIALITY,
    CryptoUsage.DIGITAL_SIGNATURE: SecurityGoal.AUTHENTICITY,
    CryptoUsage.SESSION_SIGNATURE: SecurityGoal.AUTHENTICITY,
    CryptoUsage.CERTIFICATE_SIGNING: SecurityGoal.AUTHENTICITY,
    CryptoUsage.CODE_SIGNING: SecurityGoal.AUTHENTICITY,
    CryptoUsage.INTEGRITY_HASH: SecurityGoal.INTEGRITY,
    CryptoUsage.PASSWORD_HASHING: SecurityGoal.INTEGRITY,
    CryptoUsage.MESSAGE_AUTHENTICATION: SecurityGoal.INTEGRITY,
    CryptoUsage.KEY_DERIVATION: SecurityGoal.CONFIDENTIALITY,
    CryptoUsage.RANDOM_GENERATION: SecurityGoal.UNKNOWN,
    CryptoUsage.UNKNOWN: SecurityGoal.UNKNOWN,
}

# Usage → default data lifetime in years (Mosca X).
# These are POLICY defaults. The actual lifetime depends on the application,
# but for the demo, reasonable values keyed on usage are sufficient.
_USAGE_TO_LIFETIME: dict[CryptoUsage, float] = {
    # Confidentiality — data lifetime dominates.
    CryptoUsage.DATA_AT_REST_ENCRYPTION: 15.0,  # Statutory retention
    CryptoUsage.DATA_ENCRYPTION: 5.0,
    CryptoUsage.KEY_ESTABLISHMENT: 5.0,
    CryptoUsage.KEY_TRANSPORT: 5.0,
    CryptoUsage.KEY_GENERATION: 10.0,  # Keys often outlive the data they protect
    CryptoUsage.TRANSPORT_ENCRYPTION: 3.0,
    CryptoUsage.KEY_DERIVATION: 5.0,
    # Authenticity — trust lifetime, not data lifetime.
    CryptoUsage.DIGITAL_SIGNATURE: 3.0,
    CryptoUsage.SESSION_SIGNATURE: 0.04,  # ~15 minutes to 1 hour
    CryptoUsage.CERTIFICATE_SIGNING: 20.0,  # Root CAs anchor trust for decades
    CryptoUsage.CODE_SIGNING: 15.0,  # Signed binaries remain deployed for years
    # Integrity
    CryptoUsage.INTEGRITY_HASH: 1.0,
    CryptoUsage.PASSWORD_HASHING: 5.0,
    CryptoUsage.MESSAGE_AUTHENTICATION: 1.0,
    # Other
    CryptoUsage.RANDOM_GENERATION: 1.0,
    CryptoUsage.UNKNOWN: 5.0,
}

# Usage → default criticality.
_USAGE_TO_CRITICALITY: dict[CryptoUsage, Criticality] = {
    CryptoUsage.DATA_AT_REST_ENCRYPTION: Criticality.HIGH,
    CryptoUsage.DATA_ENCRYPTION: Criticality.MEDIUM,
    CryptoUsage.KEY_ESTABLISHMENT: Criticality.MEDIUM,
    CryptoUsage.KEY_TRANSPORT: Criticality.MEDIUM,
    CryptoUsage.KEY_GENERATION: Criticality.HIGH,
    CryptoUsage.TRANSPORT_ENCRYPTION: Criticality.MEDIUM,
    CryptoUsage.KEY_DERIVATION: Criticality.MEDIUM,
    CryptoUsage.DIGITAL_SIGNATURE: Criticality.MEDIUM,
    CryptoUsage.SESSION_SIGNATURE: Criticality.LOW,
    CryptoUsage.CERTIFICATE_SIGNING: Criticality.HIGH,
    CryptoUsage.CODE_SIGNING: Criticality.HIGH,
    CryptoUsage.INTEGRITY_HASH: Criticality.HIGH,
    CryptoUsage.PASSWORD_HASHING: Criticality.HIGH,
    CryptoUsage.MESSAGE_AUTHENTICATION: Criticality.MEDIUM,
    CryptoUsage.RANDOM_GENERATION: Criticality.LOW,
    CryptoUsage.UNKNOWN: Criticality.MEDIUM,
}

# Usages that represent long-lived trust anchors where the lifetime of the
# anchored trust — not of a single message — dominates the risk calculation.
_LONG_LIVED_TRUST_ANCHORS: set[CryptoUsage] = {
    CryptoUsage.CERTIFICATE_SIGNING,
    CryptoUsage.CODE_SIGNING,
}

# Algorithm-specific overrides. Some algorithms have well-known weaknesses
# that change their criticality regardless of usage.
_WEAK_ALGORITHMS: dict[str, Criticality] = {
    "MD5": Criticality.HIGH,
    "SHA-1": Criticality.HIGH,
    "DES": Criticality.HIGH,
    "3DES": Criticality.HIGH,
}


def classify(finding: NormalizedFinding) -> Classification:
    """Classify a normalized finding.

    Returns a Classification with artefact type, security goal, data lifetime,
    criticality, and trust-anchor status.
    """
    usage = finding.usage
    algorithm = finding.algorithm

    # Security goal from usage.
    security_goal = _USAGE_TO_GOAL.get(usage, SecurityGoal.UNKNOWN)

    # Data lifetime from usage policy.
    data_lifetime = _USAGE_TO_LIFETIME.get(usage, 5.0)

    # Criticality from usage, overridden by algorithm weakness.
    criticality = _USAGE_TO_CRITICALITY.get(usage, Criticality.MEDIUM)
    if algorithm in _WEAK_ALGORITHMS:
        weak_crit = _WEAK_ALGORITHMS[algorithm]
        # Take the higher criticality.
        crit_order = {Criticality.LOW: 0, Criticality.MEDIUM: 1, Criticality.HIGH: 2}
        if crit_order.get(weak_crit, 0) > crit_order.get(criticality, 0):
            criticality = weak_crit

    # Long-lived trust anchor flag.
    is_trust_anchor = usage in _LONG_LIVED_TRUST_ANCHORS

    # Build rationale.
    rationale = _build_rationale(finding, security_goal, data_lifetime, is_trust_anchor)

    # Lifetime source — always policy_default for the demo.
    lifetime_source = "policy_default"

    return Classification(
        artefact_type=finding.artefact_type,
        security_goal=security_goal,
        data_lifetime_years=data_lifetime,
        criticality=criticality,
        is_long_lived_trust_anchor=is_trust_anchor,
        lifetime_source=lifetime_source,
        rationale=rationale,
    )


def _build_rationale(
    finding: NormalizedFinding,
    goal: SecurityGoal,
    lifetime: float,
    is_trust_anchor: bool,
) -> str:
    """Build a human-readable classification rationale."""
    parts: list[str] = []

    display = finding.display_name
    usage_label = finding.usage.value.replace("_", " ")
    goal_label = goal.value

    parts.append(f"{display} used for {usage_label}.")
    parts.append(f"Primary security goal: {goal_label}.")

    if goal == SecurityGoal.CONFIDENTIALITY:
        parts.append(
            f"Data lifetime of {lifetime} years drives the Mosca X value, "
            "since harvest-now-decrypt-later applies to confidentiality."
        )
    elif goal == SecurityGoal.AUTHENTICITY:
        if is_trust_anchor:
            parts.append(
                f"This is a long-lived trust anchor. The lifetime of the "
                f"anchored trust ({lifetime} years) dominates, not the "
                "lifetime of any single signed message."
            )
        else:
            parts.append(
                f"Short-lived signature ({lifetime} years). "
                "Harvest-now-decrypt-later does not apply to authenticity: "
                "a signature forged in the future is worthless against a "
                "token that has already expired."
            )
    elif goal == SecurityGoal.INTEGRITY:
        parts.append(
            f"Integrity check with a {lifetime}-year relevance window."
        )

    if finding.parameter_status.value == "unresolved":
        parts.append(
            f"Parameter could not be resolved ({', '.join(finding.unresolved_parameters)}). "
            "Confidence is reduced."
        )

    return " ".join(parts)
