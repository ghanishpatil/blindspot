"""Risk models.

Blindspot keeps two risk questions strictly separate:

**Current weakness** — is this cryptography broken *today*? MD5 collisions and
single-DES key sizes are present-tense defects. They are not quantum problems
and must never be laundered into one.

**Quantum migration urgency** — Mosca's inequality, ``X + Y > Z``. This asks
whether migration must start now, not whether the algorithm is currently safe.

A finding can be weak today, urgent for quantum reasons, both, or neither.
"""

from __future__ import annotations

from enum import Enum

from pydantic import Field, model_validator

from app.models.base import BlindspotModel


class RiskTier(str, Enum):
    """Quantum migration urgency tier derived from Mosca's inequality."""

    OVERDUE = "overdue"
    TRANSITIONAL = "transitional"
    LOW_RISK = "low-risk"


class Severity(str, Enum):
    """Severity of a present-day cryptographic weakness."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class QuantumThreat(str, Enum):
    """Which quantum algorithm undermines the primitive, and how badly."""

    SHOR_BREAKS = "shor_breaks"
    """Asymmetric cryptography fully broken by Shor's algorithm."""

    GROVER_WEAKENS = "grover_weakens"
    """Symmetric/hash security level reduced by Grover's algorithm."""

    NONE_KNOWN = "none_known"
    """No known practical quantum advantage against this primitive."""

    UNKNOWN = "unknown"


class CurrentRisk(BlindspotModel):
    """Present-day security assessment, independent of quantum concerns."""

    is_currently_weak: bool = Field(
        description="True when the construction is already considered broken or deprecated."
    )
    severity: Severity = Severity.NONE
    reason: str = Field(
        description="Plain-language explanation of the present-day weakness, or why none applies."
    )
    references: list[str] = Field(
        default_factory=list,
        description="Standards or advisories supporting the assessment.",
    )


class QuantumRisk(BlindspotModel):
    """Quantum exposure of the primitive, independent of timing."""

    is_quantum_vulnerable: bool = Field(
        description="True when a cryptographically relevant quantum computer would defeat this."
    )
    threat: QuantumThreat = QuantumThreat.UNKNOWN
    effective_security_loss: str | None = Field(
        default=None,
        description="e.g. 'Fully broken' or 'AES-256 reduced to ~128-bit security'.",
    )
    reason: str = Field(description="Why the primitive is or is not quantum vulnerable.")


class MoscaAssessment(BlindspotModel):
    """Mosca's inequality for one finding.

    ``X + Y > Z`` where:

    * ``X`` — how long the protected data must stay secret (years)
    * ``Y`` — how long migration will take (years)
    * ``Z`` — years until a cryptographically relevant quantum computer

    When the inequality holds, migration should already be underway.

    The UI renders :attr:`equation` verbatim, so it is built from the same
    numbers used in the comparison rather than being formatted separately.
    """

    x: float = Field(ge=0, description="Data secrecy lifetime in years.")
    y: float = Field(ge=0, description="Migration time in years.")
    z: float = Field(gt=0, description="Quantum horizon in years.")

    equation: str = Field(
        description="Rendered inequality exactly as shown to the user, e.g. '15 + 3 > 10'."
    )
    result: bool = Field(description="True when X + Y > Z, i.e. migration is urgent.")
    tier: RiskTier = Field(description="Urgency tier derived from the inequality.")

    margin_years: float = Field(
        description="(X + Y) - Z. Positive means overdue; negative is remaining slack."
    )
    z_source: str = Field(
        description="Provenance of Z. Never presented as an established fact."
    )
    applicable: bool = Field(
        default=True,
        description=(
            "False when Mosca does not meaningfully apply — for example a "
            "primitive with no known quantum vulnerability."
        ),
    )
    notes: str | None = Field(
        default=None,
        description="Assumptions or caveats worth surfacing next to the numbers.",
    )

    @model_validator(mode="after")
    def _check_internal_consistency(self) -> MoscaAssessment:
        """The stored result and margin must agree with the stored X, Y and Z.

        Guards against a formatted string or cached tier drifting away from the
        numbers it claims to represent.
        """
        expected_margin = (self.x + self.y) - self.z
        if abs(self.margin_years - expected_margin) > 1e-6:
            raise ValueError(
                f"margin_years {self.margin_years} does not match "
                f"(X + Y) - Z = {expected_margin}"
            )
        if self.result is not (expected_margin > 0):
            raise ValueError(
                f"result {self.result} contradicts X + Y > Z "
                f"({self.x} + {self.y} > {self.z})"
            )
        return self
