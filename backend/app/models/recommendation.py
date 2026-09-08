"""Migration recommendation models.

The recommender is deterministic and explainable. Every recommendation names a
strategy, a concrete target algorithm, a parameter set, and the reasoning that
produced it — so a reviewer can disagree with the conclusion on its merits
rather than guessing at the logic.
"""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from app.models.base import BlindspotModel


class MigrationStrategy(str, Enum):
    """What the organisation should actually do about this finding."""

    PQC = "PQC"
    """Migrate to post-quantum cryptography now. Driven by an overdue tier."""

    HYBRID = "HYBRID"
    """Deploy classical + PQC together as a transition path."""

    DEFER = "DEFER"
    """Monitor. Migration is not yet warranted for this finding."""

    REMEDIATE_NOW = "REMEDIATE_NOW"
    """Fix a present-day weakness. Not a quantum recommendation."""

    INVESTIGATE = "INVESTIGATE"
    """Parameters could not be resolved; a human must confirm before deciding."""


class Recommendation(BlindspotModel):
    """A single actionable recommendation for one finding."""

    strategy: MigrationStrategy
    algorithm: str = Field(
        description="Named target, e.g. 'ML-KEM-1024' or 'X25519 + ML-KEM-768'."
    )
    parameter_set: str | None = Field(
        default=None,
        description="Explicit parameter set / security category, e.g. 'ML-KEM-768 (Category 3)'.",
    )
    rationale: str = Field(
        description="Why this strategy and algorithm follow from the evidence and risk."
    )
    replaces: str | None = Field(
        default=None, description="The classical algorithm being replaced."
    )
    priority: int = Field(
        default=3,
        ge=1,
        le=5,
        description="1 = act immediately, 5 = monitor only.",
    )
    effort: str | None = Field(
        default=None, description="Rough migration effort, e.g. 'moderate'."
    )
    migration_notes: list[str] = Field(
        default_factory=list,
        description="Practical caveats: interoperability, payload size, library support.",
    )
    references: list[str] = Field(
        default_factory=list,
        description="Standards backing the target, e.g. 'NIST FIPS 203'.",
    )
    is_quantum_recommendation: bool = Field(
        default=True,
        description=(
            "False for REMEDIATE_NOW findings, which address a current "
            "weakness rather than quantum migration urgency."
        ),
    )
