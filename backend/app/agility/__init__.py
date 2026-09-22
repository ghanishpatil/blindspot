"""Crypto-agility score service.

One number per scan (0-100) summarising migration readiness. Every
component is derived from fields the pipeline already computes; the
score is a *report of the scan*, not a new source of truth.

Reference: :mod:`app.agility.score`.
"""

from app.agility.score import (
    AGILITY_SCHEMA_VERSION,
    AgilityBreakdown,
    AgilityGrade,
    AgilityScore,
    compute_agility_score,
    grade_for_score,
)

__all__ = [
    "AGILITY_SCHEMA_VERSION",
    "AgilityBreakdown",
    "AgilityGrade",
    "AgilityScore",
    "compute_agility_score",
    "grade_for_score",
]
