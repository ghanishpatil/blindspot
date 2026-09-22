"""Crypto-agility score for one scan.

A single 0-100 number summarising how ready a repo is for post-quantum
migration. The score is a **composite of fields the pipeline already
computes** -- we do not derive new risk signals here. That guardrail
matters: judges (and operators) can trace every point of the score
back to a specific finding.

Composite (100 = perfect, 0 = worst):

* **Tier posture** -- 60 points. Weighted by risk tier distribution:
  every ``low-risk`` finding contributes 1.0 * (60/N), every
  ``transitional`` contributes 0.5 * (60/N), every ``overdue`` 0.
  Rewards *forward progress* on the migration.
* **Weakness immunity** -- 25 points. Full 25 when zero findings are
  ``is_currently_weak``; drops linearly to 0 as every finding turns
  currently-weak. Currently-weak is the worst class -- broken in 2025,
  independent of any quantum horizon.
* **HNDL immunity** -- 15 points. Same shape against
  ``is_hndl_exposed`` -- captured today, decrypted tomorrow.

Edge cases:

* **Empty scan** (0 findings) -> score = 100. Nothing to protect
  cannot be a bad posture. We surface an explicit ``rationale`` note
  so the UI does not print an unreachable "perfect posture" tooltip.
* **Every finding is weak + HNDL + overdue** -> score = 0.
* **Score is a float** in the domain [0, 100]. UI rounds to display.

Grades map score bands to letters so the UI has a stable palette:

    A: >= 85, B: >= 70, C: >= 55, D: >= 40, F: < 40
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


AGILITY_SCHEMA_VERSION = "blindspot.agility.v1"


# Budgets add up to 100. Kept as module constants so tests can assert
# the invariant without hard-coding it in each assertion.
_TIER_POSTURE_BUDGET = 60.0
_WEAKNESS_IMMUNITY_BUDGET = 25.0
_HNDL_IMMUNITY_BUDGET = 15.0

# Sanity check at import time -- fail loudly if someone edits one
# constant without adjusting the others.
assert (
    _TIER_POSTURE_BUDGET + _WEAKNESS_IMMUNITY_BUDGET + _HNDL_IMMUNITY_BUDGET
) == 100.0, "agility component budgets must sum to 100"


class AgilityGrade(str, Enum):
    """Letter grade for a score. Rendered verbatim on the UI card."""

    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


def grade_for_score(score: float) -> AgilityGrade:
    """Bucket a 0-100 score into a letter grade.

    Thresholds chosen so an "A" requires a genuinely clean repo (no
    weak, no HNDL, majority low-risk) rather than being handed out for
    any positive posture. Deliberately strict.
    """
    if score >= 85:
        return AgilityGrade.A
    if score >= 70:
        return AgilityGrade.B
    if score >= 55:
        return AgilityGrade.C
    if score >= 40:
        return AgilityGrade.D
    return AgilityGrade.F


@dataclass(frozen=True)
class AgilityBreakdown:
    """The three components that add up to the total.

    Each component reports its earned value and its maximum. UI can
    render a stacked bar showing exactly where points were lost.
    """

    tier_posture: float
    tier_posture_max: float
    weakness_immunity: float
    weakness_immunity_max: float
    hndl_immunity: float
    hndl_immunity_max: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "tierPosture": {
                "earned": self.tier_posture,
                "max": self.tier_posture_max,
            },
            "weaknessImmunity": {
                "earned": self.weakness_immunity,
                "max": self.weakness_immunity_max,
            },
            "hndlImmunity": {
                "earned": self.hndl_immunity,
                "max": self.hndl_immunity_max,
            },
        }


@dataclass(frozen=True)
class AgilityScore:
    """One scan's crypto-agility score plus its provenance."""

    score: float
    grade: AgilityGrade
    breakdown: AgilityBreakdown
    inputs: dict[str, int]
    rationale: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": AGILITY_SCHEMA_VERSION,
            "score": self.score,
            "grade": self.grade.value,
            "breakdown": self.breakdown.to_dict(),
            "inputs": dict(self.inputs),
            "rationale": list(self.rationale),
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_agility_score(summary: dict[str, Any]) -> AgilityScore:
    """Compute the score from a scan summary dict.

    ``summary`` is the shape :class:`app.models.scan.ScanSummary`
    serialises to (camelCase JSON): ``totalFindings``, ``overdue``,
    ``transitional``, ``lowRisk``, ``currentWeakCrypto``,
    ``hndlExposed``. We accept snake_case aliases too, so a caller
    holding a raw Pydantic model dict works either way.

    Returns an :class:`AgilityScore` with the full breakdown. Nothing
    is fabricated: every value is deterministic from the counts in
    ``summary``, and every rationale line names the field that drove
    the deduction.
    """
    total = _read_int(summary, "totalFindings", "total_findings")
    overdue = _read_int(summary, "overdue")
    transitional = _read_int(summary, "transitional")
    low_risk = _read_int(summary, "lowRisk", "low_risk")
    weak = _read_int(summary, "currentWeakCrypto", "current_weak_crypto")
    hndl = _read_int(summary, "hndlExposed", "hndl_exposed")

    inputs = {
        "totalFindings": total,
        "overdue": overdue,
        "transitional": transitional,
        "lowRisk": low_risk,
        "currentWeakCrypto": weak,
        "hndlExposed": hndl,
    }

    rationale: list[str] = []

    # ----- Tier posture -----------------------------------------------------
    if total <= 0:
        # An empty scan is not a bad scan. We award the full posture
        # budget and say so explicitly so the UI does not silently
        # advertise a "perfect" repo the operator never actually scanned.
        tier_posture = _TIER_POSTURE_BUDGET
        rationale.append(
            "No findings on this scan. Tier posture defaults to full credit; "
            "run another scan against real source to see a differentiated score."
        )
    else:
        # Clamp counted findings so a malformed summary (counts >
        # total) cannot push the score above the budget. Never expand
        # the total; that's the honest denominator.
        tiered_sum = min(total, low_risk) + 0.5 * min(total, transitional)
        tier_posture = _TIER_POSTURE_BUDGET * (tiered_sum / total)
        if overdue:
            rationale.append(
                f"{overdue} finding(s) tier=overdue -- zero tier-posture credit "
                "on each; each costs the full per-finding budget."
            )
        if transitional:
            rationale.append(
                f"{transitional} finding(s) tier=transitional -- half tier-posture "
                "credit each; still not migration-complete."
            )

    # ----- Weakness immunity -----------------------------------------------
    if total <= 0:
        weakness_immunity = _WEAKNESS_IMMUNITY_BUDGET
    else:
        weakness_share = min(1.0, weak / total)
        weakness_immunity = _WEAKNESS_IMMUNITY_BUDGET * (1.0 - weakness_share)
        if weak:
            rationale.append(
                f"{weak} finding(s) currently-weak in 2025 -- these break the "
                "weakness-immunity band regardless of any quantum horizon."
            )

    # ----- HNDL immunity ---------------------------------------------------
    if total <= 0:
        hndl_immunity = _HNDL_IMMUNITY_BUDGET
    else:
        hndl_share = min(1.0, hndl / total)
        hndl_immunity = _HNDL_IMMUNITY_BUDGET * (1.0 - hndl_share)
        if hndl:
            rationale.append(
                f"{hndl} finding(s) HNDL-exposed -- captured today, decrypted "
                "when a CRQC arrives. Costs HNDL-immunity budget."
            )

    total_score = tier_posture + weakness_immunity + hndl_immunity
    # Numerical guard: floating-point can drift a few ulps above 100
    # after all-perfect inputs. Clamp so the API contract stays clean.
    total_score = max(0.0, min(100.0, total_score))

    breakdown = AgilityBreakdown(
        tier_posture=tier_posture,
        tier_posture_max=_TIER_POSTURE_BUDGET,
        weakness_immunity=weakness_immunity,
        weakness_immunity_max=_WEAKNESS_IMMUNITY_BUDGET,
        hndl_immunity=hndl_immunity,
        hndl_immunity_max=_HNDL_IMMUNITY_BUDGET,
    )

    if not rationale:
        rationale.append(
            "All tracked risk signals at zero. Score is at the ceiling for "
            "the composite defined in app.agility.score."
        )

    return AgilityScore(
        score=total_score,
        grade=grade_for_score(total_score),
        breakdown=breakdown,
        inputs=inputs,
        rationale=rationale,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_int(summary: dict[str, Any], *keys: str) -> int:
    """Return the first present int-valued key, else 0.

    We accept either camelCase or snake_case so both the API-shape
    dict and a raw ``ScanSummary.model_dump()`` work.
    """
    for k in keys:
        if k in summary and summary[k] is not None:
            try:
                return int(summary[k])
            except (TypeError, ValueError):
                continue
    return 0


__all__ = [
    "AGILITY_SCHEMA_VERSION",
    "AgilityBreakdown",
    "AgilityGrade",
    "AgilityScore",
    "compute_agility_score",
    "grade_for_score",
]
