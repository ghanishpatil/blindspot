"""Tests for :mod:`app.agility.score` -- pure composite math.

Locks in:

* Budgets sum to 100 (invariant guard).
* Perfect posture -> 100 / grade A.
* Worst posture (everything overdue, weak, HNDL) -> 0 / grade F.
* Empty scan -> 100 with an explicit rationale note.
* Each component contributes independently and additively.
* Snake_case + camelCase inputs both work.
* Grade thresholds map correctly.
"""

from __future__ import annotations

import pytest

from app.agility.score import (
    AGILITY_SCHEMA_VERSION,
    AgilityGrade,
    compute_agility_score,
    grade_for_score,
)


# ---------------------------------------------------------------------------
# Invariants
# ---------------------------------------------------------------------------

def test_component_budgets_sum_to_100() -> None:
    """Load-time invariant. If any component budget shifts without an
    equal offset elsewhere, the module fails to import -- this test
    exists so a refactor of the constants gets caught in CI, not in
    prod."""
    from app.agility import score as mod
    total = (
        mod._TIER_POSTURE_BUDGET
        + mod._WEAKNESS_IMMUNITY_BUDGET
        + mod._HNDL_IMMUNITY_BUDGET
    )
    assert total == pytest.approx(100.0)


def test_schema_version_is_stable() -> None:
    assert AGILITY_SCHEMA_VERSION == "blindspot.agility.v1"


# ---------------------------------------------------------------------------
# Perfect / worst / empty
# ---------------------------------------------------------------------------

def test_all_low_risk_no_weak_no_hndl_scores_100_grade_A() -> None:
    result = compute_agility_score({
        "totalFindings": 10,
        "overdue": 0,
        "transitional": 0,
        "lowRisk": 10,
        "currentWeakCrypto": 0,
        "hndlExposed": 0,
    })
    assert result.score == pytest.approx(100.0)
    assert result.grade == AgilityGrade.A


def test_all_overdue_weak_and_hndl_scores_zero_grade_F() -> None:
    result = compute_agility_score({
        "totalFindings": 4,
        "overdue": 4,
        "transitional": 0,
        "lowRisk": 0,
        "currentWeakCrypto": 4,
        "hndlExposed": 4,
    })
    assert result.score == pytest.approx(0.0)
    assert result.grade == AgilityGrade.F
    # Rationale must name every failing lever.
    combined = " ".join(result.rationale).lower()
    assert "overdue" in combined
    assert "currently-weak" in combined
    assert "hndl" in combined


def test_empty_scan_scores_100_with_explicit_rationale() -> None:
    """A scan of a repo with zero findings must NOT silently print
    'perfect posture' without saying so -- the rationale line makes
    the honest interpretation visible."""
    result = compute_agility_score({
        "totalFindings": 0,
        "overdue": 0,
        "transitional": 0,
        "lowRisk": 0,
        "currentWeakCrypto": 0,
        "hndlExposed": 0,
    })
    assert result.score == pytest.approx(100.0)
    assert result.grade == AgilityGrade.A
    assert any("No findings" in line for line in result.rationale)


# ---------------------------------------------------------------------------
# Component isolation
# ---------------------------------------------------------------------------

def test_tier_posture_alone_drives_score_when_weak_and_hndl_are_zero() -> None:
    """Half low-risk + half overdue -> 60 * (5/10) = 30 tier posture,
    full 25 weakness, full 15 hndl = 70 total."""
    result = compute_agility_score({
        "totalFindings": 10,
        "overdue": 5,
        "transitional": 0,
        "lowRisk": 5,
        "currentWeakCrypto": 0,
        "hndlExposed": 0,
    })
    assert result.score == pytest.approx(30.0 + 25.0 + 15.0)
    assert result.grade == AgilityGrade.B


def test_transitional_earns_half_the_tier_posture_credit() -> None:
    """All-transitional -> 60 * 0.5 = 30 tier posture. + 25 + 15 = 70."""
    result = compute_agility_score({
        "totalFindings": 4,
        "overdue": 0,
        "transitional": 4,
        "lowRisk": 0,
        "currentWeakCrypto": 0,
        "hndlExposed": 0,
    })
    assert result.score == pytest.approx(30.0 + 25.0 + 15.0)


def test_weakness_immunity_scales_linearly_with_weak_share() -> None:
    """1 in 4 weak = 6.25 lost from the 25-point weakness band."""
    result = compute_agility_score({
        "totalFindings": 4,
        "overdue": 0,
        "transitional": 0,
        "lowRisk": 4,
        "currentWeakCrypto": 1,
        "hndlExposed": 0,
    })
    expected = 60.0 + 25.0 * 0.75 + 15.0
    assert result.score == pytest.approx(expected)


def test_hndl_immunity_scales_linearly_with_hndl_share() -> None:
    """3 in 5 HNDL = 60% share = 9 lost from the 15-point HNDL band."""
    result = compute_agility_score({
        "totalFindings": 5,
        "overdue": 0,
        "transitional": 0,
        "lowRisk": 5,
        "currentWeakCrypto": 0,
        "hndlExposed": 3,
    })
    expected = 60.0 + 25.0 + 15.0 * (1 - 3 / 5)
    assert result.score == pytest.approx(expected)


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------

def test_snake_case_and_camel_case_inputs_agree() -> None:
    camel = compute_agility_score({
        "totalFindings": 4,
        "overdue": 2,
        "transitional": 1,
        "lowRisk": 1,
        "currentWeakCrypto": 1,
        "hndlExposed": 1,
    })
    snake = compute_agility_score({
        "total_findings": 4,
        "overdue": 2,
        "transitional": 1,
        "low_risk": 1,
        "current_weak_crypto": 1,
        "hndl_exposed": 1,
    })
    assert camel.score == pytest.approx(snake.score)
    assert camel.grade == snake.grade


def test_score_never_exceeds_100_with_malformed_counts_over_total() -> None:
    """A summary where sub-counts exceed total (bug upstream) must not
    push the score above the composite ceiling. This is the honesty
    guardrail: the number stays in [0, 100] regardless of input."""
    result = compute_agility_score({
        "totalFindings": 2,
        "overdue": 0,
        "transitional": 0,
        "lowRisk": 999,  # nonsensical, exceeds total
        "currentWeakCrypto": 0,
        "hndlExposed": 0,
    })
    assert 0.0 <= result.score <= 100.0


def test_score_never_drops_below_zero() -> None:
    """Symmetric bound: weak+HNDL shares clamp to 1.0 apiece."""
    result = compute_agility_score({
        "totalFindings": 1,
        "overdue": 1,
        "transitional": 0,
        "lowRisk": 0,
        "currentWeakCrypto": 999,
        "hndlExposed": 999,
    })
    assert result.score >= 0.0


def test_missing_summary_keys_default_to_zero() -> None:
    """A degraded scan summary that omits some keys must not crash."""
    result = compute_agility_score({"totalFindings": 0})
    assert result.grade == AgilityGrade.A


def test_non_numeric_summary_values_default_to_zero() -> None:
    result = compute_agility_score({
        "totalFindings": "not-a-number",  # type: ignore[arg-type]
        "overdue": None,
    })
    assert result.grade == AgilityGrade.A


def test_to_dict_carries_every_component() -> None:
    result = compute_agility_score({
        "totalFindings": 2,
        "overdue": 1,
        "transitional": 0,
        "lowRisk": 1,
        "currentWeakCrypto": 0,
        "hndlExposed": 0,
    })
    d = result.to_dict()
    assert d["schemaVersion"] == AGILITY_SCHEMA_VERSION
    assert 0.0 <= d["score"] <= 100.0
    assert d["grade"] in {g.value for g in AgilityGrade}
    for band in ("tierPosture", "weaknessImmunity", "hndlImmunity"):
        assert band in d["breakdown"]
        assert "earned" in d["breakdown"][band]
        assert "max" in d["breakdown"][band]
    assert d["inputs"]["totalFindings"] == 2
    assert isinstance(d["rationale"], list)


# ---------------------------------------------------------------------------
# Grade thresholds
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "score,expected",
    [
        (100.0, AgilityGrade.A),
        (85.0, AgilityGrade.A),
        (84.9, AgilityGrade.B),
        (70.0, AgilityGrade.B),
        (69.9, AgilityGrade.C),
        (55.0, AgilityGrade.C),
        (54.9, AgilityGrade.D),
        (40.0, AgilityGrade.D),
        (39.9, AgilityGrade.F),
        (0.0, AgilityGrade.F),
    ],
)
def test_grade_thresholds(score: float, expected: AgilityGrade) -> None:
    assert grade_for_score(score) == expected
