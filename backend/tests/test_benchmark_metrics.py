"""Tests for :mod:`app.benchmark.metrics`.

Pure math. No filesystem, no pipeline. Every assertion locks down one
row of the precision / recall / F1 truth table so a refactor that
silently changes the aggregation gets caught immediately.
"""

from __future__ import annotations

import math

import pytest

from app.benchmark.dataset import BenchmarkCase, ExpectedFinding
from app.benchmark.metrics import (
    ConfusionMatrix,
    compute_case_confusion,
    compute_dataset_metrics,
)


# ---------------------------------------------------------------------------
# ConfusionMatrix
# ---------------------------------------------------------------------------

def test_precision_recall_f1_on_a_perfect_matrix() -> None:
    m = ConfusionMatrix(tp=10, fp=0, fn=0, tn=0)
    assert m.precision == 1.0
    assert m.recall == 1.0
    assert m.f1 == 1.0


def test_precision_recall_f1_on_balanced_errors() -> None:
    m = ConfusionMatrix(tp=8, fp=2, fn=2, tn=0)
    assert m.precision == pytest.approx(8 / 10)
    assert m.recall == pytest.approx(8 / 10)
    assert m.f1 == pytest.approx(0.8)


def test_precision_and_recall_diverge_when_errors_are_asymmetric() -> None:
    m = ConfusionMatrix(tp=5, fp=5, fn=0, tn=0)
    assert m.precision == 0.5
    assert m.recall == 1.0
    assert m.f1 == pytest.approx(2 * 0.5 * 1.0 / (0.5 + 1.0))


def test_zero_denominator_never_raises_zero_division() -> None:
    m = ConfusionMatrix()
    assert m.precision == 0.0
    assert m.recall == 0.0
    assert m.f1 == 0.0
    assert m.accuracy == 0.0


def test_matrix_add_is_associative_over_counts() -> None:
    a = ConfusionMatrix(tp=1, fp=2, fn=3, tn=4)
    b = ConfusionMatrix(tp=10, fp=20, fn=30, tn=40)
    s = a.add(b)
    assert (s.tp, s.fp, s.fn, s.tn) == (11, 22, 33, 44)


def test_matrix_to_dict_serialises_every_derived_metric() -> None:
    d = ConfusionMatrix(tp=1, fp=1, fn=1, tn=1).to_dict()
    for key in ("tp", "fp", "fn", "tn", "precision", "recall", "f1", "accuracy"):
        assert key in d


# ---------------------------------------------------------------------------
# compute_case_confusion
# ---------------------------------------------------------------------------

def _case(*, is_negative: bool = False) -> BenchmarkCase:
    if is_negative:
        return BenchmarkCase(
            case_id="n1",
            file="n.py",
            category="negative",
            language="python",
            expected=[],
        )
    return BenchmarkCase(
        case_id="p1",
        file="p.py",
        category="weak-crypto/rsa",
        language="python",
        expected=[ExpectedFinding(algorithm="RSA", parameter="1024")],
    )


def _finding(algorithm: str, parameter: str | None = None, curve: str | None = None) -> dict:
    return {
        "id": f"F-{algorithm}",
        "algorithm": algorithm,
        "parameter": parameter,
        "curve": curve,
    }


def test_perfect_hit_scores_one_tp() -> None:
    cc = compute_case_confusion(_case(), [_finding("RSA", "1024")])
    assert (cc.tp, cc.fp, cc.fn, cc.tn) == (1, 0, 0, 0)


def test_missed_expected_scores_one_fn() -> None:
    cc = compute_case_confusion(_case(), [])
    assert (cc.tp, cc.fp, cc.fn, cc.tn) == (0, 0, 1, 0)
    assert cc.missed[0].algorithm == "RSA"


def test_unexpected_finding_scores_one_fp() -> None:
    cc = compute_case_confusion(_case(is_negative=True), [_finding("MD5")])
    assert (cc.tp, cc.fp, cc.fn, cc.tn) == (0, 1, 0, 0)
    assert cc.extra[0]["algorithm"] == "MD5"


def test_true_negative_case_scores_one_tn() -> None:
    cc = compute_case_confusion(_case(is_negative=True), [])
    assert (cc.tp, cc.fp, cc.fn, cc.tn) == (0, 0, 0, 1)


def test_wrong_parameter_scores_fn_and_fp_not_tp() -> None:
    """Match must fail when parameter differs. Both sides of the ledger
    move: expected slot is unfilled (FN) and the reported finding is
    unmatched (FP). This is the "close but not equal" ledger."""
    cc = compute_case_confusion(_case(), [_finding("RSA", "2048")])
    assert cc.tp == 0
    assert cc.fp == 1
    assert cc.fn == 1


def test_two_expected_two_matching_findings_yields_two_tp() -> None:
    case = BenchmarkCase(
        case_id="p2",
        file="p.py",
        category="weak-crypto/rsa",
        language="python",
        expected=[
            ExpectedFinding(algorithm="RSA", parameter="1024"),
            ExpectedFinding(algorithm="RSA", parameter="1024"),
        ],
    )
    cc = compute_case_confusion(
        case,
        [_finding("RSA", "1024"), _finding("RSA", "1024")],
    )
    assert (cc.tp, cc.fp, cc.fn) == (2, 0, 0)


def test_greedy_pairing_leaves_the_correct_leftover() -> None:
    """If two identical expectations are filled by three identical
    findings, the leftover is one FP (not one FN, not two of each)."""
    case = BenchmarkCase(
        case_id="p3",
        file="p.py",
        category="weak-crypto/rsa",
        language="python",
        expected=[
            ExpectedFinding(algorithm="RSA", parameter="1024"),
            ExpectedFinding(algorithm="RSA", parameter="1024"),
        ],
    )
    cc = compute_case_confusion(
        case,
        [_finding("RSA", "1024"), _finding("RSA", "1024"), _finding("RSA", "1024")],
    )
    assert (cc.tp, cc.fp, cc.fn) == (2, 1, 0)


def test_algorithm_match_is_case_insensitive() -> None:
    case = BenchmarkCase(
        case_id="p4",
        file="p.py",
        category="weak-crypto/hash",
        language="python",
        expected=[ExpectedFinding(algorithm="MD5")],
    )
    cc = compute_case_confusion(case, [_finding("md5")])
    assert cc.tp == 1


def test_curve_is_matched_when_specified() -> None:
    case = BenchmarkCase(
        case_id="p5",
        file="p.py",
        category="quantum-overdue/ec",
        language="python",
        expected=[ExpectedFinding(algorithm="ECC", curve="secp256r1")],
    )
    hit = compute_case_confusion(case, [_finding("ECC", curve="secp256r1")])
    assert hit.tp == 1

    miss = compute_case_confusion(case, [_finding("ECC", curve="secp384r1")])
    assert miss.tp == 0
    assert miss.fp == 1
    assert miss.fn == 1


# ---------------------------------------------------------------------------
# compute_dataset_metrics
# ---------------------------------------------------------------------------

def test_dataset_metrics_aggregates_overall_and_by_category() -> None:
    """One perfect case, one FN, one FP -- the overall row and the
    per-category rows must add up consistently."""
    weak_case = _case()  # weak-crypto/rsa
    hit_cc = compute_case_confusion(weak_case, [_finding("RSA", "1024")])

    weak_case_missed = _case()  # same category, but missed
    miss_cc = compute_case_confusion(weak_case_missed, [])

    negative_case = _case(is_negative=True)  # category=negative, but FP
    fp_cc = compute_case_confusion(negative_case, [_finding("MD5")])

    metrics = compute_dataset_metrics(
        [
            (weak_case, hit_cc),
            (weak_case_missed, miss_cc),
            (negative_case, fp_cc),
        ]
    )

    # Overall = 1 TP, 1 FP, 1 FN, 0 TN.
    o = metrics["overall"]
    assert (o["tp"], o["fp"], o["fn"], o["tn"]) == (1, 1, 1, 0)
    assert o["precision"] == 0.5
    assert o["recall"] == 0.5
    assert o["f1"] == pytest.approx(0.5)

    # Per-category slices sum back to overall.
    cats = metrics["categories"]
    weak = cats["weak-crypto/rsa"]
    neg = cats["negative"]
    assert (weak["tp"], weak["fp"], weak["fn"]) == (1, 0, 1)
    assert weak["cases"] == 2
    assert (neg["tp"], neg["fp"], neg["fn"]) == (0, 1, 0)
    assert neg["cases"] == 1


def test_dataset_metrics_is_stable_when_categories_are_empty() -> None:
    metrics = compute_dataset_metrics([])
    assert metrics["overall"]["tp"] == 0
    assert metrics["categories"] == {}
    # No ZeroDivisionError on the derived floats.
    assert math.isfinite(metrics["overall"]["f1"])
