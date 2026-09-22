"""Pure precision / recall / F1 math for the benchmark harness.

Everything here is a function of counts. No filesystem, no pipeline,
no serialisation. That keeps the unit tests fast (< 100 ms per file)
and forces the harness to feed real, provenanced numbers -- the only
way to trust the score is to trust the pipeline output it came from.

Definitions (per case + aggregated):

* **TP** -- an expected finding matched by at least one reported finding.
* **FN** -- an expected finding with no matching reported finding.
* **FP** -- a reported finding on a case that no expected slot matched.
* **TN** -- a case with zero expected findings and zero reported findings.

Precision, recall, F1 follow the standard definitions. When a
denominator is zero we return 0.0 rather than raising: an evaluator
that reports "no findings expected AND none produced" should not
crash on ``ZeroDivisionError``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from app.benchmark.dataset import BenchmarkCase, ExpectedFinding


@dataclass(frozen=True)
class ConfusionMatrix:
    """One (tp, fp, fn, tn) tuple plus derived metrics."""

    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        """(TP + TN) / total. Only meaningful when TN is populated."""
        total = self.tp + self.fp + self.fn + self.tn
        return (self.tp + self.tn) / total if total > 0 else 0.0

    def add(self, other: ConfusionMatrix) -> ConfusionMatrix:
        return ConfusionMatrix(
            tp=self.tp + other.tp,
            fp=self.fp + other.fp,
            fn=self.fn + other.fn,
            tn=self.tn + other.tn,
        )

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready shape. Floats are unrounded on purpose -- rounding
        is a rendering concern, not a data concern."""
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "accuracy": self.accuracy,
        }


# ---------------------------------------------------------------------------
# Per-case scoring
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CaseConfusion:
    """Per-case scoring result. ``matched`` / ``missed`` / ``extra`` name
    the individual findings that produced the counts, so the report
    surface can point at the exact case where the pipeline diverged.

    * ``matched`` -- pairs of ``(ExpectedFinding, reported_finding_dict)``.
    * ``missed``  -- expected findings the pipeline did not report.
    * ``extra``   -- reported findings that no expected slot matched.
    """

    tp: int
    fp: int
    fn: int
    tn: int
    matched: list[tuple[ExpectedFinding, dict[str, Any]]] = field(default_factory=list)
    missed: list[ExpectedFinding] = field(default_factory=list)
    extra: list[dict[str, Any]] = field(default_factory=list)

    def as_matrix(self) -> ConfusionMatrix:
        return ConfusionMatrix(tp=self.tp, fp=self.fp, fn=self.fn, tn=self.tn)


def compute_case_confusion(
    case: BenchmarkCase,
    reported: Iterable[dict[str, Any]],
) -> CaseConfusion:
    """Score one case: match its expectations to *reported* findings.

    Matching is greedy but deterministic:

    1. For each expected slot (in manifest order), we walk the
       still-unmatched reported findings (in the order they came from
       the pipeline) and pair off the first one that satisfies
       :meth:`ExpectedFinding.matches`.
    2. Anything unmatched on either side becomes ``missed`` (FN) or
       ``extra`` (FP).
    3. A case with no expectations and no reports counts as one TN,
       so the aggregate accuracy is meaningful.

    Multiple identical findings on the same file are NOT collapsed --
    if a case says "expect 2 RSA-2048" and the pipeline reports 3,
    that's 2 TP + 1 FP, not 1 TP + 1 FP.
    """
    reported_list = list(reported)
    unmatched: list[dict[str, Any]] = list(reported_list)

    matched: list[tuple[ExpectedFinding, dict[str, Any]]] = []
    missed: list[ExpectedFinding] = []

    for expected in case.expected:
        pair = None
        for idx, rf in enumerate(unmatched):
            if expected.matches(rf):
                pair = (idx, rf)
                break
        if pair is None:
            missed.append(expected)
        else:
            idx, rf = pair
            matched.append((expected, rf))
            unmatched.pop(idx)

    extra = unmatched
    tp = len(matched)
    fn = len(missed)
    fp = len(extra)

    if case.is_true_negative and fp == 0:
        tn = 1
    else:
        tn = 0

    return CaseConfusion(
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        matched=matched,
        missed=missed,
        extra=extra,
    )


# ---------------------------------------------------------------------------
# Dataset-wide aggregation
# ---------------------------------------------------------------------------

def compute_dataset_metrics(
    per_case: Iterable[tuple[BenchmarkCase, CaseConfusion]],
) -> dict[str, Any]:
    """Aggregate per-case confusion into overall + per-category matrices.

    Returns a dict shaped like::

        {
          "overall": {tp, fp, fn, tn, precision, recall, f1, accuracy},
          "categories": {
            "weak-crypto/rsa": {tp, fp, fn, tn, precision, ..., cases: 3},
            ...
          }
        }

    Nothing here is rounded -- the frontend renders to two decimal
    places, but the underlying JSON stays full-precision so consumers
    can re-round to their taste.
    """
    overall = ConfusionMatrix()
    by_category: dict[str, ConfusionMatrix] = {}
    case_counts: dict[str, int] = {}

    for case, cc in per_case:
        m = cc.as_matrix()
        overall = overall.add(m)
        prev = by_category.get(case.category, ConfusionMatrix())
        by_category[case.category] = prev.add(m)
        case_counts[case.category] = case_counts.get(case.category, 0) + 1

    return {
        "overall": overall.to_dict(),
        "categories": {
            category: {**mat.to_dict(), "cases": case_counts[category]}
            for category, mat in sorted(by_category.items())
        },
    }


__all__ = [
    "CaseConfusion",
    "ConfusionMatrix",
    "compute_case_confusion",
    "compute_dataset_metrics",
]
