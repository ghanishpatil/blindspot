"""Benchmark orchestration -- glue between the dataset, the pipeline,
and the metrics.

``run_benchmark`` takes a :class:`BenchmarkDataset`, scans its ``root``
directory through :func:`app.pipeline.run_pipeline`, buckets findings
by file, scores each case, and produces a :class:`BenchmarkReport`
that the API layer serialises to JSON.

We scan the dataset directory **once**, not once per case. Every
finding carries its relative ``file_path`` back to the harness, and
:func:`compute_case_confusion` matches expectations to per-file
buckets. This keeps a full benchmark run bounded by one semgrep +
one dependency walk over the (small) case corpus, not N of each.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from app import __version__ as _APP_VERSION
from app.benchmark.dataset import BenchmarkCase, BenchmarkDataset, BenchmarkError
from app.benchmark.metrics import (
    CaseConfusion,
    ConfusionMatrix,
    compute_case_confusion,
    compute_dataset_metrics,
)
from app.config import Settings, get_settings
from app.pipeline import run_pipeline

logger = logging.getLogger(__name__)


BENCHMARK_REPORT_SCHEMA_VERSION = "blindspot.benchmark.report.v1"


# Type of a function the harness uses to turn a target Path into a
# list of finding dicts. Real callers use :func:`_default_scanner`
# which calls the pipeline; tests inject their own so scoring can be
# exercised without semgrep on PATH.
ScanFn = Callable[[Path, Settings], list[dict[str, Any]]]


def _default_scanner(target: Path, settings: Settings) -> list[dict[str, Any]]:
    """Real pipeline runner. Returns findings as ``firestore document``
    dicts -- the same shape the rest of the product consumes."""
    _scan, findings, _cbom = run_pipeline(
        target,
        project_id="benchmark",
        settings=settings,
    )
    return [f.to_firestore_document() for f in findings]


# ---------------------------------------------------------------------------
# Report structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CaseResult:
    """Full per-case row on the report. Reads as a single narrative:
    what the case expected, what the pipeline saw, and how it scored.
    """

    case_id: str
    file: str
    category: str
    language: str
    expected_count: int
    reported_count: int
    tp: int
    fp: int
    fn: int
    tn: int
    matched: list[dict[str, Any]] = field(default_factory=list)
    missed: list[dict[str, Any]] = field(default_factory=list)
    extra: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "caseId": self.case_id,
            "file": self.file,
            "category": self.category,
            "language": self.language,
            "expectedCount": self.expected_count,
            "reportedCount": self.reported_count,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "matched": self.matched,
            "missed": self.missed,
            "extra": self.extra,
        }


@dataclass(frozen=True)
class BenchmarkReport:
    """Top-level benchmark output. Serialised as JSON by the API."""

    schema_version: str
    dataset_name: str
    dataset_description: str
    generated_at: str
    pipeline_version: str
    elapsed_seconds: float
    total_cases: int
    total_expected: int
    total_reported: int
    overall: dict[str, Any]
    categories: dict[str, Any]
    cases: list[CaseResult]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "datasetName": self.dataset_name,
            "datasetDescription": self.dataset_description,
            "generatedAt": self.generated_at,
            "pipelineVersion": self.pipeline_version,
            "elapsedSeconds": self.elapsed_seconds,
            "totalCases": self.total_cases,
            "totalExpected": self.total_expected,
            "totalReported": self.total_reported,
            "overall": self.overall,
            "categories": self.categories,
            "cases": [c.to_dict() for c in self.cases],
        }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def _bucket_findings_by_file(
    findings: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Group findings by their ``filePath`` (the field the pipeline emits).

    The pipeline sets ``filePath`` relative to the scan root, so a case
    listed as ``"file": "weak_rsa_1024.py"`` in the manifest matches
    findings whose ``filePath`` is the same string. We also fall back
    to ``evidenceDetail.filePath`` in case a finding comes through the
    dependency path where the top-level field can be null.
    """
    buckets: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        path = f.get("filePath")
        if not path:
            detail = f.get("evidenceDetail") or {}
            path = detail.get("filePath")
        if not path:
            continue
        # Normalise Windows-style separators so a case listing
        # "sub/file.py" matches a finding at "sub\\file.py".
        norm = str(path).replace("\\", "/")
        buckets.setdefault(norm, []).append(f)
    return buckets


def run_benchmark(
    dataset: BenchmarkDataset,
    *,
    settings: Settings | None = None,
    scan_fn: ScanFn | None = None,
    now: Callable[[], datetime] | None = None,
) -> BenchmarkReport:
    """Run *dataset* through the pipeline and build a report.

    ``scan_fn`` is injected in tests to skip semgrep -- the metrics /
    dataset / matching logic is exercised without any real scanner
    dependency. Real callers omit it and get :func:`_default_scanner`.

    Raises :class:`BenchmarkError` when any case file is missing --
    silently scoring a missing file as TN would be dishonest.
    """
    settings = settings or get_settings()
    scan_fn = scan_fn or _default_scanner
    clock = now or (lambda: datetime.now(timezone.utc))

    missing = dataset.missing_files()
    if missing:
        raise BenchmarkError(
            "benchmark dataset is incomplete; the following case files "
            f"are missing on disk: {[c.file for c in missing]}"
        )

    logger.info(
        "Benchmark started: dataset=%s cases=%d root=%s",
        dataset.name,
        len(dataset.cases),
        dataset.root,
    )
    t0 = time.monotonic()

    findings = scan_fn(dataset.root, settings)
    buckets = _bucket_findings_by_file(findings)

    per_case_scored: list[tuple[BenchmarkCase, CaseConfusion]] = []
    case_results: list[CaseResult] = []

    total_expected = 0
    total_reported = 0

    for case in dataset.cases:
        norm = case.file.replace("\\", "/")
        reported = buckets.get(norm, [])
        cc = compute_case_confusion(case, reported)
        per_case_scored.append((case, cc))

        total_expected += len(case.expected)
        total_reported += len(reported)

        case_results.append(
            CaseResult(
                case_id=case.case_id,
                file=case.file,
                category=case.category,
                language=case.language,
                expected_count=len(case.expected),
                reported_count=len(reported),
                tp=cc.tp,
                fp=cc.fp,
                fn=cc.fn,
                tn=cc.tn,
                matched=[
                    {
                        "expected": {
                            "algorithm": ex.algorithm,
                            "parameter": ex.parameter,
                            "curve": ex.curve,
                        },
                        "finding": _compact_finding(rf),
                    }
                    for ex, rf in cc.matched
                ],
                missed=[
                    {
                        "algorithm": ex.algorithm,
                        "parameter": ex.parameter,
                        "curve": ex.curve,
                        "notes": ex.notes,
                    }
                    for ex in cc.missed
                ],
                extra=[_compact_finding(rf) for rf in cc.extra],
            )
        )

    metrics = compute_dataset_metrics(per_case_scored)

    elapsed = time.monotonic() - t0
    logger.info(
        "Benchmark complete: tp=%d fp=%d fn=%d tn=%d f1=%.3f elapsed=%.2fs",
        metrics["overall"]["tp"],
        metrics["overall"]["fp"],
        metrics["overall"]["fn"],
        metrics["overall"]["tn"],
        metrics["overall"]["f1"],
        elapsed,
    )

    return BenchmarkReport(
        schema_version=BENCHMARK_REPORT_SCHEMA_VERSION,
        dataset_name=dataset.name,
        dataset_description=dataset.description,
        generated_at=clock().isoformat(),
        pipeline_version=_APP_VERSION,
        elapsed_seconds=elapsed,
        total_cases=len(dataset.cases),
        total_expected=total_expected,
        total_reported=total_reported,
        overall=metrics["overall"],
        categories=metrics["categories"],
        cases=case_results,
    )


def _compact_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Small projection of a finding for the report surface.

    We keep enough for a UI to render a "why did this fire?" tooltip
    without dumping the full firestore document into every case row.
    """
    return {
        "id": finding.get("id"),
        "algorithm": finding.get("algorithm"),
        "displayName": finding.get("displayName"),
        "parameter": finding.get("parameter"),
        "curve": finding.get("curve"),
        "filePath": finding.get("filePath"),
        "lineNumber": finding.get("lineNumber"),
        "riskTier": finding.get("riskTier"),
    }


__all__ = [
    "BENCHMARK_REPORT_SCHEMA_VERSION",
    "BenchmarkReport",
    "CaseResult",
    "ScanFn",
    "run_benchmark",
]
