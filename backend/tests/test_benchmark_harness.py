"""Tests for :mod:`app.benchmark.harness` with a fake scanner.

Bypasses semgrep/pipeline invocation via ``scan_fn`` injection so the
matching + reporting logic is exercised in milliseconds. The bundled
dataset is used as the input fixture because it's the shape the
harness will see in production.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from app.benchmark import BenchmarkReport, load_bundled_dataset, run_benchmark
from app.benchmark.dataset import BenchmarkDataset, BenchmarkError, load_manifest


def _finding(
    file_path: str,
    algorithm: str,
    parameter: str | None = None,
    curve: str | None = None,
) -> dict[str, Any]:
    """One finding with the fields the harness actually inspects."""
    return {
        "id": f"F-{algorithm}-{file_path}",
        "algorithm": algorithm,
        "parameter": parameter,
        "curve": curve,
        "filePath": file_path,
        "lineNumber": 10,
        "riskTier": "overdue",
        "displayName": f"{algorithm}{'-' + parameter if parameter else ''}",
    }


def _make_scan_fn(findings: list[dict[str, Any]]):
    """Adapter -- returns a callable matching the ScanFn signature."""

    def _scanner(target: Path, settings) -> list[dict[str, Any]]:
        return findings

    return _scanner


def test_perfect_run_yields_100_percent_precision_and_recall() -> None:
    dataset = load_bundled_dataset()

    # Fabricate exactly the findings the manifest expects, per case.
    fakes: list[dict[str, Any]] = []
    for case in dataset.cases:
        for ex in case.expected:
            fakes.append(
                _finding(
                    file_path=case.file,
                    algorithm=ex.algorithm,
                    parameter=ex.parameter,
                    curve=ex.curve,
                )
            )

    report = run_benchmark(dataset, scan_fn=_make_scan_fn(fakes))
    o = report.overall
    assert o["tp"] > 0
    assert o["fp"] == 0
    assert o["fn"] == 0
    assert o["precision"] == 1.0
    assert o["recall"] == 1.0
    assert o["f1"] == 1.0


def test_empty_scan_marks_every_expectation_as_fn() -> None:
    dataset = load_bundled_dataset()
    report = run_benchmark(dataset, scan_fn=_make_scan_fn([]))
    o = report.overall
    # Every positive case contributes to FN; every negative case is a TN.
    positives = sum(len(c.expected) for c in dataset.cases)
    negatives = sum(1 for c in dataset.cases if c.is_true_negative)
    assert o["fn"] == positives
    assert o["tn"] == negatives
    assert o["tp"] == 0
    assert o["recall"] == 0.0


def test_extra_finding_on_negative_case_is_a_fp() -> None:
    dataset = load_bundled_dataset()
    negative = next(c for c in dataset.cases if c.is_true_negative)
    fakes = [_finding(file_path=negative.file, algorithm="RSA", parameter="1024")]
    report = run_benchmark(dataset, scan_fn=_make_scan_fn(fakes))
    o = report.overall
    assert o["fp"] >= 1
    # And the case's row surfaces the extra finding.
    row = next(r for r in report.cases if r.case_id == negative.case_id)
    assert row.fp == 1
    assert row.extra[0]["algorithm"] == "RSA"


def test_case_rows_carry_matched_and_missed_details() -> None:
    dataset = load_bundled_dataset()
    positive = next(c for c in dataset.cases if not c.is_true_negative)
    # Deliberately mis-parameter one expectation so it becomes missed.
    fakes = [
        _finding(
            file_path=positive.file,
            algorithm=positive.expected[0].algorithm,
            parameter="9999",
            curve=positive.expected[0].curve,
        )
    ]
    report = run_benchmark(dataset, scan_fn=_make_scan_fn(fakes))
    row = next(r for r in report.cases if r.case_id == positive.case_id)
    # The mis-parameter finding is one FP + the expectation is one FN
    # (unless the expectation had no parameter set to begin with).
    if positive.expected[0].parameter is not None:
        assert row.fp == 1
        assert row.fn == 1
    else:
        # Parameter-less expectations still match on algorithm alone.
        assert row.tp == 1


def test_windows_style_filepaths_still_match() -> None:
    """The pipeline on Windows emits backslash-separated paths. The
    bucketer must normalise both sides before matching."""
    dataset = load_bundled_dataset()
    positive = next(c for c in dataset.cases if not c.is_true_negative)
    windows_path = positive.file.replace("/", "\\")
    fakes = [
        _finding(
            file_path=windows_path,
            algorithm=positive.expected[0].algorithm,
            parameter=positive.expected[0].parameter,
            curve=positive.expected[0].curve,
        )
    ]
    report = run_benchmark(dataset, scan_fn=_make_scan_fn(fakes))
    row = next(r for r in report.cases if r.case_id == positive.case_id)
    assert row.tp >= 1


def test_report_envelope_carries_provenance() -> None:
    dataset = load_bundled_dataset()
    fixed = datetime(2026, 9, 7, tzinfo=timezone.utc)
    report = run_benchmark(
        dataset,
        scan_fn=_make_scan_fn([]),
        now=lambda: fixed,
    )
    d = report.to_dict()
    assert d["schemaVersion"] == "blindspot.benchmark.report.v1"
    assert d["datasetName"] == "blindspot-builtin"
    assert d["generatedAt"] == fixed.isoformat()
    assert d["totalCases"] == len(dataset.cases)
    # Elapsed is >= 0 and finite even under a synchronous fake scanner.
    assert d["elapsedSeconds"] >= 0.0
    assert "overall" in d and "categories" in d and "cases" in d


def test_missing_case_files_are_rejected(tmp_path: Path) -> None:
    """A manifest that references non-existent files must NOT be silently
    scored as all-TN. That would inflate accuracy dishonestly."""
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        '{"schemaVersion":"blindspot.benchmark.v1","name":"unit",'
        '"cases":[{"id":"c1","file":"ghost.py","category":"x","language":"python","expected":[]}]}',
        encoding="utf-8",
    )
    dataset = load_manifest(manifest_path)

    with pytest.raises(BenchmarkError, match="missing"):
        run_benchmark(dataset, scan_fn=_make_scan_fn([]))
