"""Tests for :mod:`app.benchmark.dataset` -- manifest loader.

Locks down:

* Valid manifest -> :class:`BenchmarkDataset` with the right shape.
* Duplicate ids, missing keys, unknown keys, bad types -> BenchmarkError.
* Bundled dataset loads without touching the network / firebase.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.benchmark.dataset import (
    BENCHMARK_SCHEMA_VERSION,
    BenchmarkError,
    load_bundled_dataset,
    load_manifest,
)


def _write_manifest(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _minimal_valid_payload() -> dict:
    return {
        "schemaVersion": BENCHMARK_SCHEMA_VERSION,
        "name": "unit",
        "description": "unit-test manifest",
        "cases": [
            {
                "id": "c1",
                "file": "a.py",
                "category": "weak-crypto/rsa",
                "language": "python",
                "expected": [{"algorithm": "RSA", "parameter": "1024"}],
            },
            {
                "id": "c2",
                "file": "b.py",
                "category": "negative",
                "language": "python",
                "expected": [],
            },
        ],
    }


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------

def test_valid_manifest_loads(tmp_path: Path) -> None:
    path = _write_manifest(tmp_path, _minimal_valid_payload())
    ds = load_manifest(path)
    assert ds.name == "unit"
    assert len(ds.cases) == 2
    c1, c2 = ds.cases
    assert c1.case_id == "c1"
    assert c1.expected[0].algorithm == "RSA"
    assert c1.expected[0].parameter == "1024"
    assert c2.is_true_negative is True


def test_missing_expected_defaults_to_empty_list(tmp_path: Path) -> None:
    payload = _minimal_valid_payload()
    del payload["cases"][1]["expected"]
    path = _write_manifest(tmp_path, payload)
    ds = load_manifest(path)
    assert ds.cases[1].expected == []


def test_dataset_root_is_the_manifest_directory(tmp_path: Path) -> None:
    path = _write_manifest(tmp_path, _minimal_valid_payload())
    ds = load_manifest(path)
    assert ds.root == tmp_path


def test_missing_files_report_lists_unresolved_cases(tmp_path: Path) -> None:
    """The manifest can be valid while cases point at missing files. The
    harness needs to detect that before scoring."""
    path = _write_manifest(tmp_path, _minimal_valid_payload())
    ds = load_manifest(path)
    missing = ds.missing_files()
    # Neither a.py nor b.py exists on disk.
    assert {c.case_id for c in missing} == {"c1", "c2"}


def test_case_by_id_returns_lookup_dict(tmp_path: Path) -> None:
    path = _write_manifest(tmp_path, _minimal_valid_payload())
    ds = load_manifest(path)
    idx = ds.by_id()
    assert set(idx) == {"c1", "c2"}


# ---------------------------------------------------------------------------
# Validation failures
# ---------------------------------------------------------------------------

def test_load_raises_when_file_missing(tmp_path: Path) -> None:
    with pytest.raises(BenchmarkError, match="not found"):
        load_manifest(tmp_path / "does-not-exist.json")


def test_load_raises_when_manifest_is_not_json(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(BenchmarkError, match="valid JSON"):
        load_manifest(path)


def test_load_raises_when_schema_version_is_unknown(tmp_path: Path) -> None:
    payload = _minimal_valid_payload()
    payload["schemaVersion"] = "blindspot.benchmark.v99"
    path = _write_manifest(tmp_path, payload)
    with pytest.raises(BenchmarkError, match="schemaVersion"):
        load_manifest(path)


def test_load_raises_on_empty_cases(tmp_path: Path) -> None:
    payload = _minimal_valid_payload()
    payload["cases"] = []
    path = _write_manifest(tmp_path, payload)
    with pytest.raises(BenchmarkError, match="cases"):
        load_manifest(path)


def test_load_raises_on_duplicate_case_ids(tmp_path: Path) -> None:
    payload = _minimal_valid_payload()
    payload["cases"][1]["id"] = payload["cases"][0]["id"]
    path = _write_manifest(tmp_path, payload)
    with pytest.raises(BenchmarkError, match="duplicate"):
        load_manifest(path)


def test_load_raises_when_case_id_is_missing(tmp_path: Path) -> None:
    payload = _minimal_valid_payload()
    del payload["cases"][0]["id"]
    path = _write_manifest(tmp_path, payload)
    with pytest.raises(BenchmarkError, match="id"):
        load_manifest(path)


def test_load_raises_when_file_is_missing(tmp_path: Path) -> None:
    payload = _minimal_valid_payload()
    del payload["cases"][0]["file"]
    path = _write_manifest(tmp_path, payload)
    with pytest.raises(BenchmarkError, match="file"):
        load_manifest(path)


def test_load_raises_when_expected_algorithm_is_missing(tmp_path: Path) -> None:
    payload = _minimal_valid_payload()
    payload["cases"][0]["expected"] = [{"parameter": "1024"}]
    path = _write_manifest(tmp_path, payload)
    with pytest.raises(BenchmarkError, match="algorithm"):
        load_manifest(path)


def test_load_rejects_unknown_case_keys(tmp_path: Path) -> None:
    """Unknown keys catch typos before they silently misbehave in prod."""
    payload = _minimal_valid_payload()
    payload["cases"][0]["Category"] = "typo"  # capital C
    path = _write_manifest(tmp_path, payload)
    with pytest.raises(BenchmarkError, match="unknown keys"):
        load_manifest(path)


# ---------------------------------------------------------------------------
# Bundled dataset -- must be loadable and complete.
# ---------------------------------------------------------------------------

def test_bundled_dataset_loads_and_all_case_files_exist() -> None:
    """The shipped manifest must reference only files that exist on
    disk. A missing case file is a build-time bug, not a runtime one."""
    ds = load_bundled_dataset()
    assert ds.name == "blindspot-builtin"
    assert len(ds.cases) > 0
    assert ds.missing_files() == []


def test_bundled_dataset_case_ids_are_unique() -> None:
    ds = load_bundled_dataset()
    ids = [c.case_id for c in ds.cases]
    assert len(ids) == len(set(ids))


def test_bundled_dataset_has_both_positive_and_negative_cases() -> None:
    """Meaningful precision + accuracy requires both sides represented."""
    ds = load_bundled_dataset()
    positives = [c for c in ds.cases if not c.is_true_negative]
    negatives = [c for c in ds.cases if c.is_true_negative]
    assert len(positives) >= 1
    assert len(negatives) >= 1
