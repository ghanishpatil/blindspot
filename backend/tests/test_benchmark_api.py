"""Tests for :mod:`app.api.benchmark`.

We stub the heavy ``run_benchmark`` inside the endpoint so the API
contract (routes, verbs, status codes, cache round-trip) can be
exercised without invoking the full pipeline.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.benchmark import BenchmarkReport
from app.config import get_settings


def _canned_report() -> BenchmarkReport:
    return BenchmarkReport(
        schema_version="blindspot.benchmark.report.v1",
        dataset_name="blindspot-builtin",
        dataset_description="fake",
        generated_at="2026-09-07T00:00:00+00:00",
        pipeline_version="0.1.0",
        elapsed_seconds=0.01,
        total_cases=2,
        total_expected=1,
        total_reported=1,
        overall={
            "tp": 1, "fp": 0, "fn": 0, "tn": 1,
            "precision": 1.0, "recall": 1.0, "f1": 1.0, "accuracy": 1.0,
        },
        categories={
            "weak-crypto/rsa": {
                "tp": 1, "fp": 0, "fn": 0, "tn": 0,
                "precision": 1.0, "recall": 1.0, "f1": 1.0, "accuracy": 1.0,
                "cases": 1,
            },
        },
        cases=[],
    )


def _patch_endpoint(monkeypatch: pytest.MonkeyPatch, report: BenchmarkReport) -> None:
    """Swap out the harness call inside the endpoint so tests don't
    invoke semgrep. We patch at the *module the endpoint imports from*,
    not the source module, to intercept the actual name lookup."""
    import app.api.benchmark as ep

    monkeypatch.setattr(ep, "run_benchmark", lambda dataset, settings=None: report)
    # load_bundled_dataset still runs -- keeps the "manifest is valid"
    # part of the contract honest.


# ---------------------------------------------------------------------------
# POST /api/benchmark/run
# ---------------------------------------------------------------------------

def test_post_run_returns_the_report_dict(
    auth_bypassed_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_endpoint(monkeypatch, _canned_report())
    resp = auth_bypassed_client.post("/api/benchmark/run")
    assert resp.status_code == 200
    body = resp.json()
    assert body["datasetName"] == "blindspot-builtin"
    assert body["overall"]["f1"] == 1.0


def test_post_run_persists_the_report_to_artifacts_dir(
    auth_bypassed_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_endpoint(monkeypatch, _canned_report())
    resp = auth_bypassed_client.post("/api/benchmark/run")
    assert resp.status_code == 200

    get_settings.cache_clear()
    latest = get_settings().artifacts / "benchmark-latest.json"
    assert latest.is_file()
    saved = json.loads(latest.read_text(encoding="utf-8"))
    assert saved["overall"]["f1"] == 1.0


def test_get_latest_returns_the_last_cached_report(
    auth_bypassed_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_endpoint(monkeypatch, _canned_report())
    # First produce a report, then fetch it.
    run = auth_bypassed_client.post("/api/benchmark/run")
    assert run.status_code == 200

    got = auth_bypassed_client.get("/api/benchmark/latest")
    assert got.status_code == 200
    assert got.json()["overall"]["f1"] == 1.0


def test_get_latest_404s_when_nothing_has_run_yet(
    auth_bypassed_client: TestClient,
) -> None:
    got = auth_bypassed_client.get("/api/benchmark/latest")
    assert got.status_code == 404


def test_post_run_surfaces_harness_errors_as_500(
    auth_bypassed_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.api.benchmark as ep

    def _boom(dataset, settings=None):
        raise RuntimeError("semgrep exploded")

    monkeypatch.setattr(ep, "run_benchmark", _boom)
    resp = auth_bypassed_client.post("/api/benchmark/run")
    assert resp.status_code == 500
    assert "semgrep exploded" in resp.json()["detail"]


def test_openapi_advertises_the_benchmark_paths(
    auth_bypassed_client: TestClient,
) -> None:
    schema = auth_bypassed_client.get("/openapi.json").json()
    paths = schema["paths"]
    assert "/api/benchmark/run" in paths
    assert "/api/benchmark/latest" in paths
