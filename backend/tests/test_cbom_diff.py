"""Pure-diff unit tests + endpoint contract tests for S2 CBOM diff.

Two-layer test split:

* :func:`compute_diff` is a pure function -- most tests hit it directly
  with hand-crafted dicts. Fast, deterministic, no I/O.
* A thinner set of endpoint tests drives the FastAPI route through
  the auth-bypassed TestClient, seeding scan.json + findings.json on
  disk exactly like a real scan would.

Design contract we're pinning:

1. **Match key is (algorithm, parameter, curve, filePath)**, NOT the
   finding id or the line number. Line drift from a whitespace-only
   commit must NOT surface as ``removed X, added X``.
2. **Deltas are signed head - base.** Negative overdue delta = migration
   progress; positive overdue delta = regression (a PR introduced new
   quantum-vulnerable code).
3. **Same-scan diff is a 400.** Diffing a scan against itself is a
   user error, not a permission problem.
4. **Missing scan is 404**, whether the id truly doesn't exist or the
   caller doesn't own it. We must not leak the difference.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.diff.cbom_diff import DiffResult, compute_diff


# ---------------------------------------------------------------------------
# Small builder helpers so each test reads clearly
# ---------------------------------------------------------------------------

def _finding(
    algorithm: str,
    parameter: str | None = None,
    *,
    file_path: str = "src/demo.py",
    line: int = 10,
    tier: str = "overdue",
    hndl: bool = False,
    weak: bool = False,
    curve: str | None = None,
    fid: str | None = None,
    detection_method: str = "semgrep_api_pattern",
) -> dict[str, Any]:
    """Hand-shaped finding dict matching what the backend serialises."""
    return {
        "id": fid or f"F-{algorithm}-{parameter or curve or file_path}",
        "algorithm": algorithm,
        "displayName": f"{algorithm}-{parameter}" if parameter else algorithm,
        "parameter": parameter,
        "curve": curve,
        "filePath": file_path,
        "lineNumber": line,
        "riskTier": tier,
        "isHndlExposed": hndl,
        "isCurrentlyWeak": weak,
        "evidence": {
            "filePath": file_path,
            "lineNumber": line,
            "detectionMethod": detection_method,
        },
    }


def _scan(
    scan_id: str,
    *,
    started_at: str,
    findings: list[dict[str, Any]],
    owner: str | None = None,
) -> dict[str, Any]:
    """Compute a summary block from the finding list -- exactly the same
    shape the backend writes to scan.json."""
    summary = {
        "totalFindings": len(findings),
        "overdue": sum(1 for f in findings if f["riskTier"] == "overdue"),
        "transitional": sum(1 for f in findings if f["riskTier"] == "transitional"),
        "lowRisk": sum(1 for f in findings if f["riskTier"] == "low-risk"),
        "hndlExposed": sum(1 for f in findings if f.get("isHndlExposed")),
        "currentWeakCrypto": sum(1 for f in findings if f.get("isCurrentlyWeak")),
    }
    return {
        "id": scan_id,
        "projectId": "demo",
        "ownerId": owner,
        "status": "completed",
        "mode": "live",
        "repository": "demo-repo",
        "startedAt": started_at,
        "completedAt": started_at,
        "findingCount": len(findings),
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# compute_diff -- pure unit tests
# ---------------------------------------------------------------------------

def test_empty_scans_diff_to_empty_result() -> None:
    base = _scan("s1", started_at="2026-09-01T00:00:00Z", findings=[])
    head = _scan("s2", started_at="2026-09-02T00:00:00Z", findings=[])
    result = compute_diff(base, [], head, [])
    assert result.added_count == 0
    assert result.removed_count == 0
    assert result.changed_count == 0
    assert result.unchanged_count == 0


def test_finding_only_in_head_is_added() -> None:
    base = _scan("s1", started_at="2026-09-01T00:00:00Z", findings=[])
    new = _finding("RSA", "2048")
    head = _scan("s2", started_at="2026-09-02T00:00:00Z", findings=[new])
    result = compute_diff(base, [], head, [new])
    assert result.added_count == 1
    assert result.removed_count == 0
    assert result.added[0]["algorithm"] == "RSA"


def test_finding_only_in_base_is_removed() -> None:
    old = _finding("RSA", "2048")
    base = _scan("s1", started_at="2026-09-01T00:00:00Z", findings=[old])
    head = _scan("s2", started_at="2026-09-02T00:00:00Z", findings=[])
    result = compute_diff(base, [old], head, [])
    assert result.removed_count == 1
    assert result.added_count == 0
    assert result.removed[0]["algorithm"] == "RSA"


def test_finding_in_both_with_same_tier_is_unchanged() -> None:
    f = _finding("RSA", "2048")
    base = _scan("s1", started_at="2026-09-01T00:00:00Z", findings=[f])
    head = _scan("s2", started_at="2026-09-02T00:00:00Z", findings=[f])
    result = compute_diff(base, [f], head, [f])
    assert result.unchanged_count == 1
    assert result.added_count == 0
    assert result.removed_count == 0
    assert result.changed_count == 0


def test_tier_change_appears_in_changed_bucket() -> None:
    """A finding that moved from overdue to low-risk must land in the
    ``changed`` list with both tiers preserved -- that is the whole
    reason to diff two scans."""
    b = _finding("RSA", "2048", tier="overdue")
    h = _finding("RSA", "2048", tier="low-risk")
    base = _scan("s1", started_at="2026-09-01T00:00:00Z", findings=[b])
    head = _scan("s2", started_at="2026-09-02T00:00:00Z", findings=[h])
    result = compute_diff(base, [b], head, [h])
    assert result.changed_count == 1
    row = result.changed[0]
    assert row["previousTier"] == "overdue"
    assert row["currentTier"] == "low-risk"


def test_line_number_drift_alone_is_not_a_change() -> None:
    """A whitespace-only commit shifting the line number MUST NOT show up
    as ``removed X, added X``. Match key excludes lineNumber for exactly
    this reason -- the old recommender used to emit that noise."""
    b = _finding("RSA", "2048", line=42)
    h = _finding("RSA", "2048", line=99)
    base = _scan("s1", started_at="2026-09-01T00:00:00Z", findings=[b])
    head = _scan("s2", started_at="2026-09-02T00:00:00Z", findings=[h])
    result = compute_diff(base, [b], head, [h])
    assert result.added_count == 0
    assert result.removed_count == 0
    assert result.unchanged_count == 1


def test_parameter_change_registers_as_add_plus_remove() -> None:
    """Same file, same algorithm, different key size. The RSA-2048 has
    genuinely gone away and RSA-4096 has appeared -- both must surface."""
    b = _finding("RSA", "2048")
    h = _finding("RSA", "4096")
    base = _scan("s1", started_at="2026-09-01T00:00:00Z", findings=[b])
    head = _scan("s2", started_at="2026-09-02T00:00:00Z", findings=[h])
    result = compute_diff(base, [b], head, [h])
    assert result.added_count == 1
    assert result.removed_count == 1
    assert result.added[0]["parameter"] == "4096"
    assert result.removed[0]["parameter"] == "2048"


def test_summary_delta_is_head_minus_base() -> None:
    """A migration that fixed 3 overdue RSA findings should surface as
    ``overdue: -3`` in the delta block."""
    old = [_finding("RSA", "2048", file_path=f"a{i}.py") for i in range(3)]
    base = _scan("s1", started_at="2026-09-01T00:00:00Z", findings=old)
    head = _scan("s2", started_at="2026-09-02T00:00:00Z", findings=[])
    result = compute_diff(base, old, head, [])
    delta = result.summary_delta
    assert delta["overdue"] == -3
    assert delta["totalFindings"] == -3


def test_regression_produces_positive_delta() -> None:
    """A PR that introduced a new overdue finding must produce a POSITIVE
    delta so a CI guardrail can spot the regression."""
    base = _scan("s1", started_at="2026-09-01T00:00:00Z", findings=[])
    new = _finding("RSA", "2048")
    head = _scan("s2", started_at="2026-09-02T00:00:00Z", findings=[new])
    result = compute_diff(base, [], head, [new])
    assert result.summary_delta["overdue"] == 1
    assert result.summary_delta["totalFindings"] == 1


def test_curve_participates_in_the_match_key() -> None:
    """Two ECDSA findings at the same file with different curves are
    genuinely different assets. They must not collapse."""
    b = _finding("ECDSA", curve="P-256")
    h = _finding("ECDSA", curve="P-384")
    base = _scan("s1", started_at="2026-09-01T00:00:00Z", findings=[b])
    head = _scan("s2", started_at="2026-09-02T00:00:00Z", findings=[h])
    result = compute_diff(base, [b], head, [h])
    assert result.added_count == 1
    assert result.removed_count == 1


def test_file_path_participates_in_the_match_key() -> None:
    """Same algorithm at different files is not the same finding."""
    b = _finding("RSA", "2048", file_path="src/a.py")
    h = _finding("RSA", "2048", file_path="src/b.py")
    base = _scan("s1", started_at="2026-09-01T00:00:00Z", findings=[b])
    head = _scan("s2", started_at="2026-09-02T00:00:00Z", findings=[h])
    result = compute_diff(base, [b], head, [h])
    assert result.added_count == 1
    assert result.removed_count == 1


def test_diff_result_serialises_to_camel_case_json() -> None:
    """Output shape must match what the frontend expects, no matter
    which case Python's data classes use internally."""
    base = _scan("s1", started_at="2026-09-01T00:00:00Z", findings=[])
    head = _scan("s2", started_at="2026-09-02T00:00:00Z", findings=[])
    payload = compute_diff(base, [], head, []).to_dict()
    for key in (
        "base",
        "head",
        "summaryDelta",
        "added",
        "removed",
        "changed",
        "unchangedCount",
        "addedCount",
        "removedCount",
        "changedCount",
    ):
        assert key in payload, f"top-level key {key!r} missing"


def test_added_and_removed_lists_are_sorted_deterministically() -> None:
    """Sort order must be reproducible so the API response is stable
    across process restarts (matters for cache keys, and for tests)."""
    b_only = [
        _finding("RSA", "2048", file_path="src/z.py"),
        _finding("RSA", "2048", file_path="src/a.py"),
    ]
    base = _scan("s1", started_at="2026-09-01T00:00:00Z", findings=b_only)
    head = _scan("s2", started_at="2026-09-02T00:00:00Z", findings=[])
    result = compute_diff(base, b_only, head, [])
    paths = [row["filePath"] for row in result.removed]
    assert paths == sorted(paths)


def test_compute_diff_never_mutates_its_inputs() -> None:
    """Guardrail against a lazy dict.update anywhere in the diff logic --
    the endpoint would then leak that mutation across requests."""
    f = _finding("RSA", "2048")
    base = _scan("s1", started_at="2026-09-01T00:00:00Z", findings=[f])
    head = _scan("s2", started_at="2026-09-02T00:00:00Z", findings=[])
    base_before = json.dumps(base, sort_keys=True)
    f_before = json.dumps(f, sort_keys=True)
    compute_diff(base, [f], head, [])
    assert json.dumps(base, sort_keys=True) == base_before
    assert json.dumps(f, sort_keys=True) == f_before


# ---------------------------------------------------------------------------
# Endpoint contract tests
# ---------------------------------------------------------------------------

def _seed_scan_dir(
    artifacts_dir: Path,
    project_id: str,
    scan: dict[str, Any],
    findings: list[dict[str, Any]],
) -> Path:
    """Write scan.json + findings.json under the artefacts mirror layout."""
    scan_dir = artifacts_dir / project_id / str(scan["id"])
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan.json").write_text(json.dumps(scan), encoding="utf-8")
    (scan_dir / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
    (scan_dir / "cbom.json").write_text("{}", encoding="utf-8")
    return scan_dir


@pytest.fixture
def artifacts_dir() -> Path:
    """The isolated_env fixture in conftest.py pins ARTIFACTS_DIR to a
    per-test tmp dir. Read it back from the resolved settings."""
    get_settings.cache_clear()
    return get_settings().artifacts


def test_endpoint_returns_full_diff(
    auth_bypassed_client: TestClient, artifacts_dir: Path
) -> None:
    old = _finding("RSA", "2048", tier="overdue")
    fixed = _finding("RSA", "2048", tier="low-risk")
    _seed_scan_dir(
        artifacts_dir, "demo",
        _scan("scan-old", started_at="2026-09-01T00:00:00Z", findings=[old]),
        [old],
    )
    _seed_scan_dir(
        artifacts_dir, "demo",
        _scan("scan-new", started_at="2026-09-02T00:00:00Z", findings=[fixed]),
        [fixed],
    )

    resp = auth_bypassed_client.get(
        "/api/scans/diff?base=scan-old&head=scan-new"
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["base"]["scanId"] == "scan-old"
    assert payload["head"]["scanId"] == "scan-new"
    assert payload["changedCount"] == 1
    assert payload["changed"][0]["previousTier"] == "overdue"
    assert payload["changed"][0]["currentTier"] == "low-risk"
    assert payload["summaryDelta"]["overdue"] == -1


def test_endpoint_400s_when_base_equals_head(
    auth_bypassed_client: TestClient, artifacts_dir: Path
) -> None:
    _seed_scan_dir(
        artifacts_dir, "demo",
        _scan("only", started_at="2026-09-01T00:00:00Z", findings=[]),
        [],
    )
    resp = auth_bypassed_client.get(
        "/api/scans/diff?base=only&head=only"
    )
    assert resp.status_code == 400


def test_endpoint_404s_when_base_missing(
    auth_bypassed_client: TestClient, artifacts_dir: Path
) -> None:
    _seed_scan_dir(
        artifacts_dir, "demo",
        _scan("head-only", started_at="2026-09-02T00:00:00Z", findings=[]),
        [],
    )
    resp = auth_bypassed_client.get(
        "/api/scans/diff?base=missing&head=head-only"
    )
    assert resp.status_code == 404


def test_endpoint_404s_when_head_missing(
    auth_bypassed_client: TestClient, artifacts_dir: Path
) -> None:
    _seed_scan_dir(
        artifacts_dir, "demo",
        _scan("base-only", started_at="2026-09-01T00:00:00Z", findings=[]),
        [],
    )
    resp = auth_bypassed_client.get(
        "/api/scans/diff?base=base-only&head=missing"
    )
    assert resp.status_code == 404


def test_endpoint_requires_both_params(auth_bypassed_client: TestClient) -> None:
    """Missing base or head must produce a validation error, not a 500."""
    r1 = auth_bypassed_client.get("/api/scans/diff?head=x")
    assert r1.status_code == 422
    r2 = auth_bypassed_client.get("/api/scans/diff?base=x")
    assert r2.status_code == 422


def test_endpoint_registered_alongside_scans_endpoints(
    auth_bypassed_client: TestClient,
) -> None:
    """OpenAPI must advertise the new path so integrating clients see it."""
    schema = auth_bypassed_client.get("/openapi.json").json()
    assert "/api/scans/diff" in schema["paths"]
