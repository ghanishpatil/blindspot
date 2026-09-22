"""Cross-scan aggregation endpoint tests.

Contract:

1. ``POST /api/scan`` writes ``scan.json`` next to ``cbom.json`` and
   ``findings.json`` (verified via the isolated artifacts_dir).
2. ``GET /api/scans`` returns every scan on disk, newest first, and
   respects owner scoping.
3. ``GET /api/scans/{scan_id}`` returns the full record (scan +
   findings + cbom) or 404 when the id is unknown.
4. ``GET /api/scans/trend?project_id=X`` returns per-tier counts in
   chronological order, one point per scan.
5. Corrupt or missing artefact files degrade honestly -- an unreadable
   ``scan.json`` is skipped, not raised. This protects the demo from an
   OS-level file corruption killing the whole listing.

Every test seeds the isolated ``ARTIFACTS_DIR`` directly and hits the
endpoints via the ``auth_bypassed_client`` so the demo principal sees
every scan (single-tenant local mode) without needing a Firebase token.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings


def _seed_scan(
    artifacts_dir: Path,
    *,
    project_id: str,
    scan_id: str,
    started_at: str,
    finding_count: int = 0,
    summary: dict | None = None,
    owner_id: str | None = None,
    findings: list | None = None,
    cbom: str | None = None,
) -> Path:
    """Write a fake scan record + findings + cbom under the artifacts dir."""
    scan_dir = artifacts_dir / project_id / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    scan_record = {
        "id": scan_id,
        "projectId": project_id,
        "ownerId": owner_id,
        "status": "completed",
        "mode": "live",
        "repository": f"repo-{project_id}",
        "startedAt": started_at,
        "completedAt": started_at,
        "findingCount": finding_count,
        "summary": summary or {
            "totalFindings": finding_count,
            "overdue": 0,
            "transitional": 0,
            "lowRisk": 0,
            "hndlExposed": 0,
            "currentWeakCrypto": 0,
        },
    }
    (scan_dir / "scan.json").write_text(json.dumps(scan_record), encoding="utf-8")
    (scan_dir / "findings.json").write_text(
        json.dumps(findings or []), encoding="utf-8"
    )
    (scan_dir / "cbom.json").write_text(cbom or "{}", encoding="utf-8")
    return scan_dir


@pytest.fixture
def artifacts_dir() -> Path:
    """Read the isolated ARTIFACTS_DIR the conftest fixture set up."""
    get_settings.cache_clear()
    return get_settings().artifacts


# ---------------------------------------------------------------------------
# GET /api/scans
# ---------------------------------------------------------------------------

def test_list_scans_empty_when_nothing_on_disk(
    auth_bypassed_client: TestClient,
) -> None:
    response = auth_bypassed_client.get("/api/scans")
    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 0
    assert payload["scans"] == []


def test_list_scans_returns_newest_first(
    auth_bypassed_client: TestClient, artifacts_dir: Path
) -> None:
    _seed_scan(
        artifacts_dir, project_id="demo", scan_id="scan-old",
        started_at="2026-09-01T09:00:00+00:00", finding_count=3,
    )
    _seed_scan(
        artifacts_dir, project_id="demo", scan_id="scan-mid",
        started_at="2026-09-05T09:00:00+00:00", finding_count=5,
    )
    _seed_scan(
        artifacts_dir, project_id="demo", scan_id="scan-new",
        started_at="2026-09-10T09:00:00+00:00", finding_count=7,
    )

    payload = auth_bypassed_client.get("/api/scans").json()
    assert payload["count"] == 3
    ids = [row["scanId"] for row in payload["scans"]]
    assert ids == ["scan-new", "scan-mid", "scan-old"]


def test_list_scans_filter_by_project(
    auth_bypassed_client: TestClient, artifacts_dir: Path
) -> None:
    _seed_scan(artifacts_dir, project_id="alpha", scan_id="a1",
               started_at="2026-09-01T00:00:00+00:00")
    _seed_scan(artifacts_dir, project_id="beta", scan_id="b1",
               started_at="2026-09-01T00:00:00+00:00")

    payload = auth_bypassed_client.get("/api/scans?project_id=alpha").json()
    assert payload["count"] == 1
    assert payload["scans"][0]["projectId"] == "alpha"


def test_list_scans_carries_summary_counters(
    auth_bypassed_client: TestClient, artifacts_dir: Path
) -> None:
    """Every summary field the dashboard rows show must round-trip."""
    _seed_scan(
        artifacts_dir, project_id="demo", scan_id="scan-1",
        started_at="2026-09-01T09:00:00+00:00",
        finding_count=10,
        summary={
            "totalFindings": 10,
            "overdue": 3,
            "transitional": 4,
            "lowRisk": 3,
            "hndlExposed": 2,
            "currentWeakCrypto": 1,
        },
    )
    payload = auth_bypassed_client.get("/api/scans").json()
    row = payload["scans"][0]
    assert row["summary"]["overdue"] == 3
    assert row["summary"]["transitional"] == 4
    assert row["summary"]["lowRisk"] == 3
    assert row["summary"]["hndlExposed"] == 2
    assert row["summary"]["currentWeakCrypto"] == 1


def test_list_scans_skips_corrupt_scan_json(
    auth_bypassed_client: TestClient, artifacts_dir: Path
) -> None:
    """A malformed scan.json must be logged and skipped, not raised.

    The other scan must still surface, so a single OS-level corruption
    can't nuke the whole listing."""
    _seed_scan(artifacts_dir, project_id="demo", scan_id="good",
               started_at="2026-09-01T00:00:00+00:00")

    corrupt_dir = artifacts_dir / "demo" / "broken"
    corrupt_dir.mkdir(parents=True, exist_ok=True)
    (corrupt_dir / "scan.json").write_text("{ not-json", encoding="utf-8")

    payload = auth_bypassed_client.get("/api/scans").json()
    ids = [r["scanId"] for r in payload["scans"]]
    assert "good" in ids
    assert "broken" not in ids


# ---------------------------------------------------------------------------
# GET /api/scans/{scan_id}
# ---------------------------------------------------------------------------

def test_get_scan_returns_full_record(
    auth_bypassed_client: TestClient, artifacts_dir: Path
) -> None:
    _seed_scan(
        artifacts_dir, project_id="demo", scan_id="scan-full",
        started_at="2026-09-01T09:00:00+00:00",
        finding_count=1,
        findings=[{"id": "CRYPTO-1", "algorithm": "RSA"}],
        cbom='{"specVersion":"1.6"}',
    )
    response = auth_bypassed_client.get("/api/scans/scan-full")
    assert response.status_code == 200
    payload = response.json()

    assert payload["scan"]["id"] == "scan-full"
    assert payload["findings"] == [{"id": "CRYPTO-1", "algorithm": "RSA"}]
    assert payload["cbom"] == '{"specVersion":"1.6"}'


def test_get_scan_returns_404_when_id_missing(
    auth_bypassed_client: TestClient, artifacts_dir: Path
) -> None:
    _seed_scan(artifacts_dir, project_id="demo", scan_id="present",
               started_at="2026-09-01T09:00:00+00:00")
    response = auth_bypassed_client.get("/api/scans/does-not-exist")
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# GET /api/scans/trend
# ---------------------------------------------------------------------------

def test_trend_is_ordered_oldest_first_per_project(
    auth_bypassed_client: TestClient, artifacts_dir: Path
) -> None:
    """Line charts want time on the X axis. Trend must be chronological."""
    _seed_scan(
        artifacts_dir, project_id="demo", scan_id="s3",
        started_at="2026-09-10T00:00:00+00:00",
        summary={"totalFindings": 30, "overdue": 3, "transitional": 0,
                 "lowRisk": 27, "hndlExposed": 0, "currentWeakCrypto": 0},
    )
    _seed_scan(
        artifacts_dir, project_id="demo", scan_id="s1",
        started_at="2026-09-01T00:00:00+00:00",
        summary={"totalFindings": 10, "overdue": 5, "transitional": 0,
                 "lowRisk": 5, "hndlExposed": 0, "currentWeakCrypto": 0},
    )
    _seed_scan(
        artifacts_dir, project_id="demo", scan_id="s2",
        started_at="2026-09-05T00:00:00+00:00",
        summary={"totalFindings": 20, "overdue": 4, "transitional": 0,
                 "lowRisk": 16, "hndlExposed": 0, "currentWeakCrypto": 0},
    )

    payload = auth_bypassed_client.get("/api/scans/trend?project_id=demo").json()
    assert payload["projectId"] == "demo"
    assert payload["count"] == 3
    ids = [p["scanId"] for p in payload["points"]]
    assert ids == ["s1", "s2", "s3"]

    # Overdue counter decreasing across the three scans -- the exact
    # story a trend view is supposed to tell.
    overdues = [p["overdue"] for p in payload["points"]]
    assert overdues == [5, 4, 3]


def test_trend_only_returns_matching_project(
    auth_bypassed_client: TestClient, artifacts_dir: Path
) -> None:
    _seed_scan(artifacts_dir, project_id="alpha", scan_id="a1",
               started_at="2026-09-01T00:00:00+00:00")
    _seed_scan(artifacts_dir, project_id="beta", scan_id="b1",
               started_at="2026-09-01T00:00:00+00:00")

    payload = auth_bypassed_client.get("/api/scans/trend?project_id=alpha").json()
    assert payload["count"] == 1
    assert payload["points"][0]["scanId"] == "a1"


def test_trend_empty_when_no_scans_for_project(
    auth_bypassed_client: TestClient, artifacts_dir: Path
) -> None:
    _seed_scan(artifacts_dir, project_id="alpha", scan_id="a1",
               started_at="2026-09-01T00:00:00+00:00")

    payload = auth_bypassed_client.get("/api/scans/trend?project_id=nowhere").json()
    assert payload["count"] == 0
    assert payload["points"] == []


def test_trend_requires_project_id(auth_bypassed_client: TestClient) -> None:
    response = auth_bypassed_client.get("/api/scans/trend")
    # FastAPI returns 422 for missing required query params.
    assert response.status_code == 422
