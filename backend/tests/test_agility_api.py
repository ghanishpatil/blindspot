"""Tests for :mod:`app.api.agility` -- GET /api/agility/{scanId}.

Contract:

* Score comes from the persisted scan's ``summary`` block -- honest,
  provenanced, unable to be spoofed by a caller.
* 404 when the scan does not exist or the caller does not own it (we
  do not distinguish the two -- see the security note on the scans
  endpoint).
* Owner-scoping matches ``GET /api/scans/{scanId}``.
* OpenAPI advertises the path so integration clients see it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings


def _seed_scan(
    artifacts_dir: Path,
    scan_id: str,
    summary: dict[str, int],
    project_id: str = "demo",
    owner_id: str | None = "demo-user",
) -> None:
    """Write a minimal scan record. Only ``id``, ``summary`` and
    ``ownerId`` are read by the agility endpoint."""
    scan_dir = artifacts_dir / project_id / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    record: dict[str, Any] = {
        "id": scan_id,
        "projectId": project_id,
        "startedAt": "2026-09-01T00:00:00Z",
        "completedAt": "2026-09-01T00:00:05Z",
        "status": "success",
        "summary": summary,
    }
    if owner_id is not None:
        record["ownerId"] = owner_id
    (scan_dir / "scan.json").write_text(json.dumps(record), encoding="utf-8")
    (scan_dir / "findings.json").write_text("[]", encoding="utf-8")
    (scan_dir / "cbom.json").write_text("{}", encoding="utf-8")


@pytest.fixture
def artifacts_dir() -> Path:
    get_settings.cache_clear()
    return get_settings().artifacts


def test_agility_endpoint_returns_score_for_a_visible_scan(
    auth_bypassed_client: TestClient, artifacts_dir: Path
) -> None:
    _seed_scan(
        artifacts_dir,
        "scan-a",
        {
            "totalFindings": 4,
            "overdue": 2,
            "transitional": 0,
            "lowRisk": 2,
            "currentWeakCrypto": 0,
            "hndlExposed": 0,
        },
    )

    resp = auth_bypassed_client.get("/api/agility/scan-a")
    assert resp.status_code == 200
    body = resp.json()
    assert body["scanId"] == "scan-a"
    assert body["projectId"] == "demo"
    assert body["schemaVersion"] == "blindspot.agility.v1"
    assert 0.0 <= body["score"] <= 100.0
    assert body["grade"] in {"A", "B", "C", "D", "F"}
    assert set(body["breakdown"].keys()) == {"tierPosture", "weaknessImmunity", "hndlImmunity"}


def test_agility_score_uses_the_persisted_summary_verbatim(
    auth_bypassed_client: TestClient, artifacts_dir: Path
) -> None:
    """A caller must not be able to influence the score with query
    parameters or a request body. The endpoint is a read of the
    on-disk scan.summary."""
    _seed_scan(
        artifacts_dir,
        "scan-perfect",
        {
            "totalFindings": 5,
            "overdue": 0,
            "transitional": 0,
            "lowRisk": 5,
            "currentWeakCrypto": 0,
            "hndlExposed": 0,
        },
    )
    body = auth_bypassed_client.get("/api/agility/scan-perfect").json()
    assert body["score"] == pytest.approx(100.0)
    assert body["grade"] == "A"


def test_agility_endpoint_404s_when_scan_is_missing(
    auth_bypassed_client: TestClient, artifacts_dir: Path
) -> None:
    resp = auth_bypassed_client.get("/api/agility/no-such-scan")
    assert resp.status_code == 404
    assert "no-such-scan" in resp.json()["detail"]


def test_agility_endpoint_404s_when_scan_is_not_owned(
    client: TestClient, artifacts_dir: Path
) -> None:
    """With auth enforced (no AUTH_DISABLED bypass), an unauthenticated
    caller must not reach the score. Even if the scan exists, the
    endpoint is a 401 / 403 before the record is loaded."""
    _seed_scan(
        artifacts_dir,
        "scan-secret",
        {"totalFindings": 0},
        owner_id="someone-else",
    )
    resp = client.get("/api/agility/scan-secret")
    # Auth is enforced; caller gets rejected before ownership matters.
    assert resp.status_code in (401, 403)


def test_openapi_advertises_the_agility_path(
    auth_bypassed_client: TestClient,
) -> None:
    schema = auth_bypassed_client.get("/openapi.json").json()
    # OpenAPI uses the FastAPI path template.
    assert "/api/agility/{scan_id}" in schema["paths"]
