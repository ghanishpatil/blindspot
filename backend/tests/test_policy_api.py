"""Tests for :mod:`app.api.policy` -- the REST surface for policy-as-code.

Endpoint contract:

* ``GET  /api/policy``           -- returns the active policy, or default.
* ``GET  /api/policy/default``   -- read-only built-in default.
* ``PUT  /api/policy``           -- validate + persist. 400 on schema error.
* ``POST /api/policy/reset``     -- delete override, revert to default.
* ``POST /api/policy/simulate``  -- delta + policy evaluation without persisting.

Simulation reuses the artefact mirror on disk (same as
``GET /api/scans/diff``), so this test file seeds scans via the same
helper.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.cli.policy import DEFAULT_POLICY, POLICY_SCHEMA_VERSION, policy_to_dict
from app.config import get_settings


# ---------------------------------------------------------------------------
# Local builders -- kept intentionally small; the CLI/diff test file
# already exhausts fingerprint / delta edge cases.
# ---------------------------------------------------------------------------

def _finding(
    algorithm: str,
    parameter: str | None = None,
    *,
    file_path: str = "src/demo.py",
    line: int = 10,
    tier: str = "overdue",
    weak: bool = False,
    hndl: bool = False,
    quantum: bool = True,
    rule_id: str = "rule-a",
) -> dict[str, Any]:
    """Real-shape finding: evidence is the code snippet string, and
    the structured metadata lives under ``evidenceDetail``. Matches
    what the pipeline actually writes to ``findings.json``.
    """
    return {
        "id": f"F-{algorithm}-{parameter or file_path}",
        "algorithm": algorithm,
        "parameter": parameter,
        "curve": None,
        "filePath": file_path,
        "lineNumber": line,
        "riskTier": tier,
        "isCurrentlyWeak": weak,
        "isQuantumSensitive": quantum,
        "isHndlExposed": hndl,
        "parameterStatus": "resolved",
        "needsVerification": False,
        "evidence": "code snippet here",
        "evidenceDetail": {
            "filePath": file_path,
            "lineNumber": line,
            "ruleId": rule_id,
        },
    }


def _scan(scan_id: str) -> dict[str, Any]:
    return {
        "id": scan_id,
        "projectId": "demo",
        "startedAt": "2026-09-01T00:00:00Z",
        "completedAt": "2026-09-01T00:00:01Z",
        "status": "success",
        "ownerUid": "demo-user",  # matches AUTH_DISABLED demo principal
    }


def _seed_scan_dir(
    artifacts_dir: Path,
    scan: dict[str, Any],
    findings: list[dict[str, Any]],
) -> None:
    scan_dir = artifacts_dir / scan["projectId"] / scan["id"]
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan.json").write_text(json.dumps(scan), encoding="utf-8")
    (scan_dir / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
    (scan_dir / "cbom.json").write_text("{}", encoding="utf-8")


@pytest.fixture
def artifacts_dir() -> Path:
    get_settings.cache_clear()
    return get_settings().artifacts


# ---------------------------------------------------------------------------
# GET / default
# ---------------------------------------------------------------------------

def test_get_policy_returns_default_when_no_override(
    auth_bypassed_client: TestClient,
) -> None:
    resp = auth_bypassed_client.get("/api/policy")
    assert resp.status_code == 200
    body = resp.json()
    assert body["isDefault"] is True
    assert body["schemaVersion"] == POLICY_SCHEMA_VERSION
    assert body["policy"] == policy_to_dict(DEFAULT_POLICY)


def test_get_default_endpoint_is_readonly(
    auth_bypassed_client: TestClient,
) -> None:
    resp = auth_bypassed_client.get("/api/policy/default")
    assert resp.status_code == 200
    body = resp.json()
    assert body["isDefault"] is True
    assert body["policy"] == policy_to_dict(DEFAULT_POLICY)

    # PUT to /default must not exist -- there is no active override there.
    put = auth_bypassed_client.put("/api/policy/default", json={"name": "x"})
    assert put.status_code == 405  # Method Not Allowed


# ---------------------------------------------------------------------------
# PUT -- validate + persist
# ---------------------------------------------------------------------------

def _valid_custom_policy() -> dict[str, Any]:
    return {
        "schemaVersion": POLICY_SCHEMA_VERSION,
        "name": "team-policy",
        "rules": [
            {
                "id": "no-new-quantum-sensitive",
                "on": "introduced",
                "match": {"isQuantumSensitive": True},
                "action": "block",
            }
        ],
    }


def test_put_persists_valid_policy(
    auth_bypassed_client: TestClient,
) -> None:
    resp = auth_bypassed_client.put("/api/policy", json=_valid_custom_policy())
    assert resp.status_code == 200
    body = resp.json()
    assert body["isDefault"] is False
    assert body["policy"]["name"] == "team-policy"

    # GET reflects the new state.
    reread = auth_bypassed_client.get("/api/policy").json()
    assert reread["isDefault"] is False
    assert reread["policy"] == body["policy"]


@pytest.mark.parametrize(
    "bad_payload,expect_message_contains",
    [
        # Missing action on a rule.
        (
            {
                "name": "bad",
                "rules": [{"id": "x", "on": "introduced", "match": {"a": 1}}],
            },
            "action",
        ),
        # Unknown bucket.
        (
            {
                "name": "bad",
                "rules": [
                    {"id": "x", "on": "elsewhere", "match": {"a": 1}, "action": "block"}
                ],
            },
            "on",
        ),
        # match must be a dict.
        (
            {
                "name": "bad",
                "rules": [
                    {"id": "x", "on": "introduced", "match": "no", "action": "block"}
                ],
            },
            "match",
        ),
    ],
)
def test_put_rejects_malformed_policy_with_400(
    auth_bypassed_client: TestClient,
    bad_payload: dict[str, Any],
    expect_message_contains: str,
) -> None:
    resp = auth_bypassed_client.put("/api/policy", json=bad_payload)
    assert resp.status_code == 400
    assert expect_message_contains in resp.json()["detail"].lower()


def test_put_rejection_does_not_change_active_policy(
    auth_bypassed_client: TestClient,
) -> None:
    """Failed PUTs must be a no-op on state -- honesty guardrail."""
    # Establish a known override first.
    ok = auth_bypassed_client.put("/api/policy", json=_valid_custom_policy())
    assert ok.status_code == 200

    # Now fire a bad payload.
    bad = auth_bypassed_client.put(
        "/api/policy",
        json={"name": "bad", "rules": "not a list"},
    )
    assert bad.status_code == 400

    # The previous override is intact.
    reread = auth_bypassed_client.get("/api/policy").json()
    assert reread["policy"]["name"] == "team-policy"


# ---------------------------------------------------------------------------
# reset
# ---------------------------------------------------------------------------

def test_reset_reverts_to_default_and_is_idempotent(
    auth_bypassed_client: TestClient,
) -> None:
    auth_bypassed_client.put("/api/policy", json=_valid_custom_policy())

    first = auth_bypassed_client.post("/api/policy/reset")
    assert first.status_code == 200
    assert first.json()["isDefault"] is True

    # Second reset is a no-op, not a 404.
    second = auth_bypassed_client.post("/api/policy/reset")
    assert second.status_code == 200
    assert second.json()["isDefault"] is True

    # State reflects it.
    assert auth_bypassed_client.get("/api/policy").json()["isDefault"] is True


# ---------------------------------------------------------------------------
# simulate
# ---------------------------------------------------------------------------

def _seed_two_scans(artifacts_dir: Path) -> None:
    """Seed base=scan-a (empty) and head=scan-b (one overdue RSA)."""
    _seed_scan_dir(artifacts_dir, _scan("scan-a"), [])
    _seed_scan_dir(
        artifacts_dir,
        _scan("scan-b"),
        [_finding("RSA", "2048", tier="overdue")],
    )


def test_simulate_with_default_policy_fires_on_introduced_overdue(
    auth_bypassed_client: TestClient,
    artifacts_dir: Path,
) -> None:
    _seed_two_scans(artifacts_dir)
    resp = auth_bypassed_client.post(
        "/api/policy/simulate",
        json={"base": "scan-a", "head": "scan-b"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["counts"]["introduced"] == 1
    assert body["blockCount"] >= 1
    assert body["wouldBlock"] is True
    # The specific rule from the default policy fired.
    rule_ids = {v["ruleId"] for v in body["violations"]}
    assert "no-new-overdue" in rule_ids


def test_simulate_with_lenient_custom_policy_would_not_block(
    auth_bypassed_client: TestClient,
    artifacts_dir: Path,
) -> None:
    """A policy with only a warn rule must not report ``wouldBlock``."""
    _seed_two_scans(artifacts_dir)

    lenient = {
        "schemaVersion": POLICY_SCHEMA_VERSION,
        "name": "warn-only",
        "rules": [
            {
                "id": "warn-new-quantum-sensitive",
                "on": "introduced",
                "match": {"isQuantumSensitive": True},
                "action": "warn",
            }
        ],
    }
    resp = auth_bypassed_client.post(
        "/api/policy/simulate",
        json={"base": "scan-a", "head": "scan-b", "policy": lenient},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["wouldBlock"] is False
    assert body["blockCount"] == 0
    assert body["warnCount"] == 1


def test_simulate_rejects_same_base_and_head_with_400(
    auth_bypassed_client: TestClient,
    artifacts_dir: Path,
) -> None:
    _seed_two_scans(artifacts_dir)
    resp = auth_bypassed_client.post(
        "/api/policy/simulate",
        json={"base": "scan-a", "head": "scan-a"},
    )
    assert resp.status_code == 400


def test_simulate_returns_404_when_scan_missing(
    auth_bypassed_client: TestClient,
    artifacts_dir: Path,
) -> None:
    _seed_two_scans(artifacts_dir)
    resp = auth_bypassed_client.post(
        "/api/policy/simulate",
        json={"base": "scan-a", "head": "does-not-exist"},
    )
    assert resp.status_code == 404


def test_simulate_rejects_malformed_policy_with_400(
    auth_bypassed_client: TestClient,
    artifacts_dir: Path,
) -> None:
    _seed_two_scans(artifacts_dir)
    resp = auth_bypassed_client.post(
        "/api/policy/simulate",
        json={
            "base": "scan-a",
            "head": "scan-b",
            "policy": {"rules": [{"id": "", "on": "x", "match": {}, "action": "no"}]},
        },
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# OpenAPI advertising
# ---------------------------------------------------------------------------

def test_openapi_advertises_policy_paths(
    auth_bypassed_client: TestClient,
) -> None:
    """Integration clients discover the new endpoints via /openapi.json."""
    schema = auth_bypassed_client.get("/openapi.json").json()
    paths = schema["paths"]
    assert "/api/policy" in paths
    assert "/api/policy/default" in paths
    assert "/api/policy/reset" in paths
    assert "/api/policy/simulate" in paths
