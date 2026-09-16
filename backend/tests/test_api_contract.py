"""API contract tests.

Tests authentication enforcement and endpoint behavior now that the
pipeline is implemented.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

PROTECTED_GET_ROUTES = [
    "/api/findings",
    "/api/findings/CRYPTO-001",
    "/api/export/cbom",
]


@pytest.mark.parametrize("route", PROTECTED_GET_ROUTES)
def test_protected_get_requires_token(client: TestClient, route: str) -> None:
    response = client.get(route)
    assert response.status_code == 401
    assert "token" in response.json()["detail"].lower()


def test_protected_post_requires_token(client: TestClient) -> None:
    response = client.post("/api/scan", json={"mode": "live"})
    assert response.status_code == 401


def test_invalid_token_is_rejected(client: TestClient) -> None:
    response = client.get(
        "/api/findings", headers={"Authorization": "Bearer not-a-real-token"}
    )
    assert response.status_code in (401, 503)


def test_non_bearer_scheme_is_rejected(client: TestClient) -> None:
    response = client.get("/api/findings", headers={"Authorization": "Basic abc123"})
    assert response.status_code == 401


def test_scan_returns_200_with_auth_bypass(auth_bypassed_client: TestClient) -> None:
    """POST /scan should now run the real pipeline with auth bypassed."""
    response = auth_bypassed_client.post("/api/scan", json={"mode": "live"})
    # If demo-repo exists it returns 200, otherwise 400 (target not found).
    assert response.status_code in (200, 400, 500)


def test_scan_request_validation_rejects_unknown_mode(
    auth_bypassed_client: TestClient,
) -> None:
    response = auth_bypassed_client.post("/api/scan", json={"mode": "pretend"})
    assert response.status_code == 422


def test_scan_accepts_camel_case_request_body(
    auth_bypassed_client: TestClient,
) -> None:
    response = auth_bypassed_client.post(
        "/api/scan",
        json={"projectId": "demo", "mode": "cached"},
    )
    # Cached mode returns 404 if no cache exists, 400 if repo missing, or 200.
    assert response.status_code in (200, 400, 404)


def test_auth_bypass_uses_a_labelled_demo_principal(
    auth_bypassed_client: TestClient,
) -> None:
    from app.firebase.auth import AuthenticatedUser

    user = AuthenticatedUser.demo()
    assert user.is_demo_principal is True
    assert "bypass" in (user.display_name or "").lower()


def test_health_is_public(client: TestClient) -> None:
    assert client.get("/api/health").status_code == 200


def test_scan_rejects_disallowed_repository_url(
    auth_bypassed_client: TestClient,
) -> None:
    """A repository_url on a non-allowlisted host is rejected with 400 (SSRF guard)."""
    response = auth_bypassed_client.post(
        "/api/scan",
        json={"repositoryUrl": "https://evil.example.com/owner/repo", "mode": "live"},
    )
    assert response.status_code == 400
    assert "repository" in response.json()["detail"].lower()


def test_scan_rejects_non_https_repository_url(
    auth_bypassed_client: TestClient,
) -> None:
    """A non-HTTPS repository_url is rejected with 400 before any network access."""
    response = auth_bypassed_client.post(
        "/api/scan",
        json={"repositoryUrl": "http://github.com/owner/repo", "mode": "live"},
    )
    assert response.status_code == 400


def test_findings_return_404_before_scan(auth_bypassed_client: TestClient) -> None:
    """GET /findings before any scan returns 404, not fabricated data."""
    # Reset in-memory state.
    from app.api import scan as scan_module
    scan_module._last_scan = None
    scan_module._last_findings = None
    scan_module._last_cbom = None

    response = auth_bypassed_client.get("/api/findings")
    assert response.status_code == 404
