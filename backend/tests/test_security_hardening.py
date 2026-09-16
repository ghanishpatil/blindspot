"""Security-hardening tests.

Cover the fixes from the security review:

* H1 — auth bypass is fail-closed: only an explicit ``development`` environment
  permits it; an unset variable defaults to ``production``.
* H2 — a caller-supplied local ``repositoryPath`` is refused outside development.
* M1 — the in-memory scan store is scoped to its owner; one user cannot read
  another user's results.
* L2 — a missing scan target returns a generic message, not the server path.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.firebase.auth import AuthenticatedUser, get_current_user
from app.main import create_app


# ── H1: fail-closed auth bypass ─────────────────────────────────────────────

def test_unset_environment_defaults_to_production(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no BLINDSPOT_ENV and no .env, the app defaults to production."""
    monkeypatch.delenv("BLINDSPOT_ENV", raising=False)
    settings = Settings(auth_disabled=True, _env_file=None)  # type: ignore[call-arg]
    assert settings.is_production is True
    assert settings.auth_bypass_allowed() is False


@pytest.mark.parametrize("env", ["staging", "prod", "", "dev", "Development "])
def test_only_literal_development_permits_bypass(env: str) -> None:
    """Anything other than the literal 'development' refuses the bypass."""
    settings = Settings(auth_disabled=True, blindspot_env=env)
    expected = env.strip().lower() == "development"
    assert settings.auth_bypass_allowed() is expected


# ── H2: repository_path refused outside development ─────────────────────────

def _client_as(user: AuthenticatedUser) -> Iterator[TestClient]:
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: user
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


def test_repository_path_rejected_outside_development(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setenv("BLINDSPOT_ENV", "production")
    get_settings.cache_clear()

    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: AuthenticatedUser(uid="u1")
    try:
        with TestClient(app) as client:
            response = client.post(
                "/api/scan",
                json={"repositoryPath": str(tmp_path), "mode": "live"},
            )
        assert response.status_code == 400
        assert "disabled" in response.json()["detail"].lower()
    finally:
        app.dependency_overrides.clear()


def test_scan_target_error_is_generic(auth_bypassed_client: TestClient) -> None:
    """A missing target returns a generic message (no server path leak). In
    development, repositoryPath is allowed, so this also confirms the dev path."""
    response = auth_bypassed_client.post(
        "/api/scan",
        json={"repositoryPath": "Z:/definitely-not-here-xyz", "mode": "live"},
    )
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "not accessible" in detail.lower()
    assert "Z:/definitely-not-here-xyz" not in detail


# ── M1: owner-scoped in-memory store ────────────────────────────────────────

def test_findings_are_scoped_to_owner() -> None:
    """A user cannot read another user's last scan."""
    from app.api import scan as scan_module

    scan_module._last_scan = {"id": "s1", "ownerId": "alice"}
    scan_module._last_findings = [{"id": "f1", "scanId": "s1"}]
    scan_module._last_cbom = "{}"

    try:
        # Bob does not own the scan → 404.
        app = create_app()
        app.dependency_overrides[get_current_user] = lambda: AuthenticatedUser(uid="bob")
        with TestClient(app) as client:
            assert client.get("/api/findings").status_code == 404
        app.dependency_overrides.clear()

        # Alice owns it → 200.
        app2 = create_app()
        app2.dependency_overrides[get_current_user] = lambda: AuthenticatedUser(uid="alice")
        with TestClient(app2) as client:
            resp = client.get("/api/findings")
            assert resp.status_code == 200
            assert resp.json()[0]["id"] == "f1"
        app2.dependency_overrides.clear()
    finally:
        scan_module._last_scan = None
        scan_module._last_findings = None
        scan_module._last_cbom = None


def test_demo_principal_sees_last_scan() -> None:
    """The single-tenant demo principal always sees the last scan."""
    from app.api import scan as scan_module

    scan_module._last_scan = {"id": "s1", "ownerId": "someone-else"}
    scan_module._last_findings = [{"id": "f1", "scanId": "s1"}]
    scan_module._last_cbom = "{}"

    try:
        app = create_app()
        app.dependency_overrides[get_current_user] = lambda: AuthenticatedUser.demo()
        with TestClient(app) as client:
            assert client.get("/api/findings").status_code == 200
        app.dependency_overrides.clear()
    finally:
        scan_module._last_scan = None
        scan_module._last_findings = None
        scan_module._last_cbom = None
