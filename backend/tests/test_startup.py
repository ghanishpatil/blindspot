"""Backend startup and health endpoint tests."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_application_starts(client: TestClient) -> None:
    """Entering the TestClient context runs the lifespan without raising."""
    response = client.get("/")
    assert response.status_code == 200

    payload = response.json()
    assert payload["service"] == "Blindspot ECDAT"
    assert payload["health"] == "/api/health"


def test_startup_succeeds_without_firebase(client: TestClient) -> None:
    """A missing Firebase project must not prevent the API from serving.

    The demo has to be diagnosable. An unconfigured credential should surface as
    a clear readiness message, not a process that refuses to boot.
    """
    response = client.get("/api/health")
    assert response.status_code == 200

    firebase = response.json()["subsystems"]["firebase"]
    assert firebase["available"] is False
    assert firebase["reason"], "an unavailable subsystem must explain why"


def test_health_reports_subsystem_readiness(client: TestClient) -> None:
    payload = client.get("/api/health").json()

    assert payload["status"] == "ok"
    assert payload["environment"] == "development"

    subsystems = payload["subsystems"]
    for name in ("firebase", "semgrep", "demoRepository", "fallbackCache"):
        assert name in subsystems, f"health must report {name}"
        assert "available" in subsystems[name]


def test_health_flags_degraded_subsystems(client: TestClient) -> None:
    """With no Firebase and no seeded repo, readiness must say 'degraded'."""
    payload = client.get("/api/health").json()

    assert payload["readiness"] == "degraded"
    assert "firebase" in payload["degradedSubsystems"]
    assert "demoRepository" in payload["degradedSubsystems"]


def test_semgrep_is_installed_and_discoverable(client: TestClient) -> None:
    """Semgrep must be present, since Phase 4 discovery depends on it.

    Guards the specific Windows packaging trap: semgrep versions without a
    win_amd64 wheel fail to install at all.
    """
    semgrep = client.get("/api/health").json()["subsystems"]["semgrep"]
    assert semgrep["available"] is True, semgrep["reason"]


def test_openapi_schema_is_served(client: TestClient) -> None:
    response = client.get("/openapi.json")
    assert response.status_code == 200

    paths = response.json()["paths"]
    for route in ("/api/scan", "/api/findings", "/api/findings/{finding_id}", "/api/export/cbom"):
        assert route in paths, f"{route} must be present in the OpenAPI schema"
