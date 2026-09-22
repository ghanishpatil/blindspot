"""Backend startup and health endpoint tests."""

from __future__ import annotations

import pytest
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
    """Missing REQUIRED subsystems flip readiness to 'degraded'.

    In the default test fixture Firebase is intentionally unconfigured,
    which resolves the storage backend to 'local' (air-gap mode). In
    that state Firebase is NOT required and must not contribute to the
    degraded list -- otherwise every honest air-gap deployment would
    look broken. The seeded demo repository is missing in the fixture
    though, and it *is* required, so it must still surface as degraded.
    """
    payload = client.get("/api/health").json()

    assert payload["readiness"] == "degraded"
    assert "demoRepository" in payload["degradedSubsystems"]

    # Firebase must be reported as unavailable in the subsystems block
    # so an operator can see its state -- but it must NOT be flagged
    # as a degradation when the operator has opted into local storage.
    assert payload["subsystems"]["firebase"]["available"] is False
    assert "firebase" not in payload["degradedSubsystems"]


def test_health_flags_firebase_when_explicitly_requested(
    monkeypatch: pytest.MonkeyPatch,
    client: TestClient,
) -> None:
    """When the operator explicitly asks for the Firebase backend and
    it isn't reachable, THAT is a real degradation -- opposite of the
    default-auto case above."""
    monkeypatch.setenv("STORAGE_BACKEND", "firebase")
    from app.config import get_settings

    get_settings.cache_clear()

    payload = client.get("/api/health").json()

    assert "firebase" in payload["degradedSubsystems"], (
        "Firebase must count as degraded when the operator explicitly "
        "pinned STORAGE_BACKEND=firebase but Firebase isn't reachable."
    )


def test_health_reports_ready_when_only_firebase_is_missing_in_local_mode(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    client: TestClient,
) -> None:
    """The exact air-gap-demo config: STORAGE_BACKEND=local, no
    Firebase, but every other subsystem is fine -> readiness=ready.

    This is the state a judge will see when they hit /api/health during
    the demo. If it reads 'degraded' the story unravels.
    """
    monkeypatch.setenv("STORAGE_BACKEND", "local")

    # Materialise a stand-in demo repo dir so demoRepository is available
    # (the fixture only sets a path; it doesn't create it).
    from app.config import get_settings

    get_settings.cache_clear()
    demo_repo = get_settings().demo_repo
    demo_repo.mkdir(parents=True, exist_ok=True)
    (demo_repo / "README.md").write_text("stand-in", encoding="utf-8")

    # And a stand-in cache so fallbackCache is available too.
    cache = get_settings().fallback_cache
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text('{"scan":{}}', encoding="utf-8")

    payload = client.get("/api/health").json()

    assert payload["readiness"] == "ready", (
        f"Air-gap-mode demo should read ready but got degraded: "
        f"{payload['degradedSubsystems']}"
    )
    assert payload["degradedSubsystems"] == []


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
