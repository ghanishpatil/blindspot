"""Tests for the STORAGE_BACKEND setting and its effect on persistence.

Design contract:

1. ``storage_backend`` accepts 'auto', 'local', 'firebase' (case-insensitive).
2. ``effective_storage_backend`` resolves 'auto' to 'firebase' when
   ``firebase_configured`` is true, else to 'local'.
3. ``'local'`` pins the effective backend regardless of Firebase config -- the
   knob operators use to prove nothing leaves the box.
4. The rehydration helper repopulates the in-memory scan store from a written
   fallback cache, so a backend restart in local mode does not silently lose
   the last successful scan.
5. The health endpoint surfaces both the requested and the effective backend
   so an auditor can see the state without reading the config.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app import pipeline as pipeline_module
from app.api import scan as scan_module
from app.config import Settings, get_settings


# ---------------------------------------------------------------------------
# Setting shape + resolution
# ---------------------------------------------------------------------------

def _clear_storage_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate Settings() from the developer's own .env by clearing every
    env var the storage-backend logic depends on. Without this, running
    with STORAGE_BACKEND=local in the local .env (a legitimate air-gap
    setup) would poison tests that assert on the class default.
    """
    for var in (
        "STORAGE_BACKEND",
        "FIREBASE_PROJECT_ID",
        "FIREBASE_CREDENTIALS_PATH",
        "FIREBASE_STORAGE_BUCKET",
    ):
        monkeypatch.delenv(var, raising=False)


def test_storage_backend_defaults_to_auto(monkeypatch: pytest.MonkeyPatch) -> None:
    # Skip the developer's .env so we're testing the class default, not
    # whatever they last set for local runs (STORAGE_BACKEND=local is a
    # legitimate air-gap-demo setting).
    _clear_storage_env(monkeypatch)
    settings = Settings(_env_file=None)  # type: ignore[arg-type]
    assert settings.storage_backend == "auto"


def test_effective_backend_auto_falls_through_to_local_without_firebase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_storage_env(monkeypatch)
    settings = Settings(
        firebase_project_id=None,
        firebase_credentials_path=None,
        storage_backend="auto",
    )
    assert settings.firebase_configured is False
    assert settings.effective_storage_backend == "local"


def test_effective_backend_local_is_local_regardless_of_firebase(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A fully-configured Firebase must still resolve to 'local' when the
    # operator has explicitly pinned local mode.
    _clear_storage_env(monkeypatch)
    creds = tmp_path / "sa.json"
    creds.write_text("{}")
    settings = Settings(
        firebase_project_id="demo",
        firebase_credentials_path=str(creds),
        storage_backend="local",
    )
    assert settings.firebase_configured is True
    assert settings.effective_storage_backend == "local"


def test_effective_backend_firebase_is_firebase_even_without_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Operator asked for 'firebase' explicitly -- resolution respects the
    # request. Callers upstream still guard on adapter.available before
    # writing; the point of this branch is that we do not silently degrade
    # to 'local' when the operator wants Firebase failures to be loud.
    _clear_storage_env(monkeypatch)
    settings = Settings(
        firebase_project_id=None,
        firebase_credentials_path=None,
        storage_backend="firebase",
    )
    assert settings.effective_storage_backend == "firebase"


@pytest.mark.parametrize("value", ["Local", "LOCAL", "  local  "])
def test_effective_backend_normalises_case_and_whitespace(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    _clear_storage_env(monkeypatch)
    settings = Settings(storage_backend=value)
    assert settings.effective_storage_backend == "local"


def test_effective_backend_unknown_value_treated_as_auto(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Forward compatibility: an unknown value never crashes; it just resolves
    # via the auto rule.
    _clear_storage_env(monkeypatch)
    settings = Settings(
        firebase_project_id=None,
        firebase_credentials_path=None,
        storage_backend="cassette-tape",
    )
    assert settings.effective_storage_backend == "local"


# ---------------------------------------------------------------------------
# Rehydration from cache on startup
# ---------------------------------------------------------------------------

def _write_fake_cache(cache_path: Path) -> None:
    """Write a minimally-valid fallback cache file at ``cache_path``."""
    payload = {
        "scan": {
            "id": "scan-rehydrated",
            "projectId": "demo",
            "ownerId": None,
            "status": "completed",
            "mode": "live",
            "repository": "test-repo",
            "startedAt": "2026-09-07T10:00:00+00:00",
            "completedAt": "2026-09-07T10:05:00+00:00",
            "findingCount": 0,
            "summary": {},
        },
        "findings": [],
        "cbom": "{}",
    }
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(payload), encoding="utf-8")


def test_rehydrate_from_cache_repopulates_in_memory_store(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A restart must not silently lose the last scan when a cache is on disk."""
    cache_path = tmp_path / "cache" / "last_scan.json"
    _write_fake_cache(cache_path)

    monkeypatch.setenv("FALLBACK_CACHE_PATH", str(cache_path))
    get_settings.cache_clear()

    # Clear any residue in the in-memory store, then rehydrate.
    scan_module._last_scan = None
    scan_module._last_findings = None
    scan_module._last_cbom = None

    loaded = scan_module.rehydrate_from_cache()
    assert loaded is True
    assert scan_module._last_scan is not None
    assert scan_module._last_scan["id"] == "scan-rehydrated"
    assert scan_module._last_findings == []
    assert scan_module._last_cbom == "{}"

    # Clean up so we do not leak state to unrelated tests.
    scan_module._last_scan = None
    scan_module._last_findings = None
    scan_module._last_cbom = None
    get_settings.cache_clear()


def test_rehydrate_from_cache_returns_false_when_nothing_on_disk(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """No cache on disk is the normal fresh-boot case, not an error."""
    monkeypatch.setenv("FALLBACK_CACHE_PATH", str(tmp_path / "missing.json"))
    get_settings.cache_clear()

    scan_module._last_scan = None
    scan_module._last_findings = None
    scan_module._last_cbom = None

    loaded = scan_module.rehydrate_from_cache()
    assert loaded is False
    assert scan_module._last_scan is None

    get_settings.cache_clear()


def test_rehydrate_from_cache_swallows_corrupt_cache(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A corrupt cache must not prevent startup."""
    cache_path = tmp_path / "cache" / "last_scan.json"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text("{ not valid json", encoding="utf-8")

    monkeypatch.setenv("FALLBACK_CACHE_PATH", str(cache_path))
    get_settings.cache_clear()

    scan_module._last_scan = None
    loaded = scan_module.rehydrate_from_cache()
    # load_cached_result already returns None on parse failure -> rehydrate
    # sees no cache and returns False. Either way, no exception escapes.
    assert loaded is False

    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Health endpoint exposes the storage backend
# ---------------------------------------------------------------------------

def test_health_endpoint_reports_storage_backend(client: TestClient) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    payload = response.json()

    assert "storage" in payload, "health must report the storage subsystem"
    storage = payload["storage"]

    for key in ("requested", "effective", "artifactsDir", "fallbackCachePath"):
        assert key in storage, f"health.storage must include {key!r}"

    # Effective must be one of the two concrete values.
    assert storage["effective"] in {"firebase", "local"}
