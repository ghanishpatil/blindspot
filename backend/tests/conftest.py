"""Shared pytest fixtures.

Tests must not depend on the developer's local ``.env`` or on a real Firebase
project. Environment variables take precedence over ``.env`` in
pydantic-settings, so the ``isolated_env`` fixture pins every setting that
affects behaviour and clears the cached ``Settings`` and Firebase state between
tests.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import get_settings
from app.firebase.client import reset_firebase
from app.firebase.firestore import reset_firestore
from app.firebase.storage import reset_storage
from app.main import create_app


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """Pin configuration to known values and redirect writes to a temp dir."""
    monkeypatch.setenv("BLINDSPOT_ENV", "development")
    monkeypatch.setenv(
        "BLINDSPOT_CORS_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173"
    )

    # No Firebase project during tests; empty values read as unset.
    monkeypatch.setenv("FIREBASE_PROJECT_ID", "")
    monkeypatch.setenv("FIREBASE_CREDENTIALS_PATH", "")
    monkeypatch.setenv("FIREBASE_STORAGE_BUCKET", "")
    monkeypatch.setenv("AUTH_DISABLED", "false")

    monkeypatch.setenv("QUANTUM_HORIZON_YEARS", "10")
    monkeypatch.setenv("MIGRATION_TIME_YEARS", "3")

    monkeypatch.setenv("ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("FALLBACK_CACHE_PATH", str(tmp_path / "cache" / "last_scan.json"))
    monkeypatch.setenv("DEMO_REPO_PATH", str(tmp_path / "demo-repo"))
    monkeypatch.setenv("SCAN_WORK_DIR", str(tmp_path / "scan-work"))

    get_settings.cache_clear()
    reset_firebase()
    reset_firestore()
    reset_storage()

    yield

    get_settings.cache_clear()
    reset_firebase()
    reset_firestore()
    reset_storage()


@pytest.fixture
def app() -> FastAPI:
    """A freshly built application using the isolated environment."""
    return create_app()


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    """Test client with authentication enforced.

    Entering the context manager runs the lifespan, so this fixture also
    exercises application startup.
    """
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def auth_bypassed_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """Test client with ``AUTH_DISABLED=true``, for reaching protected handlers."""
    monkeypatch.setenv("AUTH_DISABLED", "true")
    get_settings.cache_clear()

    with TestClient(create_app()) as test_client:
        yield test_client
