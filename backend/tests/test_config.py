"""Configuration tests.

The security-relevant behaviour here is the ``AUTH_DISABLED`` escape hatch: it
must be impossible to leave enabled in production.
"""

from __future__ import annotations

import pytest

from app.config import Settings, get_settings


def test_cors_origins_parse_from_a_comma_separated_string() -> None:
    settings = Settings(blindspot_cors_origins="http://a.test, http://b.test ,")
    assert settings.cors_origins == ["http://a.test", "http://b.test"]


def test_firebase_is_not_configured_without_credentials() -> None:
    settings = Settings(firebase_project_id="demo", firebase_credentials_path=None)
    assert settings.firebase_configured is False


def test_firebase_is_not_configured_when_the_key_file_is_missing() -> None:
    settings = Settings(
        firebase_project_id="demo",
        firebase_credentials_path="C:/definitely/not/here/key.json",
    )
    assert settings.firebase_configured is False


def test_auth_bypass_allowed_in_development() -> None:
    settings = Settings(auth_disabled=True, blindspot_env="development")
    assert settings.auth_bypass_allowed() is True


def test_auth_bypass_refused_in_production() -> None:
    """A forgotten AUTH_DISABLED must not silently disable authentication."""
    settings = Settings(auth_disabled=True, blindspot_env="production")
    assert settings.is_production is True
    assert settings.auth_bypass_allowed() is False


@pytest.mark.parametrize("value", ["PRODUCTION", " production ", "Production"])
def test_production_detection_is_case_and_space_insensitive(value: str) -> None:
    settings = Settings(auth_disabled=True, blindspot_env=value)
    assert settings.auth_bypass_allowed() is False


def test_quantum_horizon_is_configurable_and_carries_provenance() -> None:
    """Z is an assumption; it must be overridable and always attributed."""
    settings = Settings(quantum_horizon_years=7, quantum_horizon_source="Internal estimate")
    assert settings.quantum_horizon_years == 7
    assert settings.quantum_horizon_source == "Internal estimate"


@pytest.mark.parametrize("field", ["quantum_horizon_years", "migration_time_years"])
def test_mosca_inputs_must_be_positive(field: str) -> None:
    with pytest.raises(Exception):
        Settings(**{field: 0})


def test_ensure_directories_creates_artefact_paths(tmp_path) -> None:
    settings = Settings(
        artifacts_dir=str(tmp_path / "artifacts"),
        fallback_cache_path=str(tmp_path / "cache" / "last_scan.json"),
    )
    settings.ensure_directories()

    assert settings.artifacts.is_dir()
    assert settings.fallback_cache.parent.is_dir()


def test_get_settings_is_cached() -> None:
    assert get_settings() is get_settings()
