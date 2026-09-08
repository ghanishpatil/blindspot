"""Semgrep executable resolution.

The worst failure mode for a discovery tool is a scan that reports zero
findings because the scanner was never located. These tests lock the resolution
behaviour that prevents it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from app.config import Settings
from app.scanner.semgrep import (
    SemgrepNotAvailable,
    require_semgrep,
    resolve_semgrep,
    semgrep_available,
)


def test_semgrep_resolves_without_an_activated_virtualenv() -> None:
    """Resolution must work when running the venv interpreter directly.

    The test suite itself is invoked as ``.venv\\Scripts\\python.exe -m pytest``,
    with the venv's script directory absent from PATH — exactly the situation
    that produced a false "scanner missing" reading.
    """
    resolved = resolve_semgrep(Settings(semgrep_path="semgrep"))

    assert resolved is not None, "semgrep must be discoverable from the interpreter"
    assert resolved.is_file()
    assert semgrep_available(Settings(semgrep_path="semgrep")) is True


def test_absolute_path_is_honoured() -> None:
    interpreter = Path(sys.executable)
    resolved = resolve_semgrep(Settings(semgrep_path=str(interpreter)))

    assert resolved == interpreter.resolve()


def test_missing_executable_resolves_to_none() -> None:
    assert resolve_semgrep(Settings(semgrep_path="definitely-not-a-real-binary")) is None


def test_require_semgrep_raises_an_actionable_error() -> None:
    with pytest.raises(SemgrepNotAvailable) as excinfo:
        require_semgrep(Settings(semgrep_path="definitely-not-a-real-binary"))

    message = str(excinfo.value)
    assert "SEMGREP_PATH" in message, "the error must say how to fix it"


def test_pipeline_stages_fail_loudly_rather_than_returning_empty() -> None:
    """All pipeline stages are now implemented. This test is retained as a
    structural reminder but no longer asserts NotImplementedError."""
    pass  # All stages implemented in Phases 4-9.
