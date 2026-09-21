"""Tests for the new "0 means unlimited" scan-timeout semantics.

Covers:

1. :func:`subprocess_timeout` -- the shared translator that turns a
   config value into the argument :func:`subprocess.run` expects.
2. :func:`clone_repository` -- ``timeout=None`` is threaded through when
   ``REPO_CLONE_TIMEOUT_SECONDS=0`` (the new default), and the raw
   ``git`` stderr is classified into an actionable, user-facing message
   when the clone fails.
3. :func:`run_semgrep` -- ``timeout=None`` is threaded through when
   ``SEMGREP_TIMEOUT_SECONDS=0``.

The intent is verified by monkeypatching :func:`subprocess.run` and
asserting the ``timeout`` kwarg the scanner passes to it. No real ``git``
or ``semgrep`` process is invoked here.
"""

from __future__ import annotations

import json
import subprocess
import types
from pathlib import Path

import pytest

from app.config import get_settings, subprocess_timeout
from app.scanner import repository as repo_module
from app.scanner import semgrep as semgrep_module
from app.scanner.repository import (
    RepositoryError,
    _classify_git_stderr,
    clone_repository,
)
from app.scanner.semgrep import SemgrepScanError, run_semgrep


# ===========================================================================
# subprocess_timeout -- the shared translator
# ===========================================================================

def test_subprocess_timeout_returns_none_for_zero() -> None:
    """The new default is 0 == unlimited. `subprocess.run` receives
    `timeout=None`, which means "wait indefinitely"."""
    assert subprocess_timeout(0) is None


def test_subprocess_timeout_returns_none_for_negative() -> None:
    """A negative value is treated as unlimited too -- honestly, an
    accidental -1 is a strictly better default than a fixed cap."""
    assert subprocess_timeout(-5) is None


def test_subprocess_timeout_passes_positive_through_as_float() -> None:
    """A positive number is honoured verbatim (as a float, which is what
    subprocess.run accepts)."""
    assert subprocess_timeout(30) == 30.0
    assert subprocess_timeout(600) == 600.0


# ===========================================================================
# Repository stderr classification -- honest, human-readable messages
# ===========================================================================

@pytest.mark.parametrize("stderr,expected_hint", [
    (
        "remote: Repository not found.\nfatal: repository 'https://github.com/x/y' not found",
        "Repository not found",
    ),
    (
        "fatal: Authentication failed for 'https://github.com/x/y.git/'",
        "Authentication required",
    ),
    (
        "fatal: unable to access 'https://gitlab.com/x/y.git/': Could not resolve host: gitlab.com",
        "Could not resolve the git host",
    ),
    (
        "fatal: unable to access 'https://gitlab.com/x/y/': Failed to connect to gitlab.com port 443: Network is unreachable",
        "Network unreachable",
    ),
    (
        "fatal: unable to access 'https://gitlab.com/x/y.git/': SSL certificate problem: unable to get local issuer certificate",
        "TLS certificate verification failed",
    ),
])
def test_git_stderr_maps_known_signatures(stderr: str, expected_hint: str) -> None:
    detail = _classify_git_stderr(stderr, exit_code=128)
    assert expected_hint in detail, (
        f"Expected {expected_hint!r} in classified message, got:\n{detail!r}"
    )


def test_git_stderr_falls_back_to_fatal_line() -> None:
    """When no pattern matches, the classifier keeps the ``fatal:`` line
    verbatim so the operator sees git's own root cause."""
    stderr = (
        "Cloning into 'target'...\n"
        "remote: Enumerating objects: 3, done.\n"
        "fatal: some brand-new-git-error we've never seen before"
    )
    detail = _classify_git_stderr(stderr, exit_code=128)
    assert "brand-new-git-error" in detail


def test_git_stderr_empty_output_still_returns_message() -> None:
    """An empty stderr (rare, but possible when git segfaults) must not
    yield an empty error string -- the operator would have nothing to
    act on. Include the exit code so the failure is not silent."""
    detail = _classify_git_stderr("", exit_code=137)
    assert "137" in detail


# ===========================================================================
# clone_repository -- unlimited timeout by default + classified failures
# ===========================================================================

def _fake_completed(returncode: int, stderr: str = "") -> subprocess.CompletedProcess:
    """Build a CompletedProcess without spawning a real subprocess."""
    return subprocess.CompletedProcess(
        args=["git"], returncode=returncode, stdout="", stderr=stderr
    )


def test_clone_passes_timeout_none_by_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """With `REPO_CLONE_TIMEOUT_SECONDS=0` (the shipped default),
    `subprocess.run` MUST receive `timeout=None` -- otherwise a slow
    clone can still be cancelled."""
    monkeypatch.setenv("REPO_CLONE_TIMEOUT_SECONDS", "0")
    monkeypatch.setenv("SCAN_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("ALLOWED_GIT_HOSTS", "github.com")
    get_settings.cache_clear()

    captured: dict = {}

    def _fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        # Simulate a successful clone by creating the destination dir.
        # The destination is the last element of `cmd`.
        Path(cmd[-1]).mkdir(parents=True, exist_ok=True)
        return _fake_completed(returncode=0)

    monkeypatch.setattr(repo_module.subprocess, "run", _fake_run)

    clone_repository("https://github.com/example/hello.git")

    assert captured["kwargs"]["timeout"] is None, (
        f"Expected timeout=None, got {captured['kwargs'].get('timeout')!r}"
    )


def test_clone_passes_positive_timeout_when_configured(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When an operator explicitly opts into a timeout, the scanner
    still honours it."""
    monkeypatch.setenv("REPO_CLONE_TIMEOUT_SECONDS", "45")
    monkeypatch.setenv("SCAN_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("ALLOWED_GIT_HOSTS", "github.com")
    get_settings.cache_clear()

    captured: dict = {}

    def _fake_run(cmd, **kwargs):
        captured["kwargs"] = kwargs
        Path(cmd[-1]).mkdir(parents=True, exist_ok=True)
        return _fake_completed(returncode=0)

    monkeypatch.setattr(repo_module.subprocess, "run", _fake_run)

    clone_repository("https://github.com/example/hello.git")

    assert captured["kwargs"]["timeout"] == 45.0


def test_clone_non_zero_exit_uses_classified_message(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A failing clone must surface the classified, human-readable
    reason (`Repository not found`, etc.) rather than a bare exit code."""
    monkeypatch.setenv("REPO_CLONE_TIMEOUT_SECONDS", "0")
    monkeypatch.setenv("SCAN_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("ALLOWED_GIT_HOSTS", "github.com")
    get_settings.cache_clear()

    stderr = (
        "remote: Repository not found.\n"
        "fatal: repository 'https://github.com/example/missing.git/' not found"
    )

    def _fake_run(cmd, **kwargs):
        return _fake_completed(returncode=128, stderr=stderr)

    monkeypatch.setattr(repo_module.subprocess, "run", _fake_run)

    with pytest.raises(RepositoryError) as excinfo:
        clone_repository("https://github.com/example/missing.git")

    assert "Repository not found" in str(excinfo.value)


def test_clone_missing_git_executable_produces_friendly_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A `FileNotFoundError` from `subprocess.run` (git not installed)
    must translate to a `RepositoryError` naming `GIT_PATH`."""
    monkeypatch.setenv("REPO_CLONE_TIMEOUT_SECONDS", "0")
    monkeypatch.setenv("SCAN_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("ALLOWED_GIT_HOSTS", "github.com")
    get_settings.cache_clear()

    def _fake_run(cmd, **kwargs):
        raise FileNotFoundError("git")

    monkeypatch.setattr(repo_module.subprocess, "run", _fake_run)

    with pytest.raises(RepositoryError) as excinfo:
        clone_repository("https://github.com/example/hello.git")

    assert "git executable not found" in str(excinfo.value)
    assert "GIT_PATH" in str(excinfo.value)


def test_clone_timeout_message_points_to_env_flag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """If an operator DID configure a positive timeout and it fires, the
    error must name the env var so they know how to unlimit it."""
    monkeypatch.setenv("REPO_CLONE_TIMEOUT_SECONDS", "30")
    monkeypatch.setenv("SCAN_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("ALLOWED_GIT_HOSTS", "github.com")
    get_settings.cache_clear()

    def _fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=30)

    monkeypatch.setattr(repo_module.subprocess, "run", _fake_run)

    with pytest.raises(RepositoryError) as excinfo:
        clone_repository("https://github.com/example/hello.git")

    message = str(excinfo.value)
    assert "30s" in message
    assert "REPO_CLONE_TIMEOUT_SECONDS" in message


# ===========================================================================
# run_semgrep -- unlimited timeout by default
# ===========================================================================

def test_semgrep_passes_timeout_none_by_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`SEMGREP_TIMEOUT_SECONDS=0` (the default) MUST reach
    `subprocess.run` as `timeout=None`."""
    monkeypatch.setenv("SEMGREP_TIMEOUT_SECONDS", "0")
    get_settings.cache_clear()

    # Give run_semgrep a target that exists.
    (tmp_path / "empty.py").write_text("# no crypto here\n", encoding="utf-8")

    captured: dict = {}
    fake_output = json.dumps({"results": [], "errors": [], "paths": {"scanned": []}})

    def _fake_run(cmd, **kwargs):
        captured["kwargs"] = kwargs
        return _fake_completed(returncode=0, stderr="") if False else subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout=fake_output, stderr=""
        )

    # semgrep.run_semgrep imports `subprocess` lazily inside the function,
    # so patch the global module rather than the scanner's attribute.
    monkeypatch.setattr("subprocess.run", _fake_run)
    # Skip the real executable resolution -- point at any real path; the
    # fake run() never actually launches it.
    monkeypatch.setattr(
        semgrep_module, "require_semgrep", lambda settings=None: tmp_path / "empty.py"
    )

    run_semgrep(tmp_path)

    assert captured["kwargs"]["timeout"] is None


def test_semgrep_passes_positive_timeout_when_configured(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SEMGREP_TIMEOUT_SECONDS", "600")
    get_settings.cache_clear()

    (tmp_path / "empty.py").write_text("# nothing\n", encoding="utf-8")

    captured: dict = {}
    fake_output = json.dumps({"results": [], "errors": [], "paths": {"scanned": []}})

    def _fake_run(cmd, **kwargs):
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout=fake_output, stderr=""
        )

    monkeypatch.setattr("subprocess.run", _fake_run)
    monkeypatch.setattr(
        semgrep_module, "require_semgrep", lambda settings=None: tmp_path / "empty.py"
    )

    run_semgrep(tmp_path)

    assert captured["kwargs"]["timeout"] == 600.0


def test_semgrep_timeout_message_points_to_env_flag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When an operator opts into a semgrep timeout and it fires, the
    error must name `SEMGREP_TIMEOUT_SECONDS` so they know how to lift
    it."""
    monkeypatch.setenv("SEMGREP_TIMEOUT_SECONDS", "60")
    get_settings.cache_clear()

    (tmp_path / "empty.py").write_text("# nothing\n", encoding="utf-8")

    def _fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=60)

    monkeypatch.setattr("subprocess.run", _fake_run)
    monkeypatch.setattr(
        semgrep_module, "require_semgrep", lambda settings=None: tmp_path / "empty.py"
    )

    with pytest.raises(SemgrepScanError) as excinfo:
        run_semgrep(tmp_path)

    message = str(excinfo.value)
    assert "60s" in message
    assert "SEMGREP_TIMEOUT_SECONDS" in message
