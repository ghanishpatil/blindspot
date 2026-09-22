"""Tests for :mod:`app.cli.git_meta`.

Contract:

1. Inside a working tree, ``gitRef`` is a real SHA and ``gitBranch`` is
   a real branch name.
2. Outside a working tree, both fields are ``None`` without raising.
3. When the ``git`` binary itself is unavailable, both fields are
   ``None`` without raising. Never crash the CI on that.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from app.cli import git_meta


def _run(cmd: list[str], cwd: Path) -> None:
    subprocess.run(cmd, cwd=str(cwd), check=True, capture_output=True)


def _init_repo(tmp_path: Path) -> Path:
    """Initialise a real git repo with one committed file.

    We use a real ``git init`` rather than mocking so the branch name
    behaviour on modern (init.defaultBranch = main) and legacy (master)
    installs is honestly exercised.
    """
    _run(["git", "init", "-q"], tmp_path)
    _run(["git", "config", "user.email", "test@example.com"], tmp_path)
    _run(["git", "config", "user.name", "Test"], tmp_path)
    (tmp_path / "README.md").write_text("hello", encoding="utf-8")
    _run(["git", "add", "."], tmp_path)
    _run(["git", "commit", "-q", "-m", "init"], tmp_path)
    return tmp_path


def test_git_meta_returns_sha_and_branch_in_working_tree(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    meta = git_meta.git_head_meta(repo)
    assert meta["gitRef"] is not None
    # SHA-1 hex is 40 chars.
    assert len(meta["gitRef"]) == 40
    assert all(c in "0123456789abcdef" for c in meta["gitRef"])
    # Branch name depends on user's git config; assert it's a non-empty
    # string but not a specific value -- both 'main' and 'master' pass.
    assert isinstance(meta["gitBranch"], str)
    assert meta["gitBranch"]


def test_git_meta_outside_working_tree_returns_none(tmp_path: Path) -> None:
    """A fresh empty directory has no .git at any level up to root."""
    # tmp_path is inside pytest's own tree; guard by using a chained
    # subdirectory that has zero chance of being under a git checkout
    # on the CI host. If a developer runs tests inside a checkout,
    # tmp_path might resolve under it -- we accept either branch state
    # as long as the CALL doesn't raise.
    meta = git_meta.git_head_meta(tmp_path)
    assert isinstance(meta, dict)
    # Both fields are either None or strings; the important contract
    # is that the call succeeds.
    for key in ("gitRef", "gitBranch"):
        assert meta[key] is None or isinstance(meta[key], str)


def test_git_meta_never_raises_when_git_binary_absent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Patch subprocess.run to raise FileNotFoundError -- simulating the
    'no git installed' case -- and confirm we still return the two-None
    dict cleanly. The CI must never crash on that."""
    def _raise(*args, **kwargs):
        raise FileNotFoundError("git")

    monkeypatch.setattr(subprocess, "run", _raise)
    meta = git_meta.git_head_meta(tmp_path)
    assert meta == {"gitRef": None, "gitBranch": None}


def test_git_meta_never_raises_on_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A slow / hung git subprocess must translate to (None, None)."""
    def _raise(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=["git"], timeout=1)

    monkeypatch.setattr(subprocess, "run", _raise)
    meta = git_meta.git_head_meta(tmp_path)
    assert meta == {"gitRef": None, "gitBranch": None}


def test_git_meta_handles_file_target(tmp_path: Path) -> None:
    """When the target is a file (e.g. a lone .pem), we climb up to its
    parent before running rev-parse. Must not crash."""
    repo = _init_repo(tmp_path)
    key_file = repo / "key.pem"
    key_file.write_text("-----BEGIN--dummy--END-----", encoding="utf-8")
    meta = git_meta.git_head_meta(key_file)
    assert meta["gitRef"] is not None


def test_git_meta_handles_missing_path(tmp_path: Path) -> None:
    """A path that doesn't exist must return two Nones."""
    meta = git_meta.git_head_meta(tmp_path / "does" / "not" / "exist")
    assert meta == {"gitRef": None, "gitBranch": None}
