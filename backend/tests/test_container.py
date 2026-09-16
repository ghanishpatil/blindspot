"""Container image scanning tests.

The feature turns an image into a directory and reuses the existing scanners,
so the tests focus on the only new code: safe archive extraction (flatten
layers, reject path traversal / links / bombs) and the scan-endpoint wiring.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.scanner import container
from app.scanner.container import (
    ContainerError,
    _Budget,
    extract_image_archive,
    prepare_image,
    validate_image_ref,
)


# ── Helpers: build a synthetic 'docker save' archive ────────────────────────

def _layer_bytes(files: dict[str, bytes], *, symlink: str | None = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        if symlink is not None:
            link = tarfile.TarInfo(name=symlink)
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            tf.addfile(link)
    return buf.getvalue()


def _make_image_archive(path: Path, files: dict[str, bytes], *, symlink: str | None = None) -> None:
    layer = _layer_bytes(files, symlink=symlink)
    manifest = json.dumps([{"Layers": ["layer0/layer.tar"]}]).encode("utf-8")
    with tarfile.open(path, mode="w") as tf:
        for name, data in {"manifest.json": manifest, "layer0/layer.tar": layer}.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


# ── Extraction ──────────────────────────────────────────────────────────────

def test_extract_flattens_layer_files(tmp_path: Path) -> None:
    archive = tmp_path / "img.tar"
    _make_image_archive(archive, {"app/crypto.py": b"key = RSA.generate(2048)\n"})
    dest = tmp_path / "root"

    extract_image_archive(archive, dest)

    extracted = dest / "app" / "crypto.py"
    assert extracted.is_file()
    assert b"RSA.generate" in extracted.read_bytes()


def test_extract_rejects_path_traversal(tmp_path: Path) -> None:
    archive = tmp_path / "evil.tar"
    _make_image_archive(archive, {"../../escape.py": b"x", "safe.py": b"ok"})
    dest = tmp_path / "root"

    extract_image_archive(archive, dest)

    assert (dest / "safe.py").is_file()
    # The traversal entry must not have been written anywhere outside dest.
    assert not (tmp_path / "escape.py").exists()
    assert not (tmp_path.parent / "escape.py").exists()


def test_extract_skips_symlinks(tmp_path: Path) -> None:
    archive = tmp_path / "link.tar"
    _make_image_archive(archive, {"real.py": b"x"}, symlink="link")
    dest = tmp_path / "root"

    extract_image_archive(archive, dest)

    assert (dest / "real.py").is_file()
    assert not (dest / "link").exists()


def test_missing_archive_raises(tmp_path: Path) -> None:
    with pytest.raises(ContainerError):
        extract_image_archive(tmp_path / "nope.tar", tmp_path / "root")


# ── Budget (decompression-bomb guard) ───────────────────────────────────────

def test_budget_rejects_oversized_bytes() -> None:
    budget = _Budget(max_bytes=10, max_files=100)
    with pytest.raises(ContainerError):
        budget.charge(20)


def test_budget_rejects_too_many_files() -> None:
    budget = _Budget(max_bytes=10_000, max_files=2)
    budget.charge(1)
    budget.charge(1)
    with pytest.raises(ContainerError):
        budget.charge(1)


# ── Image reference validation ──────────────────────────────────────────────

def test_valid_image_refs_accepted() -> None:
    assert validate_image_ref("python:3.11-slim") == "python:3.11-slim"
    assert validate_image_ref("ghcr.io/org/app@sha256:deadbeef")


@pytest.mark.parametrize("bad", ["", "  ", "bad ref", "img; rm -rf /", "a|b", "$(x)"])
def test_invalid_image_refs_rejected(bad: str) -> None:
    with pytest.raises(ContainerError):
        validate_image_ref(bad)


# ── prepare_image guards ────────────────────────────────────────────────────

def test_prepare_image_requires_exactly_one() -> None:
    with pytest.raises(ContainerError):
        prepare_image()
    with pytest.raises(ContainerError):
        prepare_image(image_ref="python:3.11", archive_path="x.tar")


def test_prepare_image_ref_without_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(container, "_find_container_cli", lambda: None)
    with pytest.raises(ContainerError):
        prepare_image(image_ref="python:3.11-slim")


def test_pull_is_invoked_when_image_missing_locally(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """If ``docker image inspect`` fails, we run ``docker pull`` before ``save``.

    Fixes the real-world 'No such image' error: users typing an image ref no
    longer need to run ``docker pull`` themselves.
    """
    calls: list[list[str]] = []

    class _Result:
        def __init__(self, code: int) -> None:
            self.returncode = code
            self.stdout = ""
            self.stderr = ""

    def _fake_run(argv, settings, *, action):  # type: ignore[no-untyped-def]
        calls.append(argv)
        # inspect fails (image not local); pull + save succeed.
        if action == "inspect":
            return _Result(1)
        # 'save' must actually create the file so the caller doesn't error out.
        if action == "save":
            out = Path(argv[argv.index("-o") + 1])
            out.write_bytes(b"fake-tar")
        return _Result(0)

    monkeypatch.setattr(container, "_run_cli", _fake_run)
    monkeypatch.setattr(container, "_find_container_cli", lambda: "docker")

    from app.scanner.container import pull_image_to_archive

    tar = tmp_path / "out.tar"
    pull_image_to_archive("python:3.11-slim", tar)

    subcommands = [c[1] for c in calls]
    assert subcommands == ["image", "pull", "save"]


def test_pull_skipped_when_image_already_local(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """No wasteful re-pull when the image is already in the local cache."""
    calls: list[list[str]] = []

    class _Result:
        def __init__(self, code: int) -> None:
            self.returncode = code
            self.stdout = ""
            self.stderr = ""

    def _fake_run(argv, settings, *, action):  # type: ignore[no-untyped-def]
        calls.append(argv)
        if action == "save":
            out = Path(argv[argv.index("-o") + 1])
            out.write_bytes(b"fake-tar")
        return _Result(0)

    monkeypatch.setattr(container, "_run_cli", _fake_run)
    monkeypatch.setattr(container, "_find_container_cli", lambda: "docker")

    from app.scanner.container import pull_image_to_archive

    pull_image_to_archive("python:3.11-slim", tmp_path / "out.tar")
    subcommands = [c[1] for c in calls]
    assert "pull" not in subcommands
    assert subcommands == ["image", "save"]


# ── Reuse boundary: the extracted image is scannable by existing scanners ───

def test_extracted_image_is_scannable_by_dependency_parser(tmp_path: Path) -> None:
    """The flattened rootfs feeds the existing dependency parser unchanged —
    this is the whole point of the feature (no new detection logic)."""
    from app.scanner.dependency_parser import parse_dependencies

    archive = tmp_path / "app-image.tar"
    _make_image_archive(
        archive,
        {
            "srv/app/auth.py": b"from Crypto.PublicKey import RSA\nkey = RSA.generate(2048)\n",
            "srv/app/requirements.txt": b"pycryptodome==3.20.0\ncryptography==42.0.0\n",
        },
    )
    dest = tmp_path / "root"
    extract_image_archive(archive, dest)

    # The manifest inside the image layer is discovered and parsed like any repo.
    findings = parse_dependencies(dest)
    assert len(findings) >= 1
    joined = json.dumps(findings).lower()
    assert "pycryptodome" in joined or "cryptography" in joined
