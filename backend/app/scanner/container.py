"""Container image ingestion — turn an image into a scannable directory.

A container image is a stack of filesystem layers (each a tar), plus metadata.
Once the layers are flattened into a directory, that directory contains the
same source files, dependency manifests, and binaries a repository would — so
the **existing** source and dependency scanners run against it unchanged. This
module's only job is *"given an image, produce a directory"*; everything
downstream is reused.

Two acquisition paths:

* **Archive** — a ``docker save`` / OCI ``docker-archive`` tarball on disk
  (offline, fully deterministic, the reliable path for a demo).
* **Reference** — pull ``name:tag`` using a container CLI already on the host
  (``docker`` / ``podman`` / ``nerdctl``), best-effort. Absent a CLI, this
  raises a clear error rather than pretending.

Security: image layers are **untrusted archives**. Extraction is done
member-by-member with guards against path traversal (zip-slip), symlink/hardlink
escape, special files, and decompression bombs (byte and file-count budgets).
This mirrors the defensive posture applied to the git-clone SSRF boundary.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import tarfile
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from app.config import Settings, get_settings
from app.scanner.repository import remove_clone  # robust rmtree (handles Windows RO)

logger = logging.getLogger(__name__)

# Container CLIs we know how to drive, in preference order. Each supports
# `<cli> save <ref> -o <tarpath>` producing a docker-archive tarball.
_KNOWN_CLIS = ("docker", "podman", "nerdctl")

# A permissive-but-safe image reference: registry/host, path, :tag, @sha256 digest.
_IMAGE_REF_RE = re.compile(r"^[A-Za-z0-9._:/@-]{1,512}$")


class ContainerError(ValueError):
    """Raised when an image cannot be acquired or safely extracted."""


# ═══════════════════════════════════════════════════════════════════════════
# Safe tar extraction
# ═══════════════════════════════════════════════════════════════════════════

class _Budget:
    """Tracks cumulative extraction size / file count to stop decompression bombs."""

    def __init__(self, max_bytes: int, max_files: int) -> None:
        self.max_bytes = max_bytes
        self.max_files = max_files
        self.bytes = 0
        self.files = 0

    def charge(self, size: int) -> None:
        self.bytes += max(0, size)
        self.files += 1
        if self.bytes > self.max_bytes:
            raise ContainerError(
                f"Image exceeds the extraction size limit ({self.max_bytes} bytes). "
                "Refusing to continue (possible decompression bomb)."
            )
        if self.files > self.max_files:
            raise ContainerError(
                f"Image exceeds the extraction file-count limit ({self.max_files})."
            )


def _is_within(base: Path, target: Path) -> bool:
    """True when *target* resolves to a path inside *base*."""
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except (ValueError, OSError):
        return False


def _extract_tar_safely(tar: tarfile.TarFile, dest: Path, budget: _Budget) -> None:
    """Extract regular files and directories from *tar* into *dest*, safely.

    Skips symlinks, hardlinks, and special files (they are the vectors for
    escaping the destination). Rejects any member whose path would land outside
    *dest*. Applies the byte/file budget.
    """
    dest.mkdir(parents=True, exist_ok=True)
    for member in tar:
        name = member.name
        # Whiteout markers (layer deletions) are irrelevant to scanning.
        base = name.rsplit("/", 1)[-1]
        if base.startswith(".wh."):
            continue

        target = dest / name
        if not _is_within(dest, target):
            logger.warning("Skipping image entry outside root: %s", name)
            continue

        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
            continue

        if member.issym() or member.islnk():
            # Links can point outside the tree; a scanner only needs real files.
            continue

        if not member.isfile():
            # Devices, FIFOs, etc. — not scannable, skip.
            continue

        budget.charge(member.size)
        target.parent.mkdir(parents=True, exist_ok=True)
        extracted = tar.extractfile(member)
        if extracted is None:
            continue
        with open(target, "wb") as handle:
            shutil.copyfileobj(extracted, handle, length=1024 * 256)


def _layer_paths_from_manifest(work: Path) -> list[Path]:
    """Return ordered layer-tar paths from a docker-save ``manifest.json``.

    Falls back to any ``layer.tar`` / ``*.tar`` files found when there is no
    manifest (best-effort for non-standard archives).
    """
    manifest = work / "manifest.json"
    if manifest.is_file():
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
            layers = data[0].get("Layers", []) if isinstance(data, list) and data else []
            paths = [work / layer for layer in layers if isinstance(layer, str)]
            paths = [p for p in paths if p.is_file()]
            if paths:
                return paths
        except (ValueError, KeyError, IndexError, OSError) as exc:
            logger.warning("Could not read manifest.json, falling back: %s", exc)

    # Fallback: OCI blobs or loose layer tars, sorted for determinism.
    candidates = sorted(
        p for p in work.rglob("*")
        if p.is_file() and (p.name == "layer.tar" or p.suffix == ".tar" or "blobs" in p.parts)
    )
    return candidates


def extract_image_archive(archive_path: Path, dest_root: Path, settings: Settings | None = None) -> Path:
    """Flatten a docker-save / OCI image archive into *dest_root* and return it.

    Layers are applied in order (later layers overlay earlier ones), matching how
    a container's filesystem is assembled.
    """
    settings = settings or get_settings()
    archive_path = Path(archive_path)
    if not archive_path.is_file():
        raise ContainerError(f"Image archive not found: {archive_path.name}")

    max_bytes = int(settings.container_max_extract_mb) * 1024 * 1024
    budget = _Budget(max_bytes=max_bytes, max_files=300_000)

    dest_root = Path(dest_root)
    dest_root.mkdir(parents=True, exist_ok=True)

    work_base = settings.scan_work
    work_base.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ecdat-img-work-", dir=str(work_base)) as work_str:
        work = Path(work_str)
        # 1) Unpack the outer archive (contains manifest.json + layer tars).
        try:
            with tarfile.open(archive_path, mode="r:*") as outer:
                _extract_tar_safely(outer, work, budget)
        except tarfile.TarError as exc:
            raise ContainerError(f"Not a readable image archive: {exc}") from exc

        # 2) Apply each layer tar into the flattened rootfs.
        layer_paths = _layer_paths_from_manifest(work)
        if not layer_paths:
            raise ContainerError(
                "No layers found in the image archive. Expected a 'docker save' "
                "or OCI docker-archive tarball."
            )
        for layer in layer_paths:
            try:
                with tarfile.open(layer, mode="r:*") as layer_tar:
                    _extract_tar_safely(layer_tar, dest_root, budget)
            except tarfile.TarError as exc:
                logger.warning("Skipping unreadable layer %s: %s", layer.name, exc)

    logger.info(
        "Flattened image archive into %s (%d files, %d bytes).",
        dest_root, budget.files, budget.bytes,
    )
    return dest_root


# ═══════════════════════════════════════════════════════════════════════════
# Reference pull (best-effort, requires a container CLI on the host)
# ═══════════════════════════════════════════════════════════════════════════

def validate_image_ref(image_ref: str) -> str:
    """Validate an image reference's shape. Raises :class:`ContainerError`."""
    if not image_ref or not image_ref.strip():
        raise ContainerError("Image reference is empty.")
    cleaned = image_ref.strip()
    if not _IMAGE_REF_RE.match(cleaned):
        raise ContainerError("Image reference contains invalid characters.")
    return cleaned


def _find_container_cli() -> str | None:
    """Return the first available container CLI on PATH, or None."""
    for cli in _KNOWN_CLIS:
        if shutil.which(cli):
            return cli
    return None


def _run_cli(
    argv: list[str], settings: Settings, *, action: str
) -> subprocess.CompletedProcess[str]:
    """Run a container-CLI subcommand with the configured timeout."""
    try:
        return subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=settings.container_cli_timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise ContainerError(
            f"Image {action} timed out after {settings.container_cli_timeout_seconds}s."
        ) from exc


def pull_image_to_archive(
    image_ref: str, tar_path: Path, settings: Settings | None = None
) -> Path:
    """Ensure *image_ref* is present locally, then save it as a docker-archive tar.

    Two steps, because ``docker save`` only exports images already in the local
    cache. We check for local presence first (cheap), pull if missing (slow but
    unavoidable), then save. Raises :class:`ContainerError` on any failure with
    a message that says which step failed and why.
    """
    settings = settings or get_settings()
    validated = validate_image_ref(image_ref)
    cli = _find_container_cli()
    if cli is None:
        raise ContainerError(
            "No container CLI (docker/podman/nerdctl) is available to pull an image "
            "reference. Provide a saved image archive instead."
        )

    # 1) Is the image already local? `image inspect` exits 0 iff yes.
    inspect = _run_cli([cli, "image", "inspect", validated], settings, action="inspect")
    if inspect.returncode != 0:
        # Not local — pull it. This is the step that can take real time.
        logger.info("Image %s not in local cache; pulling via %s ...", validated, cli)
        pull = _run_cli([cli, "pull", validated], settings, action="pull")
        if pull.returncode != 0:
            stderr = (pull.stderr or pull.stdout or "").strip()[:400]
            raise ContainerError(
                f"Image pull failed ({cli}): {stderr or 'unknown error'}. "
                "Verify the image reference and that the container daemon is running."
            )

    # 2) Save the (now local) image to a tarball.
    logger.info("Saving image %s via %s", validated, cli)
    save = _run_cli([cli, "save", validated, "-o", str(tar_path)], settings, action="save")
    if save.returncode != 0:
        stderr = (save.stderr or save.stdout or "").strip()[:400]
        raise ContainerError(f"Image save failed ({cli}): {stderr or 'unknown error'}")
    if not tar_path.is_file():
        raise ContainerError("Image save produced no archive.")
    return tar_path


def prepare_image(
    *,
    image_ref: str | None = None,
    archive_path: str | Path | None = None,
    settings: Settings | None = None,
) -> tuple[Path, Path | None]:
    """Produce a flattened, scannable rootfs directory for an image.

    Returns ``(root_dir, tmp_tar)``. The caller owns both and must remove them
    (``tmp_tar`` is ``None`` when scanning an existing archive). Exactly one of
    *image_ref* or *archive_path* must be given. Prefer :func:`prepared_image_dir`
    when a context manager fits.
    """
    settings = settings or get_settings()
    if not settings.container_scan_enabled:
        raise ContainerError("Container scanning is disabled by configuration.")
    if bool(image_ref) == bool(archive_path):
        raise ContainerError("Provide exactly one of an image reference or an image archive.")

    work_base = settings.scan_work
    work_base.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="ecdat-img-root-", dir=str(work_base)))
    tmp_tar: Path | None = None
    try:
        if archive_path is not None:
            source = Path(archive_path)
        else:
            tmp_tar = root.parent / f"{root.name}.tar"
            source = pull_image_to_archive(str(image_ref), tmp_tar, settings)
        extract_image_archive(source, root, settings)
    except Exception:
        # Clean up partial work before propagating.
        remove_clone(root)
        if tmp_tar is not None and tmp_tar.exists():
            try:
                tmp_tar.unlink()
            except OSError:
                pass
        raise
    return root, tmp_tar


@contextmanager
def prepared_image_dir(
    *,
    image_ref: str | None = None,
    archive_path: str | Path | None = None,
    settings: Settings | None = None,
) -> Iterator[Path]:
    """Yield a flattened, scannable rootfs directory for an image, then clean up."""
    root, tmp_tar = prepare_image(
        image_ref=image_ref, archive_path=archive_path, settings=settings
    )
    try:
        yield root
    finally:
        remove_clone(root)
        if tmp_tar is not None and tmp_tar.exists():
            try:
                tmp_tar.unlink()
            except OSError:
                logger.warning("Could not remove temporary image tar %s", tmp_tar)
