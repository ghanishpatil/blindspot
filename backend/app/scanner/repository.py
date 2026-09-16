"""Repository URL ingestion — clone a remote git repository for scanning.

A user-supplied repository URL is cloned by the server, which makes this an
**SSRF-sensitive boundary**. Every URL is validated strictly before any network
access:

* HTTPS only — no ``file://``, ``git://``, ``ssh://``, or ``http://``.
* Host must be on the configured allowlist (exact host or a subdomain of one).
* IP-literal hosts are rejected (blocks direct access to internal addresses).
* ``localhost`` and obvious internal suffixes are rejected.

The clone is shallow (``--depth 1``) into a fresh temporary directory. Use
:func:`cloned_repository` as a context manager so the clone is always removed,
even on failure.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlparse

from app.config import Settings, get_settings

logger = logging.getLogger(__name__)


def remove_clone(path: Path) -> None:
    """Remove a cloned repository directory, robustly.

    On Windows, git writes read-only files under ``.git`` (pack/object files).
    A plain ``shutil.rmtree`` fails on them, and ``ignore_errors=True`` would
    silently leak the directory. This handler clears the read-only bit and
    retries, so cleanup actually completes.
    """
    if not path or not Path(path).exists():
        return

    def _on_error(func, target, _exc_info):  # type: ignore[no-untyped-def]
        try:
            os.chmod(target, stat.S_IWRITE)
            func(target)
        except OSError:
            logger.warning("Could not remove %s during clone cleanup.", target)

    # `onerror` is correct for Python 3.10/3.11 (the pinned runtime). On 3.12+
    # it is deprecated in favour of `onexc` but still functions.
    shutil.rmtree(path, onerror=_on_error)


class RepositoryError(ValueError):
    """Raised when a repository URL is invalid or a clone fails.

    Subclasses ``ValueError`` for convenience, so callers that already handle
    validation errors keep working. Note: any internal ``ValueError`` checks in
    this module must be written so they do NOT accidentally catch this subclass.
    """


def _is_ip_literal(host: str) -> bool:
    """True when *host* is an IPv4/IPv6 literal (not a domain name)."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def validate_repository_url(url: str, settings: Settings | None = None) -> str:
    """Validate a repository URL against the SSRF policy.

    Returns the cleaned URL when valid; raises :class:`RepositoryError` otherwise.
    Performs no network access.
    """
    settings = settings or get_settings()

    if not url or not url.strip():
        raise RepositoryError("Repository URL is empty.")
    cleaned = url.strip()

    parsed = urlparse(cleaned)

    # Scheme: HTTPS only.
    if parsed.scheme.lower() != "https":
        raise RepositoryError(
            f"Only HTTPS repository URLs are allowed (got scheme "
            f"{parsed.scheme or '(none)'!r})."
        )

    host = (parsed.hostname or "").lower()
    if not host:
        raise RepositoryError("Repository URL has no host.")

    # Reject IP-literal hosts (checked outside the try so a RepositoryError
    # raised here is never swallowed by an except ValueError).
    if _is_ip_literal(host):
        raise RepositoryError("IP-address hosts are not allowed.")

    # Reject obvious internal names.
    if host == "localhost" or host.endswith(".local") or host.endswith(".internal"):
        raise RepositoryError(f"Internal host {host!r} is not allowed.")

    # Allowlist: exact host or a subdomain of an allowed host.
    allowlist = settings.git_host_allowlist
    if not any(host == allowed or host.endswith("." + allowed) for allowed in allowlist):
        raise RepositoryError(
            f"Host {host!r} is not permitted. Allowed hosts: {', '.join(allowlist)}."
        )

    # Path sanity: must reference something (owner/repo), not just the host root.
    if not parsed.path or parsed.path.strip("/") == "":
        raise RepositoryError("Repository URL is missing a repository path.")

    return cleaned


def clone_repository(url: str, settings: Settings | None = None) -> Path:
    """Validate and shallow-clone *url* into a fresh temporary directory.

    Returns the path to the clone. Raises :class:`RepositoryError` on any
    validation or clone failure (and cleans up a partial clone on failure).
    The caller owns the returned directory and must remove it; prefer
    :func:`cloned_repository` which handles cleanup automatically.
    """
    settings = settings or get_settings()
    validated = validate_repository_url(url, settings)

    work_base = settings.scan_work
    work_base.mkdir(parents=True, exist_ok=True)
    dest = Path(tempfile.mkdtemp(prefix="ecdat-scan-", dir=str(work_base)))
    cmd = [
        settings.git_path,
        "clone",
        "--depth",
        str(settings.git_clone_depth),
        "--single-branch",
        "--no-tags",
        validated,
        str(dest),
    ]
    logger.info("Cloning %s -> %s", validated, dest)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=settings.repo_clone_timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        remove_clone(dest)
        raise RepositoryError(
            f"Clone timed out after {settings.repo_clone_timeout_seconds}s."
        ) from exc
    except FileNotFoundError as exc:
        remove_clone(dest)
        raise RepositoryError(
            f"git executable not found (configured as {settings.git_path!r}). "
            "Install git or set GIT_PATH."
        ) from exc

    if proc.returncode != 0:
        remove_clone(dest)
        stderr = (proc.stderr or "").strip()[:500]
        raise RepositoryError(
            f"git clone failed (exit {proc.returncode}): {stderr or 'no error output'}"
        )

    return dest


@contextmanager
def cloned_repository(url: str, settings: Settings | None = None) -> Iterator[Path]:
    """Clone *url*, yield the local path, and always remove the clone afterwards."""
    dest = clone_repository(url, settings)
    try:
        yield dest
    finally:
        remove_clone(dest)
        logger.info("Removed clone directory %s", dest)
