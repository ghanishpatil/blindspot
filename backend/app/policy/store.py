"""File-backed storage for the workspace's active policy.

The policy that ``blindspot-scan gate`` evaluates in CI can also be
managed from the dashboard. This module owns that lifecycle: writing
validated JSON to disk on ``PUT /api/policy``, reading it on
``GET /api/policy``, and reverting to the built-in default on
``POST /api/policy/reset``.

Design rules:

* **Single active policy per install.** The store is not multi-tenant
  yet -- one policy JSON file lives at
  ``settings.artifacts / policy.json``. Multi-project support lands
  when the API grows a ``project_id`` scope.
* **Validate before write.** We never persist a raw dict; the store
  goes through :func:`app.cli.policy.parse_policy_dict` first. A
  malformed policy is rejected at the API layer and never touches
  disk.
* **Atomic writes.** We write to ``policy.json.tmp`` then rename, so
  a crash mid-write cannot leave a truncated file that later fails
  to parse.
* **Missing file = default.** A fresh install returns
  :data:`app.cli.policy.DEFAULT_POLICY` from :meth:`PolicyStore.get`;
  the caller cannot distinguish "no override set" from "default was
  explicitly saved" -- both are semantically identical.

The store is deliberately synchronous: policy files are tiny (< 4 KB)
and read/write frequency is low. Async I/O would be pure ceremony.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from threading import Lock
from typing import Any

from app.cli.policy import (
    DEFAULT_POLICY,
    Policy,
    PolicyError,
    parse_policy_dict,
    policy_to_dict,
)


# Filename on disk. Kept as a module constant so tests can reference
# it symbolically instead of hard-coding the string.
ACTIVE_POLICY_FILENAME = "policy.json"


class PolicyStore:
    """Persistence for the active policy.

    Instances are cheap to construct and cheap to keep -- the object
    holds only the target directory and a per-instance lock that
    serialises writes on this process. Cross-process safety is
    provided by the atomic rename step in :meth:`save`.
    """

    def __init__(self, directory: Path) -> None:
        self.directory: Path = Path(directory)
        self._lock: Lock = Lock()

    @property
    def path(self) -> Path:
        """Absolute path to ``policy.json`` in the store's directory."""
        return self.directory / ACTIVE_POLICY_FILENAME

    # -- Read ------------------------------------------------------------

    def get(self) -> Policy:
        """Return the active :class:`Policy`.

        Falls back to :data:`DEFAULT_POLICY` when the file is missing.
        Raises :class:`PolicyError` when the file exists but is
        corrupt -- callers turn that into HTTP 500 rather than
        silently masking a real corruption event.
        """
        if not self.path.is_file():
            return DEFAULT_POLICY
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PolicyError(
                f"active policy file is unreadable: {self.path}: {exc}"
            ) from exc
        return parse_policy_dict(raw)

    def has_override(self) -> bool:
        """True when an explicit policy has been persisted.

        Distinguishes "user has customised" from "we're using the
        built-in default" in the API response, without changing what
        :meth:`get` returns.
        """
        return self.path.is_file()

    # -- Write -----------------------------------------------------------

    def save(self, raw: dict[str, Any]) -> Policy:
        """Validate *raw* and persist it. Returns the parsed policy.

        Two-step to keep the store honest:
        1. :func:`parse_policy_dict` -- raises on any schema violation.
        2. Atomic write via ``NamedTemporaryFile`` + :func:`os.replace`.

        Concurrent saves on the same process are serialised through a
        lock; concurrent saves across processes rely on
        :func:`os.replace` being atomic on the same filesystem.
        """
        policy = parse_policy_dict(raw)
        canonical = policy_to_dict(policy)
        payload = json.dumps(canonical, indent=2, ensure_ascii=False) + "\n"

        self.directory.mkdir(parents=True, exist_ok=True)
        with self._lock:
            # NamedTemporaryFile in the target directory guarantees
            # os.replace() is a same-filesystem rename (atomic on POSIX
            # and Windows) rather than a cross-device copy that could
            # tear.
            tmp = tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(self.directory),
                prefix=".policy-",
                suffix=".tmp",
                delete=False,
            )
            try:
                tmp.write(payload)
                tmp.flush()
                os.fsync(tmp.fileno())
                tmp.close()
                os.replace(tmp.name, self.path)
            except Exception:
                # Best-effort cleanup of the temp file on any error.
                try:
                    os.unlink(tmp.name)
                except OSError:
                    pass
                raise
        return policy

    def reset(self) -> Policy:
        """Delete the override file. Next :meth:`get` returns default.

        Idempotent: calling ``reset()`` twice is fine. Returns
        :data:`DEFAULT_POLICY` so callers can respond with the state
        they should now show the user.
        """
        with self._lock:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
        return DEFAULT_POLICY


# ---------------------------------------------------------------------------
# Default-store accessor -- used by the API endpoint layer.
# ---------------------------------------------------------------------------

_default_store: PolicyStore | None = None
_default_store_lock = Lock()


def get_default_store() -> PolicyStore:
    """Process-wide singleton store rooted at ``settings.artifacts``.

    Deferred import of :mod:`app.config` so unit tests that stub the
    store can avoid loading settings.
    """
    global _default_store
    if _default_store is not None:
        return _default_store
    with _default_store_lock:
        if _default_store is None:
            from app.config import get_settings

            settings = get_settings()
            _default_store = PolicyStore(directory=settings.artifacts)
        return _default_store


def _reset_default_store_for_tests() -> None:
    """Test helper: clear the singleton so each test can rebind it."""
    global _default_store
    with _default_store_lock:
        _default_store = None


__all__ = [
    "ACTIVE_POLICY_FILENAME",
    "PolicyStore",
    "get_default_store",
    "_reset_default_store_for_tests",
]
