"""Firebase Admin SDK initialisation.

The Admin SDK is initialised lazily and exactly once. If credentials are absent
or unreadable the backend still starts — it reports Firebase as unavailable
instead of crashing. That keeps Phase 1 runnable before a Firebase project
exists, and it means a credential problem in the demo surfaces as a clear
message rather than a failed boot.

Credentials are only ever read from the path in the environment. No key
material is embedded in source.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any

from app.config import Settings, get_settings

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_state: FirebaseState | None = None


@dataclass(frozen=True)
class FirebaseState:
    """Outcome of an initialisation attempt."""

    available: bool
    app: Any | None = None
    project_id: str | None = None
    storage_bucket: str | None = None
    reason: str | None = None
    """Why Firebase is unavailable. None when available."""


def _initialise(settings: Settings) -> FirebaseState:
    """Attempt a single Admin SDK initialisation."""
    if not settings.firebase_project_id:
        return FirebaseState(
            available=False,
            reason="FIREBASE_PROJECT_ID is not set.",
        )

    credentials_file = settings.credentials_file
    if credentials_file is None:
        return FirebaseState(
            available=False,
            reason="FIREBASE_CREDENTIALS_PATH is not set.",
        )
    if not credentials_file.is_file():
        return FirebaseState(
            available=False,
            reason=f"Service account file not found at {credentials_file}.",
        )

    try:
        import firebase_admin
        from firebase_admin import credentials as fb_credentials
    except ImportError as exc:  # pragma: no cover - dependency is declared
        return FirebaseState(
            available=False,
            reason=f"firebase-admin is not installed: {exc}",
        )

    options: dict[str, Any] = {"projectId": settings.firebase_project_id}
    if settings.firebase_storage_bucket:
        options["storageBucket"] = settings.firebase_storage_bucket

    try:
        # Reuse an already-initialised default app (e.g. under --reload).
        app = firebase_admin.get_app()
        logger.debug("Reusing existing Firebase app.")
    except ValueError:
        try:
            credential = fb_credentials.Certificate(str(credentials_file))
            app = firebase_admin.initialize_app(credential, options)
        except Exception as exc:  # noqa: BLE001 - report, never crash the app
            logger.warning("Firebase initialisation failed: %s", exc)
            return FirebaseState(
                available=False,
                reason=f"Firebase initialisation failed: {exc}",
            )

    logger.info("Firebase initialised for project %s.", settings.firebase_project_id)
    return FirebaseState(
        available=True,
        app=app,
        project_id=settings.firebase_project_id,
        storage_bucket=settings.firebase_storage_bucket,
    )


def get_firebase(settings: Settings | None = None) -> FirebaseState:
    """Return the shared Firebase state, initialising on first use."""
    global _state

    if _state is not None:
        return _state

    with _lock:
        if _state is None:
            _state = _initialise(settings or get_settings())
    return _state


def reset_firebase() -> None:
    """Clear cached state. Used by tests to force re-initialisation."""
    global _state
    with _lock:
        _state = None


def firebase_status(settings: Settings | None = None) -> dict[str, Any]:
    """Readiness detail for the health endpoint."""
    settings = settings or get_settings()
    state = get_firebase(settings)
    return {
        "available": state.available,
        "projectId": state.project_id,
        "storageBucket": state.storage_bucket,
        "reason": state.reason,
        "authBypassed": settings.auth_bypass_allowed(),
    }
