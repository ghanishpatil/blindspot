"""Firebase Storage adapter for generated artefacts.

Firestore holds queryable metadata; Storage holds generated files. Layout per
the specification:

    projects/{projectId}/scans/{scanId}/cbom.json
    projects/{projectId}/scans/{scanId}/raw-findings.json
    projects/{projectId}/scans/{scanId}/report.json

Uploads always also land in the local artefacts directory. That gives the demo a
working CBOM export path even if Storage is unreachable, and it is what the
cached fallback mode reads from.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from app.config import Settings, get_settings
from app.firebase.client import get_firebase

logger = logging.getLogger(__name__)

CBOM_FILENAME = "cbom.json"
RAW_FINDINGS_FILENAME = "raw-findings.json"
REPORT_FILENAME = "report.json"


class StorageUnavailable(RuntimeError):
    """Raised when a Storage operation is attempted without a working bucket."""


def scan_prefix(project_id: str, scan_id: str) -> str:
    """Storage path prefix for one scan's artefacts."""
    return f"projects/{project_id}/scans/{scan_id}"


class StorageAdapter:
    """Uploads and retrieves generated scan artefacts."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._bucket: Any | None = None

    @property
    def available(self) -> bool:
        """True when a Storage bucket is configured and Firebase initialised."""
        state = get_firebase(self._settings)
        return state.available and bool(self._settings.firebase_storage_bucket)

    def _require_bucket(self) -> Any:
        state = get_firebase(self._settings)
        if not state.available:
            raise StorageUnavailable(f"Firebase is unavailable: {state.reason}")
        if not self._settings.firebase_storage_bucket:
            raise StorageUnavailable("FIREBASE_STORAGE_BUCKET is not set.")
        if self._bucket is None:
            from firebase_admin import storage as fb_storage

            self._bucket = fb_storage.bucket(
                self._settings.firebase_storage_bucket, app=state.app
            )
        return self._bucket

    # --- local artefacts --------------------------------------------------
    def local_path(self, project_id: str, scan_id: str, filename: str) -> Path:
        """Local mirror path for an artefact."""
        return self._settings.artifacts / project_id / scan_id / filename

    def write_local(
        self, project_id: str, scan_id: str, filename: str, content: str
    ) -> Path:
        """Write an artefact to the local artefacts directory."""
        destination = self.local_path(project_id, scan_id, filename)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
        return destination

    # --- remote artefacts -------------------------------------------------
    def upload_text(
        self,
        project_id: str,
        scan_id: str,
        filename: str,
        content: str,
        *,
        content_type: str = "application/json",
    ) -> dict[str, Any]:
        """Write locally, then upload to Storage when it is available.

        Returns a result describing both destinations so callers — and the UI —
        can tell exactly where the artefact ended up.
        """
        local = self.write_local(project_id, scan_id, filename, content)
        result: dict[str, Any] = {
            "localPath": str(local),
            "storagePath": None,
            "uploaded": False,
            "reason": None,
        }

        if not self.available:
            state = get_firebase(self._settings)
            result["reason"] = (
                state.reason or "FIREBASE_STORAGE_BUCKET is not set."
            )
            logger.info("Storage upload skipped: %s", result["reason"])
            return result

        remote_path = f"{scan_prefix(project_id, scan_id)}/{filename}"
        try:
            blob = self._require_bucket().blob(remote_path)
            blob.upload_from_string(content, content_type=content_type)
        except Exception as exc:  # noqa: BLE001 - never fail a scan on upload
            result["reason"] = f"Storage upload failed: {exc}"
            logger.warning("Storage upload failed for %s: %s", remote_path, exc)
            return result

        result["storagePath"] = remote_path
        result["uploaded"] = True
        return result

    def download_text(self, remote_path: str) -> str:
        """Download an artefact's contents from Storage."""
        blob = self._require_bucket().blob(remote_path)
        if not blob.exists():
            raise StorageUnavailable(f"No object at {remote_path}.")
        return blob.download_as_text()


_adapter: StorageAdapter | None = None


def get_storage(settings: Settings | None = None) -> StorageAdapter:
    """Shared storage adapter, suitable as a FastAPI dependency."""
    global _adapter
    if _adapter is None:
        _adapter = StorageAdapter(settings)
    return _adapter


def reset_storage() -> None:
    """Clear the cached adapter. Used by tests."""
    global _adapter
    _adapter = None
