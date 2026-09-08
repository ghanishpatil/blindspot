"""Firestore repository layer.

The rest of the application talks to Firestore only through this module, so the
document layout defined in the specification stays in one place and the
persistence stage (Phase 10) has a single seam to implement against.

Every method degrades explicitly: when Firebase is unavailable the repository
raises :class:`FirestoreUnavailable` rather than returning silently-empty
results, so a persistence failure can never be mistaken for "no findings".
"""

from __future__ import annotations

import logging
from typing import Any

from app.config import Settings, get_settings
from app.firebase.client import get_firebase

logger = logging.getLogger(__name__)

# Collection names, per the specification's data model.
USERS = "users"
PROJECTS = "projects"
SCANS = "scans"
FINDINGS = "findings"


class FirestoreUnavailable(RuntimeError):
    """Raised when a Firestore operation is attempted without a working client."""


class FirestoreRepository:
    """Thin, typed wrapper over the Firestore document API."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._client: Any | None = None

    # --- lifecycle --------------------------------------------------------
    @property
    def available(self) -> bool:
        """True when a Firestore client can be obtained."""
        return get_firebase(self._settings).available

    def _require_client(self) -> Any:
        state = get_firebase(self._settings)
        if not state.available:
            raise FirestoreUnavailable(
                f"Firestore is unavailable: {state.reason}"
            )
        if self._client is None:
            from firebase_admin import firestore as fb_firestore

            self._client = fb_firestore.client(app=state.app)
        return self._client

    # --- generic document operations -------------------------------------
    def set_document(
        self,
        collection: str,
        document_id: str,
        data: dict[str, Any],
        *,
        merge: bool = False,
    ) -> str:
        """Write a document and return its ID."""
        client = self._require_client()
        client.collection(collection).document(document_id).set(data, merge=merge)
        return document_id

    def add_document(self, collection: str, data: dict[str, Any]) -> str:
        """Create a document with a generated ID and return that ID."""
        client = self._require_client()
        _, reference = client.collection(collection).add(data)
        return str(reference.id)

    def get_document(self, collection: str, document_id: str) -> dict[str, Any] | None:
        """Fetch one document, or None when it does not exist."""
        client = self._require_client()
        snapshot = client.collection(collection).document(document_id).get()
        if not snapshot.exists:
            return None
        payload = snapshot.to_dict() or {}
        payload["id"] = snapshot.id
        return payload

    def query_documents(
        self,
        collection: str,
        *,
        filters: dict[str, Any] | None = None,
        limit: int | None = None,
        order_by: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch documents matching simple equality filters."""
        client = self._require_client()
        query: Any = client.collection(collection)

        for field, value in (filters or {}).items():
            query = query.where(field, "==", value)
        if order_by:
            query = query.order_by(order_by)
        if limit:
            query = query.limit(limit)

        results: list[dict[str, Any]] = []
        for snapshot in query.stream():
            payload = snapshot.to_dict() or {}
            payload["id"] = snapshot.id
            results.append(payload)
        return results

    def write_batch(
        self, collection: str, documents: dict[str, dict[str, Any]]
    ) -> int:
        """Write many documents in one batch. Returns the number written.

        Findings are written per scan, so batching keeps a scan's persistence
        to a small number of round trips.
        """
        if not documents:
            return 0

        client = self._require_client()
        batch = client.batch()
        collection_ref = client.collection(collection)

        for document_id, data in documents.items():
            batch.set(collection_ref.document(document_id), data)
        batch.commit()
        return len(documents)


_repository: FirestoreRepository | None = None


def get_firestore(settings: Settings | None = None) -> FirestoreRepository:
    """Shared repository instance, suitable as a FastAPI dependency."""
    global _repository
    if _repository is None:
        _repository = FirestoreRepository(settings)
    return _repository


def reset_firestore() -> None:
    """Clear the cached repository. Used by tests."""
    global _repository
    _repository = None
