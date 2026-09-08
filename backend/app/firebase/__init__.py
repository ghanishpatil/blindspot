"""Firebase integration: authentication, Firestore, and Storage."""

from app.firebase.auth import (
    AuthenticatedUser,
    CurrentUser,
    get_current_user,
    verify_id_token,
)
from app.firebase.client import (
    FirebaseState,
    firebase_status,
    get_firebase,
    reset_firebase,
)
from app.firebase.firestore import (
    FirestoreRepository,
    FirestoreUnavailable,
    get_firestore,
    reset_firestore,
)
from app.firebase.storage import (
    StorageAdapter,
    StorageUnavailable,
    get_storage,
    reset_storage,
)

__all__ = [
    "AuthenticatedUser",
    "CurrentUser",
    "FirebaseState",
    "FirestoreRepository",
    "FirestoreUnavailable",
    "StorageAdapter",
    "StorageUnavailable",
    "firebase_status",
    "get_current_user",
    "get_firebase",
    "get_firestore",
    "get_storage",
    "reset_firebase",
    "reset_firestore",
    "reset_storage",
    "verify_id_token",
]
