# ARTEFACT 9 — WEAK CRYPTO TODAY (SHA-1)
# SHA-1 digests used to verify partner drop manifests.
#
# Added for BUILD SPEC section 9 algorithm coverage (SHA-1).
#
# SHA-1 is collision-broken in practice (SHAttered, 2017) and is unsuitable
# wherever collision resistance matters — which includes manifest integrity,
# because a partner could publish two manifests with the same digest. This is
# a present-day weakness. Grover is irrelevant to the conclusion.
"""Manifest verification for the nightly partner drop.

Each drop ships a manifest listing every file and its digest. The importer
recomputes the digests before handing files to the ledger loader.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import hashes

CHUNK_SIZE = 1024 * 1024


def manifest_entry_digest(path: Path) -> str:
    """Return the SHA-1 hex digest recorded in a partner manifest entry."""
    digest = hashlib.sha1()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)

    return digest.hexdigest()


def manifest_fingerprint(manifest_bytes: bytes) -> bytes:
    """Fingerprint a whole manifest for the import audit log."""
    digest = hashes.Hash(hashes.SHA1())
    digest.update(manifest_bytes)
    return digest.finalize()
