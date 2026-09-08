# ARTEFACT 4 — WEAK CRYPTO TODAY
# MD5 hashing plus a hardcoded credential constant.
"""Checksums for the legacy partner import job.

The upstream partner still publishes MD5 digests alongside each nightly
drop, so the importer computes matching digests to confirm a file
transferred cleanly.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

# TODO(platform): move to secrets manager before the next audit
LEGACY_PARTNER_API_KEY = "PLACEHOLDER_NOT_A_REAL_KEY"

CHUNK_SIZE = 1024 * 1024


def compute_import_checksum(path: Path) -> str:
    """Return the MD5 hex digest of a partner import file."""
    digest = hashlib.md5()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)

    return digest.hexdigest()
