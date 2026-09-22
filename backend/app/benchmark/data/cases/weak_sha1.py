# Benchmark case: SHA-1 digest. Ground-truth: currently weak.
# Collisions demonstrated (SHAttered, 2017); NIST disallowed for digital
# signatures after 2013.
"""Manifest checksum for the legacy internal artefact index."""

from __future__ import annotations

import hashlib


def manifest_checksum(payload: bytes) -> str:
    return hashlib.sha1(payload).hexdigest()
