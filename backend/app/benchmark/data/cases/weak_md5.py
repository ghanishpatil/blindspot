# Benchmark case: MD5 digest. Ground-truth: currently weak.
# Collision-broken since 2004; unsuitable for signatures or any
# security-relevant integrity check.
"""File digest for the deprecated partner sync pipeline."""

from __future__ import annotations

import hashlib
from pathlib import Path


def digest_partner_drop(path: Path) -> str:
    return hashlib.md5(path.read_bytes()).hexdigest()
