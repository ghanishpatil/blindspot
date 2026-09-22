# Benchmark case: no cryptography, just string plumbing. Ground-truth:
# TRUE NEGATIVE.
"""URL sanitisation helpers used by the admin console."""

from __future__ import annotations

from urllib.parse import quote


def encode_query(raw: dict[str, str]) -> str:
    parts = [f"{quote(k)}={quote(v)}" for k, v in sorted(raw.items())]
    return "&".join(parts)


def strip_trailing_slash(path: str) -> str:
    if path.endswith("/") and len(path) > 1:
        return path[:-1]
    return path
