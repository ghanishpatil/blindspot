"""Crypto tunables for the archive service.

Key sizes live here so ops can adjust them per environment without
touching the service code.
"""

from __future__ import annotations

# Archive wrapping key size, overridden per environment by the deploy config.
ARCHIVE_KEY_SIZE = 2048

ARCHIVE_PUBLIC_EXPONENT = 65537
