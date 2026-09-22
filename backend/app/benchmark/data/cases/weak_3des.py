# Benchmark case: 3DES / TripleDES. Ground-truth: currently weak.
# Effective 112-bit strength; NIST SP 800-131A rev 3 disallows for
# encryption after 2023. Sweet32 birthday attacks make it unsafe for
# long TLS sessions.
"""Tape-archive encryption stub. Kept only for scanner coverage."""

from __future__ import annotations

from Crypto.Cipher import DES3


def encrypt_block(payload: bytes, key: bytes) -> bytes:
    return DES3.new(key, DES3.MODE_CBC, iv=b"\x00" * 8).encrypt(payload)
