# Benchmark case: AES in ECB mode. Ground-truth: weak *mode* even
# though AES itself is strong. ECB leaks plaintext block equality; the
# ECB penguin.
"""Session cache encryption -- legacy path, being retired Q4."""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def make_cipher(key: bytes) -> Cipher:
    return Cipher(algorithms.AES(key), modes.ECB())
