# ARTEFACT 7 — WEAK CRYPTO TODAY (3DES)
# Triple DES in CBC mode, still used by the archival tape export job.
#
# Added for BUILD SPEC section 9 algorithm coverage (3DES).
#
# 3DES is a PRESENT-DAY weakness, not a quantum one: its 64-bit block size
# makes it vulnerable to Sweet32 birthday attacks, and NIST SP 800-131A Rev.2
# disallowed it after 2023. The correct output here is "remediate now",
# reached independently of anything Mosca has to say.
"""Nightly archival tape export for the settlement warehouse.

The offsite tape appliance predates the current KMS integration and still
speaks the original 3DES-CBC wire format.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Tape appliance firmware only accepts 24-byte keying option 1 material.
TAPE_KEY_BYTES = 24
TAPE_BLOCK_BYTES = 8


def _pad_to_block(payload: bytes) -> bytes:
    """PKCS#5-style padding to the 3DES block size."""
    padding_length = TAPE_BLOCK_BYTES - (len(payload) % TAPE_BLOCK_BYTES)
    return payload + bytes([padding_length]) * padding_length


def encrypt_tape_segment(tape_key: bytes, segment: bytes) -> tuple[bytes, bytes]:
    """Encrypt one archival tape segment for the offsite appliance."""
    iv = os.urandom(TAPE_BLOCK_BYTES)

    encryptor = Cipher(algorithms.TripleDES(tape_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(_pad_to_block(segment)) + encryptor.finalize()

    return iv, ciphertext
