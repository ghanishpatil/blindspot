# ARTEFACT 6 — LOW RISK (symmetric, quantum-resistant)
# AES-256 field encryption in two modes: GCM for the current path, CBC for a
# legacy path that has not been migrated yet.
#
# Added for BUILD SPEC section 9 algorithm coverage (AES) and to exercise mode
# extraction (GCM vs CBC).
#
# This is deliberately a CONTRAST case. The data is long-lived, exactly like
# ARTEFACT 1, but AES is symmetric and Shor does not break it. Mosca must not
# fire here just because the lifetime is long. If the tool reports this as
# overdue, the risk engine is wrong.
"""Field-level encryption for the customer ledger.

Selected account fields are sealed before they reach the row store, using a
data key unwrapped from the record protection key. Sealed fields share the
statutory retention window of the records that contain them.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FIELD_KEY_BITS = 256
GCM_NONCE_BYTES = 12
CBC_IV_BYTES = 16


def generate_field_key() -> bytes:
    """Mint a fresh AES-256 data key for field sealing."""
    return AESGCM.generate_key(bit_length=FIELD_KEY_BITS)


def seal_account_field(field_key: bytes, plaintext: bytes, record_id: str) -> bytes:
    """Seal one account field with AES-256-GCM, binding it to its record id."""
    nonce = os.urandom(GCM_NONCE_BYTES)
    ciphertext = AESGCM(field_key).encrypt(
        nonce, plaintext, record_id.encode("ascii")
    )
    return nonce + ciphertext


def open_account_field(field_key: bytes, sealed: bytes, record_id: str) -> bytes:
    """Open a field sealed by :func:`seal_account_field`."""
    nonce, ciphertext = sealed[:GCM_NONCE_BYTES], sealed[GCM_NONCE_BYTES:]
    return AESGCM(field_key).decrypt(
        nonce, ciphertext, record_id.encode("ascii")
    )


def seal_legacy_field(field_key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Seal a field using the pre-migration AES-256-CBC path.

    Retained because the reporting warehouse still reads fields written by the
    old batch job. New writes go through :func:`seal_account_field`.
    """
    iv = os.urandom(CBC_IV_BYTES)
    encryptor = Cipher(algorithms.AES(field_key), modes.CBC(iv)).encryptor()
    return iv, encryptor.update(plaintext) + encryptor.finalize()
