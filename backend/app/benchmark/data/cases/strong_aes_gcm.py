# Benchmark case: AES-256-GCM key generation. Ground-truth: acceptable.
# AES-GCM is a NIST-approved authenticated cipher; 256-bit key survives
# Grover with 128-bit effective quantum strength.
"""Field-encryption key material for the customer profile store."""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


FIELD_KEY_BITS = 256


def new_field_key() -> bytes:
    return AESGCM.generate_key(bit_length=FIELD_KEY_BITS)
