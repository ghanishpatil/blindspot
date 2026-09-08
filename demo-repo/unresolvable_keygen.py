# ARTEFACT 5 — UNRESOLVABLE
# RSA keygen where the key size comes from an external config constant,
# not a literal, so a static scan cannot resolve the strength locally.
"""Archive wrapping keys for the document archive service."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import rsa

from crypto_config import ARCHIVE_KEY_SIZE, ARCHIVE_PUBLIC_EXPONENT


def generate_archive_wrapping_key() -> rsa.RSAPrivateKey:
    """Mint the RSA keypair used to wrap archive segment keys."""
    return rsa.generate_private_key(
        public_exponent=ARCHIVE_PUBLIC_EXPONENT,
        key_size=ARCHIVE_KEY_SIZE,
    )
