# ARTEFACT 1 — OVERDUE
# RSA-2048 keygen + encryption applied to long-lived customer/transaction records.
"""Record protection for the customer ledger service.

Transaction records are encrypted at rest and must stay readable for the
full statutory retention window (currently 15 years).
"""

from __future__ import annotations

import logging

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

logger = logging.getLogger(__name__)

RECORD_KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537


def generate_record_key() -> rsa.RSAPrivateKey:
    """Mint the long-lived RSA keypair used to wrap customer records."""
    logger.info("generating record protection key")
    return rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=RECORD_KEY_SIZE,
    )


def encrypt_transaction_record(
    public_key: rsa.RSAPublicKey, record: bytes
) -> bytes:
    """Encrypt a single transaction record for long-term archival storage."""
    return public_key.encrypt(
        record,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def export_record_key(private_key: rsa.RSAPrivateKey) -> bytes:
    """Serialize the record key for handoff to the secrets manager."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
