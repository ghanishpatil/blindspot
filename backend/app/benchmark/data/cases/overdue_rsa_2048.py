# Benchmark case: RSA-2048 keygen for long-lived data.
# Ground-truth: RSA-2048 is Overdue for migration under Blindspot's
# default 10-year quantum horizon (Mosca X > Z after 2035). Expected to
# fire with algorithm=RSA, parameter=2048.
"""Record-protection key for the customer ledger service."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import rsa


RECORD_KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537


def mint_record_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=RECORD_KEY_SIZE,
    )
