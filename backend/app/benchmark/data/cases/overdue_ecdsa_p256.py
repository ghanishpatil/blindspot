# Benchmark case: ECDSA on secp256r1 (NIST P-256). Ground-truth:
# ECDSA is Shor-vulnerable; even at 256-bit strength it counts as
# quantum-migration overdue for long-lifetime signing keys.
"""JWT signing key for the partner API. Long-lived per contract."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec


def new_jwt_signer() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())
