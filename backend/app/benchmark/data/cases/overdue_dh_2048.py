# Benchmark case: Diffie-Hellman 2048. Ground-truth: quantum-migration
# overdue (Shor-vulnerable) even though the classical margin is fine.
"""Application-layer key agreement, in-house TLS-like handshake."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import dh


def new_dh_parameters() -> dh.DHParameters:
    return dh.generate_parameters(generator=2, key_size=2048)
