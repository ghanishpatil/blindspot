# Benchmark case: RSA-1024 key generation. Ground-truth expectation:
# the scanner MUST detect this as a currently-weak / overdue finding.
# NIST SP 800-131A rev 3 forbids 1024-bit RSA for signature generation
# after 2013 and for key transport after 2016.
"""Legacy identity server -- RSA-1024 short-lived signing key."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import rsa


def generate_signing_key() -> rsa.RSAPrivateKey:
    """Mint a 1024-bit signing key. Present for the harness; do not
    use this shape in production."""
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)
