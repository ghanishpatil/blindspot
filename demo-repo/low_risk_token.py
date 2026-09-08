# ARTEFACT 3 — LOW RISK
# ECDSA signature over an explicitly short-lived (1 hour) session token.
"""Short-lived session tokens for the internal admin console.

Tokens are signed with the console's ECDSA key and expire inside a single
operator session, so revocation is handled by expiry rather than a
blocklist.
"""

from __future__ import annotations

import base64
import json
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

TOKEN_TTL_SECONDS = 3600
TOKEN_CURVE = ec.SECP256R1()


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_token_signing_key() -> ec.EllipticCurvePrivateKey:
    """Create the ephemeral ECDSA key the console uses to sign tokens."""
    return ec.generate_private_key(TOKEN_CURVE)


def issue_session_token(
    signing_key: ec.EllipticCurvePrivateKey, user_id: str, scopes: list[str]
) -> str:
    """Issue an ECDSA-signed session token with a 1 hour TTL."""
    now = int(time.time())
    claims = {
        "sub": user_id,
        "scp": scopes,
        "iat": now,
        "exp": now + TOKEN_TTL_SECONDS,
    }

    payload = _b64(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    signature = signing_key.sign(
        payload.encode("ascii"), ec.ECDSA(hashes.SHA256())
    )

    return f"{payload}.{_b64(signature)}"
