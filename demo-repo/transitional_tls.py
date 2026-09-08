# ARTEFACT 2 — TRANSITIONAL
# ECDH key exchange protecting active service-to-service API traffic.
"""Session key negotiation for the internal service mesh.

Every service-to-service call rides an mTLS channel whose traffic keys are
negotiated per connection, then expanded into per-direction AEAD keys.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MESH_CURVE = ec.SECP256R1()
SESSION_KEY_BYTES = 32
HKDF_INFO = b"internal-api/service-link/v1"


def negotiate_link_key(peer_public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Derive the symmetric key for an internal API link via ECDH.

    The local key is ephemeral and dropped once the shared secret has been
    expanded, giving forward secrecy for the connection.
    """
    local_private_key = ec.generate_private_key(MESH_CURVE)

    shared_secret = local_private_key.exchange(ec.ECDH(), peer_public_key)

    return HKDF(
        algorithm=hashes.SHA256(),
        length=SESSION_KEY_BYTES,
        salt=None,
        info=HKDF_INFO,
    ).derive(shared_secret)
