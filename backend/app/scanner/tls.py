"""Live TLS / certificate scanning.

Connects to ``host:port``, completes a TLS handshake, and reads the negotiated
protocol/cipher plus the server certificate. The certificate's public-key
algorithm is emitted as a :class:`NormalizedFinding` so it runs through the
*same* classify → risk → recommend analysis as a source finding — a cert using
RSA/ECDSA is Shor-breakable exactly like the same algorithm found in code.

This closes the PS "certificates" and "protocols" artefact types with a real,
live observation (no credentials, no vendor SDK — just the standard library
plus ``cryptography`` for DER parsing).

SSRF boundary: a user supplies the hostname, so before connecting we resolve it
and refuse private / loopback / link-local / reserved addresses. This blocks
using the scanner to probe internal services.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from app.config import Settings, get_settings
from app.models.asset import ArtefactType, CryptoPrimitive, CryptoUsage, ParameterStatus
from app.models.finding import DetectionMethod, Evidence, NormalizedFinding

logger = logging.getLogger(__name__)

# Protocol versions still considered acceptable today. Anything else is a
# present-day weakness, flagged in the result.
_SECURE_PROTOCOLS = {"TLSv1.2", "TLSv1.3"}


class TlsScanError(ValueError):
    """Raised when a TLS target is invalid (client error)."""


class TlsConnectionError(TlsScanError):
    """Raised when the target is valid but the handshake/connection failed."""


def validate_tls_target(host: str, port: int) -> tuple[str, int]:
    """Validate host/port and refuse internal addresses (SSRF guard).

    Resolves the host and rejects the target if *any* resolved address is
    private, loopback, link-local, reserved, multicast, or unspecified.
    """
    if not host or not host.strip():
        raise TlsScanError("Host is empty.")
    cleaned = host.strip()
    # Reject anything that looks like a URL/scheme or contains a path.
    if "/" in cleaned or "\\" in cleaned or " " in cleaned:
        raise TlsScanError("Host must be a bare hostname, not a URL.")
    if not (1 <= port <= 65535):
        raise TlsScanError("Port must be between 1 and 65535.")

    try:
        infos = socket.getaddrinfo(cleaned, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise TlsScanError(f"Host could not be resolved: {cleaned}") from exc

    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise TlsScanError(
                f"Refusing to scan internal address {addr} for host {cleaned!r}."
            )
    return cleaned, port


def _key_details(cert: x509.Certificate) -> tuple[str, str | None, int | None, str | None]:
    """Return (risk_algorithm, key_type_label, key_bits, curve) for the cert key.

    ``risk_algorithm`` is the canonical name the risk engine understands
    (RSA / ECDSA / DSA). ``key_type_label`` is the honest, specific key type for
    display (e.g. 'Ed25519'), which may differ from the risk bucket.
    """
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", "RSA", pub.key_size, None
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "ECDSA", "ECDSA", pub.curve.key_size, pub.curve.name
    if isinstance(pub, ed25519.Ed25519PublicKey):
        # EdDSA is elliptic-curve and Shor-breakable; bucket as ECDSA for risk.
        return "ECDSA", "Ed25519", 256, "ed25519"
    if isinstance(pub, ed448.Ed448PublicKey):
        return "ECDSA", "Ed448", 448, "ed448"
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", "DSA", pub.key_size, None
    return "unknown", "unknown", None, None


def _name_str(name: x509.Name) -> str:
    try:
        return name.rfc4514_string()
    except Exception:  # noqa: BLE001
        return str(name)


def scan_tls(
    host: str, port: int = 443, settings: Settings | None = None
) -> tuple[dict, list[NormalizedFinding]]:
    """Probe ``host:port`` and return (observed metadata, normalized findings).

    The observed dict is camelCase and ready to serialise. Findings describe the
    certificate's public key and are enriched by the caller.
    """
    settings = settings or get_settings()
    if not settings.tls_scan_enabled:
        raise TlsScanError("TLS scanning is disabled by configuration.")

    cleaned, port = validate_tls_target(host, port)

    # Read the certificate WITHOUT validating the chain, so self-signed or
    # expired certs can still be inspected (we are assessing, not trusting).
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection(
            (cleaned, port), timeout=settings.tls_scan_timeout_seconds
        ) as sock:
            with context.wrap_socket(sock, server_hostname=cleaned) as ssock:
                der = ssock.getpeercert(binary_form=True)
                protocol = ssock.version() or "unknown"
                cipher = ssock.cipher()  # (name, protocol, secret_bits)
    except (socket.timeout, ssl.SSLError, OSError) as exc:
        raise TlsConnectionError(f"TLS handshake failed for {cleaned}:{port}: {exc}") from exc

    if not der:
        raise TlsConnectionError("No certificate was presented by the server.")

    cert = x509.load_der_x509_certificate(der)
    risk_algo, key_type, key_bits, curve = _key_details(cert)
    sig_alg = getattr(cert.signature_algorithm_oid, "_name", None) or cert.signature_algorithm_oid.dotted_string

    try:
        not_after = cert.not_valid_after_utc
    except AttributeError:  # older cryptography
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    expired = not_after < datetime.now(timezone.utc)

    cipher_name = cipher[0] if cipher else None
    cipher_bits = cipher[2] if cipher and len(cipher) > 2 else None
    protocol_secure = protocol in _SECURE_PROTOCOLS

    notes: list[str] = []
    if not protocol_secure:
        notes.append(
            f"Negotiated {protocol}, which is below TLS 1.2 and a present-day weakness."
        )
    if expired:
        notes.append("The certificate is expired.")

    observed = {
        "host": cleaned,
        "port": port,
        "protocol": protocol,
        "protocolSecure": protocol_secure,
        "cipherSuite": cipher_name,
        "cipherBits": cipher_bits,
        "certificate": {
            "subject": _name_str(cert.subject),
            "issuer": _name_str(cert.issuer),
            "notAfter": not_after.isoformat(),
            "expired": expired,
            "signatureAlgorithm": sig_alg,
            "keyType": key_type,
            "keyBits": key_bits,
            "curve": curve,
        },
        "notes": notes,
    }

    # Emit the certificate's public key as a normalized finding so it runs
    # through the same analysis pipeline as a code finding.
    snippet = f"{key_type} {key_bits or ''}-bit certificate; sig={sig_alg}; {protocol}".strip()
    evidence = Evidence(
        file_path=f"{cleaned}:{port}",
        line_number=None,
        code_snippet=snippet,
        detection_method=DetectionMethod.TLS_PROBE,
        confidence=0.95,
    )
    finding = NormalizedFinding(
        id=f"TLS-{cleaned}-{port}",
        algorithm=risk_algo,
        primitive=CryptoPrimitive.SIGNATURE,
        parameter=str(key_bits) if key_bits else None,
        parameter_status=ParameterStatus.RESOLVED if key_bits else ParameterStatus.UNRESOLVED,
        curve=curve,
        usage=CryptoUsage.CERTIFICATE_SIGNING,
        artefact_type=ArtefactType.CERTIFICATE,
        evidence=evidence,
    )

    return observed, [finding]
