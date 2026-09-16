"""Live TLS / certificate scanning tests (offline).

The socket handshake needs the network, so these tests avoid it: they exercise
the SSRF guard, the certificate-key parsing (with synthetic self-signed certs),
the endpoint error mapping, and the reuse of the enrichment pipeline for a cert
finding. The live handshake itself is validated by the end-to-end smoke test.
"""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.models.asset import ArtefactType, CryptoPrimitive, CryptoUsage, ParameterStatus
from app.models.finding import DetectionMethod, Evidence, NormalizedFinding
from app.scanner.tls import TlsScanError, _key_details, validate_tls_target


def _self_signed(key, sign_key=None) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
    )
    return builder.sign(sign_key or key, hashes.SHA256())


# ── Certificate key parsing ──────────────────────────────────────────────────

def test_key_details_rsa() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _self_signed(key)
    assert _key_details(cert) == ("RSA", "RSA", 2048, None)


def test_key_details_ec_is_shor_bucketed() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _self_signed(key)
    risk_algo, key_type, bits, curve = _key_details(cert)
    assert risk_algo == "ECDSA"  # canonical risk bucket
    assert curve == "secp256r1"
    assert bits == 256


# ── SSRF guard ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "10.0.0.1", "192.168.1.1", "0.0.0.0"])
def test_validate_rejects_internal_addresses(host: str) -> None:
    with pytest.raises(TlsScanError):
        validate_tls_target(host, 443)


def test_validate_rejects_url_like_host() -> None:
    with pytest.raises(TlsScanError):
        validate_tls_target("https://example.com/path", 443)


@pytest.mark.parametrize("port", [0, 70000, -1])
def test_validate_rejects_bad_port(port: int) -> None:
    with pytest.raises(TlsScanError):
        validate_tls_target("8.8.8.8", port)


def test_validate_accepts_public_ip_literal() -> None:
    # A numeric literal resolves without DNS — a public address is accepted.
    assert validate_tls_target("8.8.8.8", 443) == ("8.8.8.8", 443)


# ── Endpoint ─────────────────────────────────────────────────────────────────

def test_tls_scan_requires_auth(client: TestClient) -> None:
    assert client.post("/api/tls-scan", json={"host": "example.com"}).status_code == 401


def test_tls_scan_rejects_internal_host(auth_bypassed_client: TestClient) -> None:
    response = auth_bypassed_client.post("/api/tls-scan", json={"host": "localhost"})
    assert response.status_code == 400
    assert "tls scan error" in response.json()["detail"].lower()


# ── Reuse: a cert finding enriches through the same pipeline ────────────────

def test_cert_finding_enriches_to_recommendation() -> None:
    from app.config import get_settings
    from app.pipeline import _enrich_finding

    nf = NormalizedFinding(
        id="TLS-example.com-443",
        algorithm="RSA",
        primitive=CryptoPrimitive.SIGNATURE,
        parameter="2048",
        parameter_status=ParameterStatus.RESOLVED,
        usage=CryptoUsage.CERTIFICATE_SIGNING,
        artefact_type=ArtefactType.CERTIFICATE,
        evidence=Evidence(
            file_path="example.com:443",
            code_snippet="RSA 2048-bit certificate",
            detection_method=DetectionMethod.TLS_PROBE,
            confidence=0.95,
        ),
    )
    finding = _enrich_finding(nf, "tls-x", "tls", get_settings())

    assert finding.quantum_risk is not None
    assert finding.quantum_risk.is_quantum_vulnerable is True
    assert finding.recommendation is not None
    assert finding.evidence.detection_method == DetectionMethod.TLS_PROBE
