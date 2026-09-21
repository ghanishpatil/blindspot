"""Static cert / key / keystore scanner tests — R1.

Every fixture is generated in-process with :mod:`cryptography` so tests do
not depend on external PKI material. The scanner is asserted on three
guarantees:

1. **Algorithm resolution.** RSA / DSA / ECDSA / Ed25519 / X25519 keys and
   certs land with the correct algorithm and parameter.
2. **File-is-evidence discipline.** Every finding lands with high confidence
   and one of the STATIC_* detection methods.
3. **Defensive parsing.** Malformed PEM, encrypted keys, and password-
   protected keystores never crash the scanner — they either produce an
   UNRESOLVED finding or are quietly skipped, but never a traceback.
"""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519
from cryptography.x509.oid import NameOID

from app.models.asset import ArtefactType, ParameterStatus
from app.models.finding import ConfidenceLevel, DetectionMethod
from app.scanner.static_crypto import scan_static_crypto


# ── Helpers ─────────────────────────────────────────────────────────────────

def _self_signed_cert(private_key, subject_cn: str = "example.com") -> x509.Certificate:
    """Build a minimal self-signed certificate for testing."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
    )
    # Ed25519 does not use a hash algorithm at signing time.
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return builder.sign(private_key, algorithm=None)
    return builder.sign(private_key, algorithm=hashes.SHA256())


def _pem_cert(private_key) -> bytes:
    """Return a PEM-encoded self-signed cert for ``private_key``."""
    return _self_signed_cert(private_key).public_bytes(serialization.Encoding.PEM)


def _pem_key(private_key) -> bytes:
    """Return a PEM-encoded unencrypted private key."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


# ── RSA ─────────────────────────────────────────────────────────────────────

def test_rsa_pem_certificate_resolves_key_size(tmp_path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (tmp_path / "server.crt").write_bytes(_pem_cert(key))

    findings = scan_static_crypto(tmp_path)

    certs = [f for f in findings if f.algorithm == "RSA"]
    assert certs, "RSA cert not discovered"
    cert = certs[0]
    assert cert.parameter == "2048"
    assert cert.artefact_type == ArtefactType.CERTIFICATE
    assert cert.evidence.detection_method == DetectionMethod.STATIC_CERT_FILE
    assert cert.evidence.confidence_level == ConfidenceLevel.HIGH
    assert cert.parameter_status == ParameterStatus.RESOLVED


def test_rsa_pem_private_key_resolves_key_size(tmp_path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (tmp_path / "server.key").write_bytes(_pem_key(key))

    findings = scan_static_crypto(tmp_path)

    keys = [f for f in findings if f.algorithm == "RSA"]
    assert keys
    assert keys[0].parameter == "2048"
    assert keys[0].evidence.detection_method == DetectionMethod.STATIC_KEY_MATERIAL


# ── ECDSA / EC ──────────────────────────────────────────────────────────────

def test_ecdsa_p256_certificate_resolves_curve(tmp_path: Path) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    (tmp_path / "signer.pem").write_bytes(_pem_cert(key))

    findings = scan_static_crypto(tmp_path)

    ec_certs = [f for f in findings if f.algorithm == "ECDSA"]
    assert ec_certs
    # cryptography exposes the curve name as ``secp256r1``.
    assert ec_certs[0].curve == "secp256r1"
    assert ec_certs[0].parameter == "secp256r1"
    assert ec_certs[0].artefact_type == ArtefactType.CERTIFICATE


# ── Ed25519 ─────────────────────────────────────────────────────────────────

def test_ed25519_certificate_and_key(tmp_path: Path) -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    (tmp_path / "id_ed25519.crt").write_bytes(_pem_cert(key))
    (tmp_path / "id_ed25519.key").write_bytes(_pem_key(key))

    findings = scan_static_crypto(tmp_path)

    algos = [f.algorithm for f in findings]
    assert algos.count("Ed25519") >= 2


# ── X25519 (key exchange) ───────────────────────────────────────────────────

def test_x25519_private_key_is_key_exchange(tmp_path: Path) -> None:
    key = x25519.X25519PrivateKey.generate()
    (tmp_path / "peer.key").write_bytes(_pem_key(key))

    findings = scan_static_crypto(tmp_path)

    ex = [f for f in findings if f.algorithm == "X25519"]
    assert ex
    assert ex[0].artefact_type == ArtefactType.KEY_EXCHANGE


# ── DER-encoded material ────────────────────────────────────────────────────

def test_der_encoded_certificate(tmp_path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _self_signed_cert(key)
    (tmp_path / "server.der").write_bytes(cert.public_bytes(serialization.Encoding.DER))

    findings = scan_static_crypto(tmp_path)

    rsa_certs = [f for f in findings if f.algorithm == "RSA"]
    assert rsa_certs
    assert rsa_certs[0].parameter == "2048"
    assert rsa_certs[0].evidence.detection_method == DetectionMethod.STATIC_CERT_FILE


# ── Inline PEM in source and config files ───────────────────────────────────

def test_inline_pem_in_python_source(tmp_path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem_cert = _pem_cert(key).decode()
    (tmp_path / "server.py").write_text(
        f'CERT = """{pem_cert}"""\nprint("hello")\n', encoding="utf-8"
    )

    findings = scan_static_crypto(tmp_path)

    inline = [
        f for f in findings
        if f.evidence.file_path.endswith("server.py") and f.algorithm == "RSA"
    ]
    assert inline
    assert inline[0].evidence.detection_method == DetectionMethod.STATIC_CERT_FILE


def test_inline_pem_in_env_file(tmp_path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (tmp_path / ".env").write_bytes(b"# secrets\n" + _pem_key(key))
    findings = scan_static_crypto(tmp_path)
    assert any(f.algorithm == "RSA" and f.parameter == "2048" for f in findings)


# ── PEM bundles (multiple blocks per file) ──────────────────────────────────

def test_pem_bundle_emits_one_finding_per_cert(tmp_path: Path) -> None:
    """A single ``.pem`` file may hold multiple certificates. Each must be
    surfaced — the file is a bundle, and its contents matter individually."""
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    bundle = _pem_cert(rsa_key) + b"\n" + _pem_cert(ec_key)
    (tmp_path / "bundle.pem").write_bytes(bundle)

    findings = scan_static_crypto(tmp_path)

    algos = {f.algorithm for f in findings if f.evidence.file_path.endswith("bundle.pem")}
    assert {"RSA", "ECDSA"}.issubset(algos)


# ── Encrypted material and keystores ────────────────────────────────────────

def test_encrypted_pem_private_key_is_unresolved(tmp_path: Path) -> None:
    """Password-encrypted key: file exists, algorithm inside is opaque."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    encrypted = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"correct-horse"),
    )
    (tmp_path / "vault.key").write_bytes(encrypted)

    findings = scan_static_crypto(tmp_path)

    keystores = [
        f for f in findings if f.evidence.detection_method == DetectionMethod.STATIC_KEYSTORE
    ]
    assert keystores, "Encrypted PEM should still produce a keystore finding"
    assert keystores[0].parameter_status == ParameterStatus.UNRESOLVED
    assert "algorithm" in keystores[0].unresolved_parameters


def test_pkcs12_file_is_declared_only(tmp_path: Path) -> None:
    """PKCS#12 bundles are password-protected. The scanner records the
    existence honestly but never guesses at contents."""
    (tmp_path / "keystore.p12").write_bytes(b"\x30\x82\x00\x04somebinarybytes")

    findings = scan_static_crypto(tmp_path)

    ks = [f for f in findings if f.evidence.detection_method == DetectionMethod.STATIC_KEYSTORE]
    assert ks
    assert ks[0].algorithm == "PKCS12-Keystore"
    assert ks[0].parameter_status == ParameterStatus.UNRESOLVED


def test_jks_file_is_declared_only(tmp_path: Path) -> None:
    (tmp_path / "cacerts.jks").write_bytes(b"\xfe\xed\xfe\xed" + b"\x00" * 60)
    findings = scan_static_crypto(tmp_path)
    ks = [f for f in findings if f.algorithm == "JKS-Keystore"]
    assert ks
    assert ks[0].parameter_status == ParameterStatus.UNRESOLVED


# ── Defensive parsing ───────────────────────────────────────────────────────

def test_malformed_pem_does_not_crash(tmp_path: Path) -> None:
    (tmp_path / "garbage.pem").write_text(
        "-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----\n"
    )
    # Must not raise. Findings may or may not include this file — we only
    # care that the scanner returns cleanly.
    findings = scan_static_crypto(tmp_path)
    assert isinstance(findings, list)


def test_binary_noise_file_is_ignored(tmp_path: Path) -> None:
    (tmp_path / "image.der").write_bytes(b"\x00" * 200 + b"\xff" * 200)
    findings = scan_static_crypto(tmp_path)
    # No cert / key parses out of random bytes → no findings.
    assert not any(f.evidence.file_path.endswith("image.der") for f in findings)


def test_symlinks_are_skipped(tmp_path: Path) -> None:
    """Symlinks must be skipped so a hostile repo cannot reach outside the
    scanned tree via a link."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    real = tmp_path / "real.crt"
    real.write_bytes(_pem_cert(key))
    link = tmp_path / "link.crt"
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on this platform")

    findings = scan_static_crypto(tmp_path)

    # Only the real file should have produced a finding.
    paths = {f.evidence.file_path for f in findings}
    assert "real.crt" in paths
    assert "link.crt" not in paths


# ── Config surface ─────────────────────────────────────────────────────────

def test_disabled_by_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.config import get_settings

    monkeypatch.setenv("STATIC_CRYPTO_SCAN_ENABLED", "false")
    get_settings.cache_clear()
    try:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        (tmp_path / "server.crt").write_bytes(_pem_cert(key))
        assert scan_static_crypto(tmp_path) == []
    finally:
        get_settings.cache_clear()


def test_oversized_files_are_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The size cap prevents the scanner from reading a hostile 500 MB
    ``.pem`` into memory."""
    from app.config import get_settings

    monkeypatch.setenv("STATIC_CRYPTO_MAX_SCAN_MB", "1")
    get_settings.cache_clear()
    try:
        big = tmp_path / "huge.pem"
        big.write_bytes(b"A" * (2 * 1024 * 1024))  # 2 MB > 1 MB cap
        findings = scan_static_crypto(tmp_path)
        assert not any(f.evidence.file_path.endswith("huge.pem") for f in findings)
    finally:
        get_settings.cache_clear()
