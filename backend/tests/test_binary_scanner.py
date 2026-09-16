"""Binary scanner (lite) tests.

Fingerprints are matched against tiny synthetic byte blobs — no real ELF/PE
files needed to verify the signature logic. Every emitted finding must land
at LOW confidence so the honesty layer routes it to manual verification.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from app.models.asset import ArtefactType
from app.models.finding import DetectionMethod
from app.scanner.binary import (
    _AES_SBOX_HEAD,
    _MD5_H0,
    _SHA1_H0,
    _SHA256_H0,
    _SHA512_H0,
    _looks_binary,
    scan_binaries,
)


def _write_fake_binary(path: Path, payload: bytes) -> None:
    """Write a fake ELF-prefixed binary containing *payload*."""
    path.write_bytes(b"\x7fELF" + b"\x00" * 60 + payload + b"\x00" * 64)


# ── Detection ──────────────────────────────────────────────────────────────

def test_looks_binary_by_extension(tmp_path: Path) -> None:
    dll = tmp_path / "foo.dll"
    dll.write_bytes(b"anything")
    assert _looks_binary(dll) is True


def test_looks_binary_by_magic(tmp_path: Path) -> None:
    elf = tmp_path / "no-ext-executable"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 20)
    assert _looks_binary(elf) is True


def test_ignores_non_binary(tmp_path: Path) -> None:
    txt = tmp_path / "readme.txt"
    txt.write_text("just text")
    assert _looks_binary(txt) is False


# ── Constant signatures ────────────────────────────────────────────────────

def test_sha256_constants_detected(tmp_path: Path) -> None:
    b = tmp_path / "libcrypto.so"
    _write_fake_binary(b, _SHA256_H0)
    findings = scan_binaries(tmp_path)
    algos = {f.algorithm for f in findings}
    assert "SHA-256" in algos


def test_sha512_constants_detected(tmp_path: Path) -> None:
    b = tmp_path / "hashlib.dll"
    _write_fake_binary(b, _SHA512_H0)
    findings = scan_binaries(tmp_path)
    assert "SHA-512" in {f.algorithm for f in findings}


def test_sha1_and_md5_are_disambiguated(tmp_path: Path) -> None:
    """SHA-1's 5th word distinguishes it from MD5 despite the 4 shared words."""
    sha1 = tmp_path / "libssl.so"
    _write_fake_binary(sha1, _SHA1_H0)
    md5 = tmp_path / "hashlegacy.dll"
    _write_fake_binary(md5, _MD5_H0)

    findings = scan_binaries(tmp_path)
    by_file = {(f.evidence.file_path, f.algorithm) for f in findings}
    assert ("libssl.so", "SHA-1") in by_file
    assert ("hashlegacy.dll", "MD5") in by_file
    # MD5 must NOT be reported for the file that actually contains SHA-1.
    assert ("libssl.so", "MD5") not in by_file


def test_aes_sbox_detected(tmp_path: Path) -> None:
    b = tmp_path / "cipher.dylib"
    _write_fake_binary(b, _AES_SBOX_HEAD)
    findings = scan_binaries(tmp_path)
    assert "AES" in {f.algorithm for f in findings}


# ── OID signatures ─────────────────────────────────────────────────────────

def test_rsa_oid_detected(tmp_path: Path) -> None:
    b = tmp_path / "signer.so"
    _write_fake_binary(b, bytes.fromhex("2a864886f70d010101"))  # rsaEncryption OID
    findings = scan_binaries(tmp_path)
    assert "RSA" in {f.algorithm for f in findings}


def test_ecdsa_oid_detected(tmp_path: Path) -> None:
    b = tmp_path / "wallet.dll"
    _write_fake_binary(b, bytes.fromhex("2a8648ce3d040302"))  # ecdsa-with-SHA256 OID
    findings = scan_binaries(tmp_path)
    assert "ECDSA" in {f.algorithm for f in findings}


# ── Library string signatures ──────────────────────────────────────────────

def test_openssl_version_string_detected(tmp_path: Path) -> None:
    b = tmp_path / "app.exe"
    _write_fake_binary(b, b"OpenSSL 3.0.11 5 Dec 2023")
    findings = scan_binaries(tmp_path)
    linked = [f for f in findings if f.algorithm == "OpenSSL-linked"]
    assert len(linked) == 1
    assert linked[0].parameter == "3.0.11"


# ── Honesty: every binary finding must be low confidence ───────────────────

def test_all_binary_findings_are_low_confidence(tmp_path: Path) -> None:
    b = tmp_path / "kitchensink.so"
    _write_fake_binary(b, _SHA256_H0 + _AES_SBOX_HEAD + b"OpenSSL 3.0.1")
    findings = scan_binaries(tmp_path)
    assert findings, "expected multiple binary findings"
    for f in findings:
        assert f.evidence.detection_method == DetectionMethod.BINARY_SIGNATURE
        assert f.evidence.confidence_level.value == "low"


def test_findings_are_deduplicated_per_file(tmp_path: Path) -> None:
    b = tmp_path / "twice.so"
    # Repeat the same S-box twice in the same file.
    _write_fake_binary(b, _AES_SBOX_HEAD + b"filler" * 20 + _AES_SBOX_HEAD)
    findings = scan_binaries(tmp_path)
    aes = [f for f in findings if f.algorithm == "AES"]
    assert len(aes) == 1


# ── Guards ─────────────────────────────────────────────────────────────────

def test_oversize_binaries_are_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A binary larger than the cap is silently skipped, not read into memory."""
    from app.config import get_settings

    monkeypatch.setenv("BINARY_MAX_SCAN_MB", "1")
    get_settings.cache_clear()

    huge = tmp_path / "huge.so"
    # 2 MB body — over the 1 MB cap.
    _write_fake_binary(huge, _SHA256_H0 + b"\x00" * (2 * 1024 * 1024))
    assert scan_binaries(tmp_path) == []


def test_disabled_by_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.config import get_settings

    monkeypatch.setenv("BINARY_SCAN_ENABLED", "false")
    get_settings.cache_clear()

    b = tmp_path / "would-match.so"
    _write_fake_binary(b, _SHA256_H0)
    assert scan_binaries(tmp_path) == []


def test_findings_carry_binary_signature_method_and_artefact_type(tmp_path: Path) -> None:
    b = tmp_path / "artefact-check.so"
    _write_fake_binary(b, _SHA256_H0)
    findings = scan_binaries(tmp_path)
    f = next(x for x in findings if x.algorithm == "SHA-256")
    assert f.evidence.detection_method == DetectionMethod.BINARY_SIGNATURE
    assert f.artefact_type == ArtefactType.HASH
