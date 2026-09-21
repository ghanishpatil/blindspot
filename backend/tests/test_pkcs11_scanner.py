"""PKCS#11 HSM attestation scanner tests -- R7.

The scanner is opt-in and depends on the optional ``python-pkcs11``
package. Tests here exercise:

1. **Gating.** The scanner refuses to touch the module unless
   ``pkcs11_scan_enabled`` is true AND ``pkcs11_module_path`` names an
   existing file AND ``python-pkcs11`` is importable.
2. **Extraction.** ``_resolve_object`` walks dict-shaped fake objects
   (matching the ``obj[Attribute.<name>]`` protocol tests provide) and
   emits ``NormalizedFinding`` with the right algorithm, parameter, and
   detection method.
3. **Fallbacks.** Unknown key types surface as ``PKCS11-<name>`` with an
   ``UNRESOLVED`` parameter -- never silently dropped, never invented.

Test doubles are dict-shaped rather than mock-heavy: the extractor
accepts either a real python-pkcs11 object or a plain dict, exactly so
the tests can avoid the real library.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.config import get_settings
from app.models.asset import ArtefactType, CryptoPrimitive, ParameterStatus
from app.models.finding import ConfidenceLevel, DetectionMethod
from app.scanner import pkcs11_scanner
from app.scanner.pkcs11_scanner import _resolve_object, scan_pkcs11


# ---------------------------------------------------------------------------
# Object-level extraction (dict-shaped fakes -- no library import needed)
# ---------------------------------------------------------------------------

def test_rsa_public_key_resolves_to_2048() -> None:
    fake = {
        "CLASS": "PUBLIC_KEY",
        "KEY_TYPE": "RSA",
        "LABEL": "web-tls-2025",
        "MODULUS_BITS": 2048,
    }
    finding = _resolve_object(fake, token_label="softhsm-test", module_path="/opt/softhsm.so")

    assert finding is not None
    assert finding.algorithm == "RSA"
    assert finding.parameter == "2048"
    assert finding.parameter_status == ParameterStatus.RESOLVED
    assert finding.primitive == CryptoPrimitive.PKE
    assert finding.artefact_type == ArtefactType.HARDWARE_MODULE
    assert finding.evidence.detection_method == DetectionMethod.PKCS11_ATTESTED
    assert finding.evidence.confidence_level == ConfidenceLevel.HIGH
    assert "softhsm-test" in finding.evidence.code_snippet


def test_rsa_falls_back_to_modulus_bytes_when_modulus_bits_missing() -> None:
    # Some tokens don't expose MODULUS_BITS; RFC lets you derive from MODULUS.
    fake = {
        "CLASS": "PUBLIC_KEY",
        "KEY_TYPE": "RSA",
        "LABEL": "web-tls-2025",
        "MODULUS": b"\x00" * 256,  # 256 bytes -> 2048 bits
    }
    finding = _resolve_object(fake, token_label="hsm", module_path="/x")
    assert finding is not None
    assert finding.parameter == "2048"
    assert finding.parameter_status == ParameterStatus.RESOLVED


def test_ec_p256_resolves_to_curve_name() -> None:
    fake = {
        "CLASS": "PRIVATE_KEY",
        "KEY_TYPE": "EC",
        "LABEL": "code-signing",
        # secp256r1 DER-encoded OID: 06 08 2A 86 48 CE 3D 03 01 07
        "EC_PARAMS": b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
    }
    finding = _resolve_object(fake, token_label="softhsm", module_path="/opt/softhsm.so")

    assert finding is not None
    assert finding.algorithm == "ECDSA"
    assert finding.curve == "secp256r1"
    assert finding.parameter == "P-256"
    assert finding.parameter_status == ParameterStatus.RESOLVED


def test_ec_p384_resolves() -> None:
    fake = {
        "CLASS": "PUBLIC_KEY",
        "KEY_TYPE": "EC",
        "EC_PARAMS": b"\x06\x05\x2b\x81\x04\x00\x22",
    }
    finding = _resolve_object(fake, token_label="hsm", module_path="/x")
    assert finding is not None
    assert finding.parameter == "P-384"


def test_ed25519_resolves_from_key_type() -> None:
    fake = {
        "CLASS": "PRIVATE_KEY",
        "KEY_TYPE": "EC_EDWARDS",
        "LABEL": "signing-ed25519",
    }
    finding = _resolve_object(fake, token_label="hsm", module_path="/x")

    assert finding is not None
    assert finding.algorithm == "Ed25519"
    assert finding.curve == "Ed25519"


def test_aes_key_resolves_from_value_len() -> None:
    fake = {
        "CLASS": "SECRET_KEY",
        "KEY_TYPE": "AES",
        "LABEL": "data-encryption",
        "VALUE_LEN": 32,   # bytes -> 256-bit key
    }
    finding = _resolve_object(fake, token_label="hsm", module_path="/x")

    assert finding is not None
    assert finding.algorithm == "AES"
    assert finding.parameter == "256"


def test_certificate_object_is_catalogued() -> None:
    """PKCS#11 CERTIFICATE objects have no KEY_TYPE. The scanner catalogues
    them as ``PKCS11-CERT`` with an unresolved parameter -- honest about
    what a raw certificate object without a linked key can tell us."""
    fake = {
        "CLASS": "CERTIFICATE",
        "LABEL": "trust-anchor-2030",
    }
    finding = _resolve_object(fake, token_label="hsm", module_path="/x")

    assert finding is not None
    assert finding.algorithm == "PKCS11-CERT"
    assert finding.parameter_status == ParameterStatus.UNRESOLVED


def test_unknown_key_type_surfaces_verbatim() -> None:
    """An unexpected KEY_TYPE must not crash and must not be dropped."""
    fake = {"CLASS": "PRIVATE_KEY", "KEY_TYPE": "FUTURE_ALG_9000"}
    finding = _resolve_object(fake, token_label="hsm", module_path="/x")

    assert finding is not None
    assert finding.algorithm == "PKCS11-FUTURE_ALG_9000"
    assert finding.parameter_status == ParameterStatus.UNRESOLVED


def test_data_and_mechanism_objects_are_ignored() -> None:
    """Non-key, non-cert PKCS#11 classes carry no algorithm signal.
    Ignoring them keeps the algorithm inventory clean."""
    assert _resolve_object({"CLASS": "DATA"}, token_label="t", module_path="/x") is None
    assert _resolve_object({"CLASS": "MECHANISM"}, token_label="t", module_path="/x") is None


def test_missing_class_is_ignored() -> None:
    assert _resolve_object({"KEY_TYPE": "RSA"}, token_label="t", module_path="/x") is None


# ---------------------------------------------------------------------------
# Top-level scan_pkcs11 -- gating, graceful degradation, session iteration
# ---------------------------------------------------------------------------

def test_scan_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """The whole scanner is opt-in. Without `pkcs11_scan_enabled` it must
    return an empty list without importing anything or touching the disk."""
    monkeypatch.delenv("PKCS11_SCAN_ENABLED", raising=False)
    get_settings.cache_clear()
    assert scan_pkcs11() == []


def test_scan_returns_empty_when_library_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    """Enabling the scanner while `python-pkcs11` is not installed must
    log-and-return, never crash."""
    monkeypatch.setenv("PKCS11_SCAN_ENABLED", "true")
    monkeypatch.setenv("PKCS11_MODULE_PATH", "/nonexistent/libsofthsm2.so")
    get_settings.cache_clear()

    monkeypatch.setattr(pkcs11_scanner, "_pkcs11", None)
    assert scan_pkcs11() == []


def test_scan_returns_empty_when_module_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Enabled + library present + module path pointing at a non-file
    must not crash. Honest empty-list return is the right behaviour."""
    monkeypatch.setenv("PKCS11_SCAN_ENABLED", "true")
    monkeypatch.setenv("PKCS11_MODULE_PATH", str(tmp_path / "missing.so"))
    get_settings.cache_clear()

    # Pretend python-pkcs11 is present but the module file is not.
    monkeypatch.setattr(pkcs11_scanner, "_pkcs11", SimpleNamespace(lib=lambda p: None))
    assert scan_pkcs11() == []


def test_scan_enumerates_fake_module(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The happy path: library present, module file present, one token
    with three key objects. Every key must land as a NormalizedFinding
    and the algorithm inventory must include RSA + ECDSA + AES."""
    module_path = tmp_path / "libsofthsm2.so"
    module_path.write_bytes(b"stub")

    monkeypatch.setenv("PKCS11_SCAN_ENABLED", "true")
    monkeypatch.setenv("PKCS11_MODULE_PATH", str(module_path))
    monkeypatch.setenv("PKCS11_TOKEN_LABEL", "")
    monkeypatch.setenv("PKCS11_PIN", "")
    get_settings.cache_clear()

    @contextmanager
    def _session_ctx(objects):
        session = SimpleNamespace(get_objects=lambda _q: iter(objects))
        yield session

    class _FakeToken:
        def __init__(self, label, objects):
            self.label = label
            self._objects = objects

        def open(self, user_pin=None):
            return _session_ctx(self._objects)

    fake_token = _FakeToken("softhsm-demo", [
        {"CLASS": "PUBLIC_KEY", "KEY_TYPE": "RSA",
         "LABEL": "tls-2025", "MODULUS_BITS": 2048},
        {"CLASS": "PRIVATE_KEY", "KEY_TYPE": "EC", "LABEL": "code-sign",
         "EC_PARAMS": b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"},
        {"CLASS": "SECRET_KEY", "KEY_TYPE": "AES", "LABEL": "at-rest",
         "VALUE_LEN": 32},
    ])

    fake_module = SimpleNamespace(
        lib=lambda _path: SimpleNamespace(get_tokens=lambda: [fake_token]),
        Attribute=SimpleNamespace(),
    )
    monkeypatch.setattr(pkcs11_scanner, "_pkcs11", fake_module)

    findings = scan_pkcs11()

    assert {f.algorithm for f in findings} == {"RSA", "ECDSA", "AES"}
    assert all(f.evidence.detection_method == DetectionMethod.PKCS11_ATTESTED for f in findings)
    assert all(f.artefact_type == ArtefactType.HARDWARE_MODULE for f in findings)
    # Every finding lands at HIGH confidence -- attested is the strongest
    # key-material signal the tool produces.
    assert all(f.evidence.confidence_level == ConfidenceLevel.HIGH for f in findings)


def test_scan_filters_by_token_label(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A configured `PKCS11_TOKEN_LABEL` must limit enumeration to the
    matching token, so a multi-token module doesn't leak keys from an
    unrelated token into the report."""
    module_path = tmp_path / "libsofthsm2.so"
    module_path.write_bytes(b"stub")

    monkeypatch.setenv("PKCS11_SCAN_ENABLED", "true")
    monkeypatch.setenv("PKCS11_MODULE_PATH", str(module_path))
    monkeypatch.setenv("PKCS11_TOKEN_LABEL", "prod-signing")
    get_settings.cache_clear()

    @contextmanager
    def _session_ctx(objects):
        yield SimpleNamespace(get_objects=lambda _q: iter(objects))

    class _FakeToken:
        def __init__(self, label, objects):
            self.label = label
            self._objects = objects

        def open(self, user_pin=None):
            return _session_ctx(self._objects)

    prod_token = _FakeToken("prod-signing", [
        {"CLASS": "PRIVATE_KEY", "KEY_TYPE": "RSA",
         "LABEL": "sig-key", "MODULUS_BITS": 4096},
    ])
    dev_token = _FakeToken("dev-testing", [
        {"CLASS": "PRIVATE_KEY", "KEY_TYPE": "RSA",
         "LABEL": "throwaway", "MODULUS_BITS": 1024},
    ])

    fake_module = SimpleNamespace(
        lib=lambda _p: SimpleNamespace(get_tokens=lambda: [prod_token, dev_token]),
        Attribute=SimpleNamespace(),
    )
    monkeypatch.setattr(pkcs11_scanner, "_pkcs11", fake_module)

    findings = scan_pkcs11()

    # Only the prod token's key should surface.
    assert len(findings) == 1
    assert findings[0].parameter == "4096"


def test_scan_survives_token_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A token that raises during enumeration must not abort the whole
    scan; the log is emitted and the other tokens still contribute."""
    module_path = tmp_path / "libsofthsm2.so"
    module_path.write_bytes(b"stub")

    monkeypatch.setenv("PKCS11_SCAN_ENABLED", "true")
    monkeypatch.setenv("PKCS11_MODULE_PATH", str(module_path))
    get_settings.cache_clear()

    @contextmanager
    def _good_session():
        yield SimpleNamespace(
            get_objects=lambda _q: iter([
                {"CLASS": "PUBLIC_KEY", "KEY_TYPE": "RSA",
                 "LABEL": "good", "MODULUS_BITS": 2048},
            ])
        )

    class _GoodToken:
        label = "good"
        def open(self, user_pin=None):
            return _good_session()

    class _BadToken:
        label = "bad"
        def open(self, user_pin=None):
            raise RuntimeError("USB cable came loose")

    fake_module = SimpleNamespace(
        lib=lambda _p: SimpleNamespace(get_tokens=lambda: [_BadToken(), _GoodToken()]),
        Attribute=SimpleNamespace(),
    )
    monkeypatch.setattr(pkcs11_scanner, "_pkcs11", fake_module)

    findings = scan_pkcs11()

    # The good token's key surfaces even though the bad token crashed.
    assert len(findings) == 1
    assert findings[0].algorithm == "RSA"
