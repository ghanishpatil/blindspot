"""GCP Cloud KMS attestation scanner tests.

Same discipline as the Azure tests: dict-shaped fakes for the client and
returned objects, so no ``google-cloud-kms`` install is required to run
the suite.

Coverage:

1. **Gating.** Disabled by default, empty when the SDK is missing, empty
   without a project id.
2. **Algorithm enum mapping.** Every entry in ``_ALGO_MAP`` (RSA / EC /
   HMAC / symmetric) resolves to the expected algorithm / parameter.
3. **Unknown enum values** surface verbatim as ``GCP-<enum>`` with
   ``ParameterStatus.UNRESOLVED``.
4. **Rotation** reports enabled when ``rotation_period`` is set,
   disabled when absent, n/a when protection level is EXTERNAL or the
   algorithm enum starts with ``EXTERNAL_``.
5. **HSM protection level** flags ``ArtefactType.HARDWARE_MODULE``.
6. **Resilience.** A single ``list_crypto_keys`` failure on one ring
   does not sink the whole scan.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.config import get_settings
from app.models.asset import ArtefactType, CryptoPrimitive, ParameterStatus
from app.models.finding import DetectionMethod
from app.scanner import gcp_kms as gcp_kms_module
from app.scanner.gcp_kms import _resolve_key, scan_gcp_kms


PROJECT = "demo-project"
LOCATION = "global"


def _version(algorithm: str, *, protection: str = "SOFTWARE") -> dict:
    return {
        "algorithm": algorithm,
        "protection_level": protection,
    }


def _crypto_key(name: str, version: dict, rotation_period: object | None = None) -> dict:
    return {
        "name": (
            f"projects/{PROJECT}/locations/{LOCATION}/keyRings/ring/cryptoKeys/{name}"
        ),
        "primary": version,
        "rotation_period": rotation_period,
    }


# ---------------------------------------------------------------------------
# _resolve_key -- pure data
# ---------------------------------------------------------------------------

def test_resolve_google_symmetric_encryption() -> None:
    key = _crypto_key("aes", _version("GOOGLE_SYMMETRIC_ENCRYPTION"))
    finding = _resolve_key(
        key, key["primary"], project=PROJECT, location=LOCATION,
        rotation_enabled=True,
    )
    assert finding is not None
    assert finding.algorithm == "AES"
    assert finding.parameter == "256"
    assert finding.primitive == CryptoPrimitive.BLOCK_CIPHER
    assert finding.evidence.detection_method == DetectionMethod.GCP_KMS_ATTESTED
    assert "rotation=enabled" in finding.evidence.code_snippet


@pytest.mark.parametrize("algo,expected_algo,expected_param", [
    ("RSA_SIGN_PSS_2048_SHA256",     "RSA",   "2048"),
    ("RSA_SIGN_PSS_3072_SHA256",     "RSA",   "3072"),
    ("RSA_SIGN_PSS_4096_SHA256",     "RSA",   "4096"),
    ("RSA_SIGN_PKCS1_2048_SHA256",   "RSA",   "2048"),
    ("RSA_DECRYPT_OAEP_2048_SHA256", "RSA",   "2048"),
    ("EC_SIGN_P256_SHA256",          "ECDSA", "P-256"),
    ("EC_SIGN_P384_SHA384",          "ECDSA", "P-384"),
    ("EC_SIGN_SECP256K1_SHA256",     "ECDSA", "secp256k1"),
    ("HMAC_SHA256",                  "SHA-256", None),
])
def test_resolve_algorithm_mapping(
    algo: str, expected_algo: str, expected_param: str | None
) -> None:
    key = _crypto_key(algo.lower(), _version(algo))
    finding = _resolve_key(
        key, key["primary"], project=PROJECT, location=LOCATION,
        rotation_enabled=False,
    )
    assert finding is not None
    assert finding.algorithm == expected_algo
    assert finding.parameter == expected_param


def test_resolve_hsm_protection_flags_hardware_module() -> None:
    key = _crypto_key(
        "hsm-signing",
        _version("EC_SIGN_P256_SHA256", protection="HSM"),
    )
    finding = _resolve_key(
        key, key["primary"], project=PROJECT, location=LOCATION,
        rotation_enabled=False,
    )
    assert finding is not None
    assert finding.artefact_type == ArtefactType.HARDWARE_MODULE


def test_resolve_external_symmetric_surfaces_as_aes_but_external_tagged() -> None:
    key = _crypto_key(
        "ext-key",
        _version("EXTERNAL_SYMMETRIC_ENCRYPTION", protection="EXTERNAL"),
    )
    finding = _resolve_key(
        key, key["primary"], project=PROJECT, location=LOCATION,
        rotation_enabled=None,   # <- rotation N/A for external keys
    )
    assert finding is not None
    assert finding.algorithm == "AES"
    assert "external=yes" in finding.evidence.code_snippet
    assert "rotation=n/a" in finding.evidence.code_snippet


def test_resolve_unknown_algo_surfaces_verbatim() -> None:
    key = _crypto_key("future", _version("PQC_KEM_2048"))
    finding = _resolve_key(
        key, key["primary"], project=PROJECT, location=LOCATION,
        rotation_enabled=None,
    )
    assert finding is not None
    assert finding.algorithm == "GCP-PQC_KEM_2048"
    assert finding.parameter_status == ParameterStatus.UNRESOLVED


def test_resolve_returns_none_without_algorithm() -> None:
    key = _crypto_key("nameless", {"algorithm": "", "protection_level": "SOFTWARE"})
    assert _resolve_key(
        key, key["primary"], project=PROJECT, location=LOCATION,
        rotation_enabled=None,
    ) is None


# ---------------------------------------------------------------------------
# Fake KMS client
# ---------------------------------------------------------------------------

class _FakeKmsClient:
    """Minimum surface of KeyManagementServiceClient the scanner touches."""

    def __init__(
        self,
        *,
        keys_by_ring: dict[str, list[dict]],
        fail_on_ring: str | None = None,
    ) -> None:
        self._keys_by_ring = keys_by_ring
        self._fail_on_ring = fail_on_ring

    def list_key_rings(self, *, parent):
        for ring_name in self._keys_by_ring:
            yield SimpleNamespace(name=f"{parent}/keyRings/{ring_name}")

    def list_crypto_keys(self, *, parent):
        ring = parent.rsplit("/", 1)[-1]
        if ring == self._fail_on_ring:
            raise RuntimeError("simulated GCP transient error")
        for key_dict in self._keys_by_ring.get(ring, []):
            # Rewrite the crypto key's name to sit under this parent so
            # the paths line up.
            key_dict = {**key_dict, "name": f"{parent}/cryptoKeys/{key_dict['name'].rsplit('/', 1)[-1]}"}
            yield key_dict


# ---------------------------------------------------------------------------
# scan_gcp_kms end-to-end
# ---------------------------------------------------------------------------

def test_scan_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GCP_KMS_SCAN_ENABLED", raising=False)
    get_settings.cache_clear()
    assert scan_gcp_kms() == []


def test_scan_empty_without_project(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GCP_KMS_SCAN_ENABLED", "true")
    monkeypatch.setenv("GCP_KMS_PROJECT", "")
    get_settings.cache_clear()
    assert scan_gcp_kms() == []


def test_scan_empty_when_sdk_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GCP_KMS_SCAN_ENABLED", "true")
    monkeypatch.setenv("GCP_KMS_PROJECT", PROJECT)
    get_settings.cache_clear()
    monkeypatch.setattr(gcp_kms_module, "_google_kms", None)
    assert scan_gcp_kms() == []


def test_scan_walks_rings_and_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GCP_KMS_SCAN_ENABLED", "true")
    monkeypatch.setenv("GCP_KMS_PROJECT", PROJECT)
    get_settings.cache_clear()

    fake = _FakeKmsClient(keys_by_ring={
        "prod": [
            _crypto_key("db-encrypt", _version("GOOGLE_SYMMETRIC_ENCRYPTION"),
                        rotation_period="7776000s"),   # rotates
            _crypto_key("jwt-sign", _version("EC_SIGN_P256_SHA256")),
        ],
        "staging": [
            _crypto_key("rsa-2048", _version("RSA_SIGN_PSS_2048_SHA256"),
                        rotation_period="7776000s"),
        ],
    })

    findings = scan_gcp_kms(client_factory=lambda: fake)
    algos = sorted(f.algorithm for f in findings)
    assert algos == ["AES", "ECDSA", "RSA"]

    aes = next(f for f in findings if f.algorithm == "AES")
    assert "rotation=enabled" in aes.evidence.code_snippet
    ec = next(f for f in findings if f.algorithm == "ECDSA")
    assert "rotation=disabled" in ec.evidence.code_snippet


def test_scan_survives_list_error_on_one_ring(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GCP_KMS_SCAN_ENABLED", "true")
    monkeypatch.setenv("GCP_KMS_PROJECT", PROJECT)
    get_settings.cache_clear()

    fake = _FakeKmsClient(
        keys_by_ring={
            "prod": [_crypto_key("k1", _version("GOOGLE_SYMMETRIC_ENCRYPTION"))],
            "broken": [_crypto_key("k2", _version("EC_SIGN_P256_SHA256"))],
        },
        fail_on_ring="broken",
    )
    findings = scan_gcp_kms(client_factory=lambda: fake)
    assert len(findings) == 1
    assert findings[0].algorithm == "AES"


def test_scan_respects_max_keys_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GCP_KMS_SCAN_ENABLED", "true")
    monkeypatch.setenv("GCP_KMS_PROJECT", PROJECT)
    monkeypatch.setenv("GCP_KMS_MAX_KEYS", "2")
    get_settings.cache_clear()

    fake = _FakeKmsClient(keys_by_ring={
        "prod": [
            _crypto_key(f"k{i}", _version("GOOGLE_SYMMETRIC_ENCRYPTION"))
            for i in range(5)
        ],
    })
    findings = scan_gcp_kms(client_factory=lambda: fake)
    assert len(findings) == 2


def test_scan_skips_crypto_keys_without_primary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A CryptoKey with no primary CryptoKeyVersion is a transient state
    that must be skipped without an exception."""
    monkeypatch.setenv("GCP_KMS_SCAN_ENABLED", "true")
    monkeypatch.setenv("GCP_KMS_PROJECT", PROJECT)
    get_settings.cache_clear()

    fake = _FakeKmsClient(keys_by_ring={
        "prod": [
            {"name": f"projects/{PROJECT}/locations/{LOCATION}/keyRings/prod/cryptoKeys/none", "primary": None},
            _crypto_key("has-primary", _version("GOOGLE_SYMMETRIC_ENCRYPTION")),
        ],
    })
    findings = scan_gcp_kms(client_factory=lambda: fake)
    assert len(findings) == 1
    assert findings[0].algorithm == "AES"


def test_client_build_failure_returns_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GCP_KMS_SCAN_ENABLED", "true")
    monkeypatch.setenv("GCP_KMS_PROJECT", PROJECT)
    get_settings.cache_clear()

    def broken_factory():
        raise RuntimeError("no ADC")

    assert scan_gcp_kms(client_factory=broken_factory) == []
