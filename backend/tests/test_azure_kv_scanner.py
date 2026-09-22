"""Azure Key Vault attestation scanner tests.

Uses dict-shaped fakes for both the KeyClient and the returned key
objects, mirroring the pkcs11_scanner test pattern. That means these
tests run without ``azure-keyvault-keys`` or ``azure-identity`` being
installed -- important for keeping the demo's dependency chain small.

Coverage:

1. **Gating.** Disabled by default, empty when the SDK is missing, empty
   when ``AZURE_KV_VAULT_URL`` is unset.
2. **Key type resolution.** RSA, RSA-HSM, EC, EC-HSM, oct, oct-HSM all
   surface with the right algorithm / primitive / artefact type.
3. **RSA size derivation.** JWK ``n`` (modulus) length translates to the
   canonical 2048 / 3072 / 4096 bit sizes.
4. **EC curve mapping.** P-256 / P-384 / P-521 / P-256K all map to the
   pipeline's canonical parameter + curve names.
5. **Rotation policy read.** A policy with a Rotate lifetime action
   surfaces as rotation=enabled; no policy or no Rotate action surfaces
   as disabled; a failing call surfaces as n/a.
6. **HSM-backed keys** additionally carry ArtefactType.HARDWARE_MODULE.
7. **Resilience.** A failed get_key on one key does not kill the scan.
"""

from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest

from app.config import get_settings
from app.models.asset import ArtefactType, CryptoPrimitive
from app.models.finding import DetectionMethod
from app.scanner import azure_kv as azure_kv_module
from app.scanner.azure_kv import _resolve_key, scan_azure_kv


VAULT_URL = "https://demo-vault.vault.azure.net"


def _b64url(nbytes: int) -> str:
    """Return a base64url-encoded string whose decoded length is *nbytes*."""
    raw = b"\xAB" * nbytes
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# _resolve_key -- pure data, no I/O
# ---------------------------------------------------------------------------

def test_resolve_rsa_2048_key_from_jwk() -> None:
    kv_key = {
        "name": "rsa-signing",
        "key": {"kty": "RSA", "n": _b64url(256)},  # 256 bytes = 2048 bits
    }
    finding = _resolve_key(kv_key, vault_url=VAULT_URL)
    assert finding is not None
    assert finding.algorithm == "RSA"
    assert finding.parameter == "2048"
    assert finding.primitive == CryptoPrimitive.PKE
    assert finding.artefact_type == ArtefactType.CLOUD_SERVICE
    assert finding.evidence.detection_method == DetectionMethod.AZURE_KV_ATTESTED


@pytest.mark.parametrize("modulus_bytes, expected_bits", [
    (128, 1024),
    (256, 2048),
    (384, 3072),
    (512, 4096),
])
def test_resolve_rsa_key_size_from_modulus_length(
    modulus_bytes: int, expected_bits: int
) -> None:
    kv_key = {
        "name": "rsa",
        "key": {"kty": "RSA", "n": _b64url(modulus_bytes)},
    }
    finding = _resolve_key(kv_key, vault_url=VAULT_URL)
    assert finding is not None
    assert finding.parameter == str(expected_bits)


def test_resolve_rsa_hsm_key_flags_hardware_module() -> None:
    kv_key = {
        "name": "rsa-hsm-key",
        "key": {"kty": "RSA-HSM", "n": _b64url(256)},
    }
    finding = _resolve_key(kv_key, vault_url=VAULT_URL)
    assert finding is not None
    assert finding.algorithm == "RSA"
    assert finding.artefact_type == ArtefactType.HARDWARE_MODULE, (
        "HSM-backed keys must be tagged as hardware modules so the "
        "inventory keeps software-vs-hardware distinction intact."
    )


@pytest.mark.parametrize("crv, expected_param, expected_curve", [
    ("P-256", "P-256", "secp256r1"),
    ("P-384", "P-384", "secp384r1"),
    ("P-521", "P-521", "secp521r1"),
    ("P-256K", "secp256k1", "secp256k1"),
])
def test_resolve_ec_curves(crv: str, expected_param: str, expected_curve: str) -> None:
    kv_key = {
        "name": f"ec-{crv}",
        "key": {"kty": "EC", "crv": crv},
    }
    finding = _resolve_key(kv_key, vault_url=VAULT_URL)
    assert finding is not None
    assert finding.algorithm == "ECDSA"
    assert finding.parameter == expected_param
    assert finding.curve == expected_curve


def test_resolve_ec_hsm_flags_hardware_module() -> None:
    kv_key = {"name": "ec-hsm", "key": {"kty": "EC-HSM", "crv": "P-256"}}
    finding = _resolve_key(kv_key, vault_url=VAULT_URL)
    assert finding is not None
    assert finding.artefact_type == ArtefactType.HARDWARE_MODULE


def test_resolve_oct_key_surfaces_as_aes() -> None:
    kv_key = {
        "name": "oct-key",
        "key": {"kty": "oct", "key_size": 256},
    }
    finding = _resolve_key(kv_key, vault_url=VAULT_URL)
    assert finding is not None
    assert finding.algorithm == "AES"
    assert finding.parameter == "256"


def test_resolve_unknown_kty_surfaces_verbatim() -> None:
    kv_key = {"name": "future", "key": {"kty": "PQC-KEM"}}
    finding = _resolve_key(kv_key, vault_url=VAULT_URL)
    assert finding is not None
    assert finding.algorithm == "AzureKV-PQC-KEM"


def test_resolve_missing_kty_returns_none() -> None:
    assert _resolve_key({"name": "no-kty", "key": {}}, vault_url=VAULT_URL) is None


def test_snippet_carries_rotation_state() -> None:
    kv_key = {"name": "k1", "key": {"kty": "RSA", "n": _b64url(256)}}
    assert "rotation=enabled" in _resolve_key(
        kv_key, vault_url=VAULT_URL, rotation_enabled=True
    ).evidence.code_snippet
    assert "rotation=disabled" in _resolve_key(
        kv_key, vault_url=VAULT_URL, rotation_enabled=False
    ).evidence.code_snippet
    assert "rotation=n/a" in _resolve_key(
        kv_key, vault_url=VAULT_URL, rotation_enabled=None
    ).evidence.code_snippet


# ---------------------------------------------------------------------------
# Fake client for full-scan tests
# ---------------------------------------------------------------------------

class _FakeKeyClient:
    """Minimum surface of :class:`azure.keyvault.keys.KeyClient` the
    scanner touches. Deterministic and independent of any Azure SDK."""

    def __init__(
        self,
        *,
        keys: list[dict],
        rotation_by_name: dict[str, list[dict]] | None = None,
        fail_on_key: str | None = None,
    ) -> None:
        self._keys = keys
        self._rotation = rotation_by_name or {}
        self._fail_on_key = fail_on_key

    def list_properties_of_keys(self):
        for k in self._keys:
            yield SimpleNamespace(name=k["name"])

    def get_key(self, name: str):
        if name == self._fail_on_key:
            raise RuntimeError("simulated Azure transient error")
        for k in self._keys:
            if k["name"] == name:
                return k
        raise KeyError(name)

    def get_key_rotation_policy(self, name: str):
        actions = self._rotation.get(name)
        if actions is None:
            raise RuntimeError("no rotation policy configured")
        return SimpleNamespace(lifetime_actions=actions)


# ---------------------------------------------------------------------------
# scan_azure_kv -- gating + fake-client end-to-end
# ---------------------------------------------------------------------------

def test_scan_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AZURE_KV_SCAN_ENABLED", raising=False)
    get_settings.cache_clear()
    assert scan_azure_kv() == []


def test_scan_returns_empty_without_vault_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Enabled + missing vault URL => honest empty list, not a crash."""
    monkeypatch.setenv("AZURE_KV_SCAN_ENABLED", "true")
    monkeypatch.setenv("AZURE_KV_VAULT_URL", "")
    get_settings.cache_clear()
    assert scan_azure_kv() == []


def test_scan_returns_empty_when_sdk_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SDK absent + enabled + URL present => log & return empty."""
    monkeypatch.setenv("AZURE_KV_SCAN_ENABLED", "true")
    monkeypatch.setenv("AZURE_KV_VAULT_URL", VAULT_URL)
    get_settings.cache_clear()

    monkeypatch.setattr(azure_kv_module, "_KeyClient", None)
    monkeypatch.setattr(azure_kv_module, "_DefaultAzureCredential", None)
    assert scan_azure_kv() == []


def test_scan_enumerates_keys_via_injected_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AZURE_KV_SCAN_ENABLED", "true")
    monkeypatch.setenv("AZURE_KV_VAULT_URL", VAULT_URL)
    get_settings.cache_clear()

    fake = _FakeKeyClient(keys=[
        {"name": "rsa", "key": {"kty": "RSA", "n": _b64url(256)}},
        {"name": "ec", "key": {"kty": "EC", "crv": "P-256"}},
        {"name": "aes", "key": {"kty": "oct", "key_size": 256}},
    ])
    findings = scan_azure_kv(client_factory=lambda: fake)

    algos = sorted(f.algorithm for f in findings)
    assert algos == ["AES", "ECDSA", "RSA"]
    for f in findings:
        assert f.evidence.detection_method == DetectionMethod.AZURE_KV_ATTESTED


def test_scan_reads_rotation_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_KV_SCAN_ENABLED", "true")
    monkeypatch.setenv("AZURE_KV_VAULT_URL", VAULT_URL)
    get_settings.cache_clear()

    fake = _FakeKeyClient(
        keys=[{"name": "rotates", "key": {"kty": "RSA", "n": _b64url(256)}}],
        rotation_by_name={"rotates": [{"action": "Rotate"}]},
    )
    findings = scan_azure_kv(client_factory=lambda: fake)
    assert len(findings) == 1
    assert "rotation=enabled" in findings[0].evidence.code_snippet


def test_scan_reports_disabled_when_policy_has_no_rotate_action(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AZURE_KV_SCAN_ENABLED", "true")
    monkeypatch.setenv("AZURE_KV_VAULT_URL", VAULT_URL)
    get_settings.cache_clear()

    fake = _FakeKeyClient(
        keys=[{"name": "notify-only", "key": {"kty": "RSA", "n": _b64url(256)}}],
        rotation_by_name={"notify-only": [{"action": "Notify"}]},
    )
    findings = scan_azure_kv(client_factory=lambda: fake)
    assert "rotation=disabled" in findings[0].evidence.code_snippet


def test_scan_reports_na_when_rotation_call_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AZURE_KV_SCAN_ENABLED", "true")
    monkeypatch.setenv("AZURE_KV_VAULT_URL", VAULT_URL)
    get_settings.cache_clear()

    fake = _FakeKeyClient(
        keys=[{"name": "opaque", "key": {"kty": "RSA", "n": _b64url(256)}}],
        # No rotation policy entry => get_key_rotation_policy raises.
    )
    findings = scan_azure_kv(client_factory=lambda: fake)
    assert "rotation=n/a" in findings[0].evidence.code_snippet


def test_scan_survives_get_key_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_KV_SCAN_ENABLED", "true")
    monkeypatch.setenv("AZURE_KV_VAULT_URL", VAULT_URL)
    get_settings.cache_clear()

    fake = _FakeKeyClient(
        keys=[
            {"name": "broken", "key": {"kty": "RSA", "n": _b64url(256)}},
            {"name": "ok", "key": {"kty": "EC", "crv": "P-256"}},
        ],
        fail_on_key="broken",
    )
    findings = scan_azure_kv(client_factory=lambda: fake)
    assert len(findings) == 1
    assert findings[0].id == "AZUREKV-ok"


def test_scan_respects_max_keys_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_KV_SCAN_ENABLED", "true")
    monkeypatch.setenv("AZURE_KV_VAULT_URL", VAULT_URL)
    monkeypatch.setenv("AZURE_KV_MAX_KEYS", "2")
    get_settings.cache_clear()

    fake = _FakeKeyClient(keys=[
        {"name": f"k{i}", "key": {"kty": "RSA", "n": _b64url(256)}}
        for i in range(5)
    ])
    findings = scan_azure_kv(client_factory=lambda: fake)
    assert len(findings) == 2


def test_client_build_failure_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_KV_SCAN_ENABLED", "true")
    monkeypatch.setenv("AZURE_KV_VAULT_URL", VAULT_URL)
    get_settings.cache_clear()

    def broken_factory():
        raise RuntimeError("credentials misconfigured")

    assert scan_azure_kv(client_factory=broken_factory) == []
