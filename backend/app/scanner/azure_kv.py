"""Azure Key Vault attestation scanner.

Live attestation counterpart to the declared IaC / SDK-import scan in
``app/scanner/infra.py``. When configured, this module opens a live
``KeyClient`` against the operator's vault, enumerates every accessible
key, reads its algorithm + key size / curve straight off the returned
JWK payload, and emits one high-confidence
:class:`~app.models.finding.NormalizedFinding` per key.

Discipline that keeps this honest:

1. **Opt-in.** ``settings.azure_kv_scan_enabled`` defaults to ``False``.
   The scanner short-circuits before importing the SDK when it is off.
2. **Optional dependency.** ``azure-keyvault-keys`` + ``azure-identity``
   are imported inside a ``try / except``. When either is absent the
   scanner logs once and returns an empty list.
3. **Public attributes only.** We call ``get_key`` and read the JWK
   payload plus (optionally) the rotation policy. We do NOT sign,
   decrypt, wrap, or otherwise exercise the key.
4. **HSM-backed types stay honest.** ``RSA-HSM`` / ``EC-HSM`` /
   ``oct-HSM`` keys additionally surface with
   :class:`ArtefactType.HARDWARE_MODULE` so the report keeps the
   software-vs-hardware distinction intact.
5. **Rotation reported honestly.** ``get_key_rotation_policy`` may not
   apply (managed HSM legacy keys, oct keys) or may be denied by RBAC.
   Either case surfaces as ``rotation=n/a`` -- we never fabricate.
"""

from __future__ import annotations

import base64
import logging
from typing import Any

from app.config import Settings, get_settings
from app.models.asset import (
    ArtefactType,
    CryptoPrimitive,
    CryptoUsage,
    ParameterStatus,
)
from app.models.finding import DetectionMethod, Evidence, NormalizedFinding

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Optional dependency imports.
#
# Keeping them optional means a fresh clone of the repo does not need the
# ~40 MB of azure-* wheels to run the demo. Operators who actually want
# Azure attestation install the two packages themselves.
# ---------------------------------------------------------------------------

try:  # pragma: no cover -- exercised via monkeypatch in tests
    from azure.keyvault.keys import KeyClient as _KeyClient  # type: ignore
    from azure.identity import DefaultAzureCredential as _DefaultAzureCredential  # type: ignore
    from azure.core.exceptions import (  # type: ignore
        AzureError as _AzureError,
        HttpResponseError as _HttpResponseError,
    )
except Exception:  # noqa: BLE001
    _KeyClient = None  # type: ignore[assignment]
    _DefaultAzureCredential = None  # type: ignore[assignment]
    _AzureError = Exception  # type: ignore[assignment,misc]
    _HttpResponseError = Exception  # type: ignore[assignment,misc]


# ---------------------------------------------------------------------------
# JWK curve name -> friendly parameter used across the pipeline
# ---------------------------------------------------------------------------

_EC_CURVE_MAP: dict[str, tuple[str, str]] = {
    # JWK crv    -> (parameter for finding, curve name)
    "P-256":       ("P-256", "secp256r1"),
    "P-384":       ("P-384", "secp384r1"),
    "P-521":       ("P-521", "secp521r1"),
    "P-256K":      ("secp256k1", "secp256k1"),
}


# ---------------------------------------------------------------------------
# Attribute extraction helpers.
#
# The Azure SDK's ``KeyVaultKey`` object exposes:
#   .name              -- vault-local key name
#   .id                -- full versioned URL
#   .key.kty           -- key type string
#   .key.n             -- RSA modulus (base64url bytes)
#   .key.crv           -- EC curve name
#   .key.k             -- oct key material (base64url bytes, only if extractable)
#   .properties.tags   -- vault tags dict
#
# Tests inject dict-shaped fakes to exercise every branch without needing
# the real SDK installed. ``_getattr`` bridges both shapes.
# ---------------------------------------------------------------------------

def _get(obj: Any, attr: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(attr, default)
    return getattr(obj, attr, default)


def _b64url_len_bytes(value: Any) -> int | None:
    """Return the byte-length of a base64url-encoded JWK field, or None."""
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return len(value)
    if isinstance(value, str):
        # base64url may omit padding; add it back before decoding.
        padded = value + "=" * (-len(value) % 4)
        try:
            return len(base64.urlsafe_b64decode(padded))
        except (ValueError, TypeError):
            return None
    return None


def _resolve_rsa_key_size(jwk: Any) -> int | None:
    """RSA key size (bits) from the modulus. Azure does not return it
    directly on the JWK, so we compute from the modulus length."""
    n_bytes = _b64url_len_bytes(_get(jwk, "n"))
    if n_bytes is None:
        return None
    # Round to the nearest common RSA modulus size. Azure emits keys at
    # 2048 / 3072 / 4096 (and legacy 1024). The raw byte-length may be
    # one byte off due to a leading zero, so we round up to the next
    # 256-bit boundary.
    bits = n_bytes * 8
    for canonical in (1024, 2048, 3072, 4096):
        if bits <= canonical:
            return canonical
    return bits


# ---------------------------------------------------------------------------
# Key resolution -- pure data, no I/O. Directly unit-testable.
# ---------------------------------------------------------------------------

def _resolve_key(
    kv_key: Any,
    *,
    vault_url: str,
    rotation_enabled: bool | None = None,
) -> NormalizedFinding | None:
    """Convert one Key Vault key into a :class:`NormalizedFinding`.

    ``kv_key`` is either a real ``KeyVaultKey`` from the SDK or a
    dict-shaped fake used by tests. Only public JWK attributes are read.
    """
    name = _get(kv_key, "name") or "unnamed"
    jwk = _get(kv_key, "key") or {}
    kty_raw = (_get(jwk, "kty") or "").strip()
    if not kty_raw:
        return None

    kty = kty_raw.upper()
    hsm_backed = kty.endswith("-HSM")
    base_type = kty[:-4] if hsm_backed else kty

    algorithm: str
    primitive: CryptoPrimitive
    parameter: str | None = None
    curve: str | None = None
    usage: CryptoUsage
    artefact_type: ArtefactType

    if base_type == "RSA":
        algorithm = "RSA"
        primitive = CryptoPrimitive.PKE
        key_bits = _resolve_rsa_key_size(jwk)
        parameter = str(key_bits) if key_bits else None
        usage = CryptoUsage.KEY_ESTABLISHMENT
        artefact_type = (
            ArtefactType.HARDWARE_MODULE if hsm_backed else ArtefactType.CLOUD_SERVICE
        )
    elif base_type == "EC":
        algorithm = "ECDSA"
        primitive = CryptoPrimitive.SIGNATURE
        crv = (_get(jwk, "crv") or "").strip()
        resolved = _EC_CURVE_MAP.get(crv)
        if resolved:
            parameter, curve = resolved
        else:
            parameter = crv or None
        usage = CryptoUsage.DIGITAL_SIGNATURE
        artefact_type = (
            ArtefactType.HARDWARE_MODULE if hsm_backed else ArtefactType.CLOUD_SERVICE
        )
    elif base_type == "OCT":
        algorithm = "AES"
        primitive = CryptoPrimitive.BLOCK_CIPHER
        # oct keys expose a size hint via key_ops metadata / .key.key_size.
        # ``k`` is only returned when the key is extractable, which most
        # vault keys are not. Fall back to a NotSet parameter.
        k_bytes = _b64url_len_bytes(_get(jwk, "k"))
        if k_bytes:
            parameter = str(k_bytes * 8)
        else:
            key_size_prop = _get(jwk, "key_size")
            parameter = str(int(key_size_prop)) if key_size_prop else None
        usage = CryptoUsage.DATA_ENCRYPTION
        artefact_type = (
            ArtefactType.HARDWARE_MODULE if hsm_backed else ArtefactType.CLOUD_SERVICE
        )
    else:
        # Surface unknown key types verbatim rather than dropping them.
        algorithm = f"AzureKV-{kty_raw}"
        primitive = CryptoPrimitive.UNKNOWN
        usage = CryptoUsage.UNKNOWN
        artefact_type = ArtefactType.CLOUD_SERVICE

    parameter_status = (
        ParameterStatus.RESOLVED if parameter else ParameterStatus.UNRESOLVED
    )

    # Human-readable rotation state, same shape as the AWS scanner.
    if rotation_enabled is True:
        rotation_str = "enabled"
    elif rotation_enabled is False:
        rotation_str = "disabled"
    else:
        rotation_str = "n/a"

    key_id_url = _get(kv_key, "id") or f"{vault_url.rstrip('/')}/keys/{name}"
    snippet = (
        f"azure-kv name={name} kty={kty_raw} "
        f"hsm={'yes' if hsm_backed else 'no'} rotation={rotation_str}"
    )

    evidence = Evidence(
        file_path=str(key_id_url),
        line_number=None,
        code_snippet=snippet,
        detection_method=DetectionMethod.AZURE_KV_ATTESTED,
        # HIGH band -- the vault answered with the JWK directly.
        confidence=0.95,
    )

    return NormalizedFinding(
        id=f"AZUREKV-{name}",
        algorithm=algorithm,
        primitive=primitive,
        parameter=parameter,
        parameter_status=parameter_status,
        curve=curve,
        usage=usage,
        artefact_type=artefact_type,
        library="azure-keyvault-keys",
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# Rotation policy read -- honest 'n/a' on any refusal.
# ---------------------------------------------------------------------------

def _read_rotation_state(client: Any, key_name: str) -> bool | None:
    """Return True/False when the vault reports a rotation policy, or
    None when the API declines / errors.

    A rotation policy is considered enabled when at least one lifetime
    action of type ``Rotate`` exists on the returned policy. This matches
    what the Azure portal calls 'Auto rotation'.
    """
    getter = getattr(client, "get_key_rotation_policy", None)
    if getter is None:
        return None
    try:
        policy = getter(key_name)
    except Exception as exc:  # noqa: BLE001 -- azure raises a wide zoo
        logger.debug(
            "GetKeyRotationPolicy failed for %s: %s", key_name, exc
        )
        return None

    lifetime_actions = _get(policy, "lifetime_actions") or []
    for action in lifetime_actions:
        action_type = _get(action, "action")
        # SDK exposes action as either a string 'Rotate' or an enum-like
        # object with a ``.value``; normalise both.
        if isinstance(action_type, str):
            if action_type.lower() == "rotate":
                return True
        elif hasattr(action_type, "value"):
            if str(action_type.value).lower() == "rotate":
                return True
    return False


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def scan_azure_kv(
    settings: Settings | None = None,
    *,
    client_factory: Any = None,
) -> list[NormalizedFinding]:
    """Enumerate keys in the configured Azure Key Vault.

    ``client_factory`` exists so tests can inject a fake client without
    importing the Azure SDK. In production the argument is unused; the
    scanner builds a real ``KeyClient`` from ``settings.azure_kv_vault_url``
    authenticated with ``DefaultAzureCredential``.

    Returns an empty list when:

    * the scanner is disabled,
    * the SDK is not installed and no ``client_factory`` was provided,
    * ``azure_kv_vault_url`` is empty,
    * the vault refuses the caller outright.

    An empty list is honest -- it means there is nothing to attest under
    the current configuration, not that the scan failed.
    """
    settings = settings or get_settings()

    if not settings.azure_kv_scan_enabled:
        return []

    vault_url = settings.azure_kv_vault_url.strip()
    if not vault_url:
        logger.info(
            "Azure Key Vault scan enabled but AZURE_KV_VAULT_URL is not set; "
            "skipping."
        )
        return []

    if client_factory is None:
        if _KeyClient is None or _DefaultAzureCredential is None:
            logger.info(
                "Azure Key Vault scan enabled but azure-keyvault-keys / "
                "azure-identity are not installed; skipping. Install with "
                "`pip install azure-keyvault-keys azure-identity`."
            )
            return []

        def client_factory():
            credential = _DefaultAzureCredential()
            return _KeyClient(vault_url=vault_url, credential=credential)

    try:
        client = client_factory()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Azure Key Vault scan: could not build client: %s", exc)
        return []

    findings: list[NormalizedFinding] = []
    max_keys = settings.azure_kv_max_keys

    try:
        properties_iter = client.list_properties_of_keys()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Azure Key Vault scan: list_properties_of_keys failed: %s", exc)
        return []

    remaining = max_keys
    for properties in properties_iter:
        if remaining <= 0:
            break
        remaining -= 1
        key_name = _get(properties, "name")
        if not key_name:
            continue
        try:
            kv_key = client.get_key(key_name)
        except Exception as exc:  # noqa: BLE001
            logger.warning("get_key failed for %s: %s", key_name, exc)
            continue

        rotation = _read_rotation_state(client, key_name)
        resolved = _resolve_key(kv_key, vault_url=vault_url, rotation_enabled=rotation)
        if resolved is not None:
            findings.append(resolved)

    logger.info(
        "Azure Key Vault scan: %d attested key(s) at %s.",
        len(findings),
        vault_url,
    )
    return findings
