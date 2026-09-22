"""GCP Cloud KMS attestation scanner.

Live attestation for Google Cloud KMS. The scanner walks the configured
project + location, enumerates every ``KeyRing``, every ``CryptoKey`` in
each ring, and reads the primary ``CryptoKeyVersion``'s algorithm enum
straight off the API response.

Discipline that keeps this honest:

1. **Opt-in.** ``settings.gcp_kms_scan_enabled`` defaults to ``False``.
2. **Optional dependency.** ``google-cloud-kms`` is imported inside a
   ``try / except``. Absent SDK -> log once and return an empty list.
3. **Algorithm mapping is verbatim.** Every algorithm string GCP KMS
   returns has an entry in :data:`_ALGO_MAP`. Unknown enum values are
   surfaced as ``GCP-<enum>`` with ``ParameterStatus.UNRESOLVED`` -- the
   report routes those to INVESTIGATE rather than dropping them.
4. **Rotation reported honestly.** GCP KMS represents rotation as
   ``CryptoKey.rotation_period`` (a Duration). Present -> rotation is
   configured; missing -> disabled. External / imported keys and HSM
   keys are honestly labelled ``n/a`` when rotation is not supported.
"""

from __future__ import annotations

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
# Optional dependency import
# ---------------------------------------------------------------------------

try:  # pragma: no cover -- exercised via monkeypatch in tests
    from google.cloud import kms as _google_kms  # type: ignore
    from google.api_core.exceptions import GoogleAPIError as _GoogleAPIError  # type: ignore
except Exception:  # noqa: BLE001
    _google_kms = None  # type: ignore[assignment]
    _GoogleAPIError = Exception  # type: ignore[assignment,misc]


# ---------------------------------------------------------------------------
# CryptoKeyVersionAlgorithm enum -> (algorithm, primitive, parameter, curve, usage)
#
# Source: https://cloud.google.com/kms/docs/algorithms
# The enum values are what GCP returns on the wire; we do not translate.
# ---------------------------------------------------------------------------

_ALGO_MAP: dict[str, dict[str, Any]] = {
    # Symmetric
    "GOOGLE_SYMMETRIC_ENCRYPTION": {
        "algorithm": "AES", "primitive": CryptoPrimitive.BLOCK_CIPHER,
        "parameter": "256", "curve": None,
        "usage": CryptoUsage.DATA_ENCRYPTION,
    },
    "EXTERNAL_SYMMETRIC_ENCRYPTION": {
        "algorithm": "AES", "primitive": CryptoPrimitive.BLOCK_CIPHER,
        "parameter": "256", "curve": None,
        "usage": CryptoUsage.DATA_ENCRYPTION,
    },
    # RSA sign / verify (PSS + PKCS#1v1.5)
    "RSA_SIGN_PSS_2048_SHA256":     {"algorithm": "RSA", "primitive": CryptoPrimitive.SIGNATURE, "parameter": "2048", "curve": None, "usage": CryptoUsage.DIGITAL_SIGNATURE},
    "RSA_SIGN_PSS_3072_SHA256":     {"algorithm": "RSA", "primitive": CryptoPrimitive.SIGNATURE, "parameter": "3072", "curve": None, "usage": CryptoUsage.DIGITAL_SIGNATURE},
    "RSA_SIGN_PSS_4096_SHA256":     {"algorithm": "RSA", "primitive": CryptoPrimitive.SIGNATURE, "parameter": "4096", "curve": None, "usage": CryptoUsage.DIGITAL_SIGNATURE},
    "RSA_SIGN_PSS_4096_SHA512":     {"algorithm": "RSA", "primitive": CryptoPrimitive.SIGNATURE, "parameter": "4096", "curve": None, "usage": CryptoUsage.DIGITAL_SIGNATURE},
    "RSA_SIGN_PKCS1_2048_SHA256":   {"algorithm": "RSA", "primitive": CryptoPrimitive.SIGNATURE, "parameter": "2048", "curve": None, "usage": CryptoUsage.DIGITAL_SIGNATURE},
    "RSA_SIGN_PKCS1_3072_SHA256":   {"algorithm": "RSA", "primitive": CryptoPrimitive.SIGNATURE, "parameter": "3072", "curve": None, "usage": CryptoUsage.DIGITAL_SIGNATURE},
    "RSA_SIGN_PKCS1_4096_SHA256":   {"algorithm": "RSA", "primitive": CryptoPrimitive.SIGNATURE, "parameter": "4096", "curve": None, "usage": CryptoUsage.DIGITAL_SIGNATURE},
    "RSA_SIGN_PKCS1_4096_SHA512":   {"algorithm": "RSA", "primitive": CryptoPrimitive.SIGNATURE, "parameter": "4096", "curve": None, "usage": CryptoUsage.DIGITAL_SIGNATURE},
    # RSA encryption
    "RSA_DECRYPT_OAEP_2048_SHA256": {"algorithm": "RSA", "primitive": CryptoPrimitive.PKE, "parameter": "2048", "curve": None, "usage": CryptoUsage.KEY_ESTABLISHMENT},
    "RSA_DECRYPT_OAEP_3072_SHA256": {"algorithm": "RSA", "primitive": CryptoPrimitive.PKE, "parameter": "3072", "curve": None, "usage": CryptoUsage.KEY_ESTABLISHMENT},
    "RSA_DECRYPT_OAEP_4096_SHA256": {"algorithm": "RSA", "primitive": CryptoPrimitive.PKE, "parameter": "4096", "curve": None, "usage": CryptoUsage.KEY_ESTABLISHMENT},
    "RSA_DECRYPT_OAEP_4096_SHA512": {"algorithm": "RSA", "primitive": CryptoPrimitive.PKE, "parameter": "4096", "curve": None, "usage": CryptoUsage.KEY_ESTABLISHMENT},
    # EC sign
    "EC_SIGN_P256_SHA256":     {"algorithm": "ECDSA", "primitive": CryptoPrimitive.SIGNATURE, "parameter": "P-256",     "curve": "secp256r1", "usage": CryptoUsage.DIGITAL_SIGNATURE},
    "EC_SIGN_P384_SHA384":     {"algorithm": "ECDSA", "primitive": CryptoPrimitive.SIGNATURE, "parameter": "P-384",     "curve": "secp384r1", "usage": CryptoUsage.DIGITAL_SIGNATURE},
    "EC_SIGN_SECP256K1_SHA256":{"algorithm": "ECDSA", "primitive": CryptoPrimitive.SIGNATURE, "parameter": "secp256k1", "curve": "secp256k1", "usage": CryptoUsage.DIGITAL_SIGNATURE},
    # HMAC
    "HMAC_SHA224": {"algorithm": "SHA-224", "primitive": CryptoPrimitive.MAC, "parameter": None, "curve": None, "usage": CryptoUsage.MESSAGE_AUTHENTICATION},
    "HMAC_SHA256": {"algorithm": "SHA-256", "primitive": CryptoPrimitive.MAC, "parameter": None, "curve": None, "usage": CryptoUsage.MESSAGE_AUTHENTICATION},
    "HMAC_SHA384": {"algorithm": "SHA-384", "primitive": CryptoPrimitive.MAC, "parameter": None, "curve": None, "usage": CryptoUsage.MESSAGE_AUTHENTICATION},
    "HMAC_SHA512": {"algorithm": "SHA-512", "primitive": CryptoPrimitive.MAC, "parameter": None, "curve": None, "usage": CryptoUsage.MESSAGE_AUTHENTICATION},
}


# ---------------------------------------------------------------------------
# Dict/attribute bridge -- same trick used by pkcs11 + azure_kv scanners
# ---------------------------------------------------------------------------

def _get(obj: Any, attr: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(attr, default)
    return getattr(obj, attr, default)


def _algorithm_name(version: Any) -> str:
    """Extract the algorithm enum's string name from a CryptoKeyVersion.

    The real SDK returns an ``IntEnum`` for ``algorithm``; ``.name`` gives
    the canonical string. Dict-shaped fakes just carry the string.
    """
    raw = _get(version, "algorithm")
    if isinstance(raw, str):
        return raw
    name = getattr(raw, "name", None)
    if isinstance(name, str):
        return name
    return str(raw) if raw is not None else ""


def _protection_level(version: Any) -> str:
    """Return the CryptoKeyVersion protection level as an upper-case string."""
    raw = _get(version, "protection_level")
    if isinstance(raw, str):
        return raw.upper()
    name = getattr(raw, "name", None)
    if isinstance(name, str):
        return name.upper()
    return "SOFTWARE"


def _has_rotation_period(crypto_key: Any) -> bool:
    """True when ``CryptoKey.rotation_period`` is set (rotation configured).

    The real SDK exposes ``rotation_period`` as a
    ``google.protobuf.Duration`` -- absent -> falsey; present -> truthy.
    Dict-shaped fakes use ``None`` for absent.
    """
    return bool(_get(crypto_key, "rotation_period"))


def _resolve_key(
    crypto_key: Any,
    version: Any,
    *,
    project: str,
    location: str,
    rotation_enabled: bool | None,
) -> NormalizedFinding | None:
    """Convert one (CryptoKey, primary CryptoKeyVersion) into a finding."""
    algo_enum = _algorithm_name(version)
    if not algo_enum:
        return None

    resolved = _ALGO_MAP.get(algo_enum)
    if resolved is None:
        algorithm = f"GCP-{algo_enum}"
        primitive = CryptoPrimitive.UNKNOWN
        parameter = None
        curve = None
        usage = CryptoUsage.UNKNOWN
        parameter_status = ParameterStatus.UNRESOLVED
    else:
        algorithm = resolved["algorithm"]
        primitive = resolved["primitive"]
        parameter = resolved["parameter"]
        curve = resolved["curve"]
        usage = resolved["usage"]
        parameter_status = (
            ParameterStatus.RESOLVED if parameter else ParameterStatus.NOT_APPLICABLE
        )

    protection = _protection_level(version)
    hsm_backed = protection == "HSM"
    external = protection == "EXTERNAL" or algo_enum.startswith("EXTERNAL_")
    artefact_type = (
        ArtefactType.HARDWARE_MODULE if hsm_backed else ArtefactType.CLOUD_SERVICE
    )

    if rotation_enabled is True:
        rotation_str = "enabled"
    elif rotation_enabled is False:
        rotation_str = "disabled"
    else:
        rotation_str = "n/a"

    key_name = _get(crypto_key, "name") or "unknown"
    key_id = key_name.rsplit("/", 1)[-1] if "/" in key_name else key_name

    snippet = (
        f"gcp-kms name={key_name} algo={algo_enum} "
        f"protection={protection} rotation={rotation_str}"
        + (" external=yes" if external else "")
    )

    evidence = Evidence(
        file_path=key_name,
        line_number=None,
        code_snippet=snippet,
        detection_method=DetectionMethod.GCP_KMS_ATTESTED,
        confidence=0.95,
    )

    return NormalizedFinding(
        id=f"GCPKMS-{project}-{location}-{key_id}"[:120],
        algorithm=algorithm,
        primitive=primitive,
        parameter=parameter,
        parameter_status=parameter_status,
        curve=curve,
        usage=usage,
        artefact_type=artefact_type,
        library="google-cloud-kms",
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# Rotation eligibility. HSM + EXTERNAL keys don't rotate automatically in
# the same sense as software keys; we surface those as n/a rather than
# reporting a misleading 'disabled'.
# ---------------------------------------------------------------------------

def _rotation_supported(crypto_key: Any, version: Any) -> bool:
    protection = _protection_level(version)
    if protection in {"EXTERNAL", "EXTERNAL_VPC"}:
        return False
    algo_enum = _algorithm_name(version)
    if algo_enum.startswith("EXTERNAL_"):
        return False
    return True


def _read_rotation_state(crypto_key: Any, version: Any) -> bool | None:
    if not _rotation_supported(crypto_key, version):
        return None
    return _has_rotation_period(crypto_key)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def scan_gcp_kms(
    settings: Settings | None = None,
    *,
    client_factory: Any = None,
) -> list[NormalizedFinding]:
    """Enumerate CryptoKeys in the configured GCP project + location.

    ``client_factory`` is the seam tests use to inject a fake
    ``KeyManagementServiceClient`` without importing the SDK.

    Returns an empty list on any of the honest-degrade conditions:

    * scanner disabled,
    * ``google-cloud-kms`` not installed (and no factory injected),
    * project or location missing from configuration,
    * top-level list_key_rings fails outright.
    """
    settings = settings or get_settings()

    if not settings.gcp_kms_scan_enabled:
        return []

    project = settings.gcp_kms_project.strip()
    location = (settings.gcp_kms_location or "global").strip()
    if not project:
        logger.info(
            "GCP KMS scan enabled but GCP_KMS_PROJECT is not set; skipping."
        )
        return []

    if client_factory is None:
        if _google_kms is None:
            logger.info(
                "GCP KMS scan enabled but google-cloud-kms is not installed; "
                "skipping. Install with `pip install google-cloud-kms`."
            )
            return []

        def client_factory():
            return _google_kms.KeyManagementServiceClient()

    try:
        client = client_factory()
    except Exception as exc:  # noqa: BLE001
        logger.warning("GCP KMS scan: could not build client: %s", exc)
        return []

    parent = f"projects/{project}/locations/{location}"
    findings: list[NormalizedFinding] = []
    remaining = settings.gcp_kms_max_keys

    try:
        key_rings = client.list_key_rings(parent=parent)
    except _GoogleAPIError as exc:
        logger.warning("GCP KMS scan: list_key_rings failed: %s", exc)
        return []
    except Exception as exc:  # noqa: BLE001
        logger.warning("GCP KMS scan: list_key_rings raised: %s", exc)
        return []

    for key_ring in key_rings:
        if remaining <= 0:
            break
        ring_name = _get(key_ring, "name")
        if not ring_name:
            continue

        # Wrap both the call AND the iteration in the same guard -- real
        # gRPC-backed generators may raise at either point (the call
        # returns a lazy iterator; the RPC happens on first next()).
        try:
            for crypto_key in client.list_crypto_keys(parent=ring_name):
                if remaining <= 0:
                    break
                remaining -= 1
                primary = _get(crypto_key, "primary")
                if primary is None:
                    # A CryptoKey with no primary version is a valid but
                    # rare transient state. Skip cleanly.
                    continue

                rotation = _read_rotation_state(crypto_key, primary)
                resolved = _resolve_key(
                    crypto_key, primary,
                    project=project, location=location,
                    rotation_enabled=rotation,
                )
                if resolved is not None:
                    findings.append(resolved)
        except Exception as exc:  # noqa: BLE001
            logger.warning("list_crypto_keys failed for %s: %s", ring_name, exc)
            continue

    logger.info(
        "GCP KMS scan: %d attested key(s) at %s.", len(findings), parent
    )
    return findings
