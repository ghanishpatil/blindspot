"""AWS KMS attestation scanner -- R8.

The PS names *cloud services* as an artefact class to catalogue. The existing
``app/scanner/infra.py`` covers *declared* KMS references in Terraform /
CloudFormation / SDK code; this module handles the *attested* side: it uses
boto3 to list keys in an AWS account, calls ``DescribeKey`` on each one, and
reports the ``KeySpec`` / ``KeyUsage`` verbatim as a high-confidence finding.

Discipline that keeps this honest:

1. **The scanner is opt-in.** ``settings.aws_kms_scan_enabled`` defaults to
   ``False``. When the flag is off the scanner returns an empty list
   before any AWS call is attempted.
2. **The dependency is optional.** ``boto3`` is imported inside a
   ``try/except`` block. When it is not installed the scanner logs once
   and short-circuits.
3. **No credentials are ever taken from a request.** boto3's default
   credential resolution (env vars, ``~/.aws/credentials``, IAM role) is
   the only source. Requests never carry AWS keys.
4. **Only ``DescribeKey`` metadata is read.** We do *not* call
   ``GetKeyPolicy``, ``GetKeyRotationStatus``, or any signing / encryption
   operation. The scanner reads the algorithm classification and stops.
5. **AWS multi-region keys and pending-deletion keys** are surfaced with
   an honest ``KeyState`` label in the evidence snippet -- they are
   inventory items whether the caller currently uses them or not.
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
    import boto3 as _boto3
    from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
except Exception:  # noqa: BLE001
    _boto3 = None  # type: ignore[assignment]
    BotoCoreError = ClientError = NoCredentialsError = Exception  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# KeySpec -> (algorithm, primitive, parameter, curve, usage) resolution.
#
# AWS documents every possible KeySpec value at
# https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html
# and the values below are exactly the strings the API returns. We do NOT
# invent or normalise -- if AWS returns "RSA_2048", we surface "RSA-2048".
# ---------------------------------------------------------------------------
_KEY_SPECS: dict[str, dict[str, Any]] = {
    # Symmetric
    "SYMMETRIC_DEFAULT": {
        "algorithm": "AES",
        "primitive": CryptoPrimitive.BLOCK_CIPHER,
        "parameter": "256",
        "curve": None,
        "usage": CryptoUsage.DATA_ENCRYPTION,
    },
    # HMAC
    "HMAC_224": {
        "algorithm": "SHA-224",
        "primitive": CryptoPrimitive.MAC,
        "parameter": None,
        "curve": None,
        "usage": CryptoUsage.MESSAGE_AUTHENTICATION,
    },
    "HMAC_256": {
        "algorithm": "SHA-256",
        "primitive": CryptoPrimitive.MAC,
        "parameter": None,
        "curve": None,
        "usage": CryptoUsage.MESSAGE_AUTHENTICATION,
    },
    "HMAC_384": {
        "algorithm": "SHA-384",
        "primitive": CryptoPrimitive.MAC,
        "parameter": None,
        "curve": None,
        "usage": CryptoUsage.MESSAGE_AUTHENTICATION,
    },
    "HMAC_512": {
        "algorithm": "SHA-512",
        "primitive": CryptoPrimitive.MAC,
        "parameter": None,
        "curve": None,
        "usage": CryptoUsage.MESSAGE_AUTHENTICATION,
    },
    # RSA (all sizes AWS supports)
    "RSA_2048": {
        "algorithm": "RSA",
        "primitive": CryptoPrimitive.PKE,
        "parameter": "2048",
        "curve": None,
        "usage": CryptoUsage.KEY_ESTABLISHMENT,
    },
    "RSA_3072": {
        "algorithm": "RSA",
        "primitive": CryptoPrimitive.PKE,
        "parameter": "3072",
        "curve": None,
        "usage": CryptoUsage.KEY_ESTABLISHMENT,
    },
    "RSA_4096": {
        "algorithm": "RSA",
        "primitive": CryptoPrimitive.PKE,
        "parameter": "4096",
        "curve": None,
        "usage": CryptoUsage.KEY_ESTABLISHMENT,
    },
    # ECC on NIST curves
    "ECC_NIST_P256": {
        "algorithm": "ECDSA",
        "primitive": CryptoPrimitive.SIGNATURE,
        "parameter": "P-256",
        "curve": "secp256r1",
        "usage": CryptoUsage.DIGITAL_SIGNATURE,
    },
    "ECC_NIST_P384": {
        "algorithm": "ECDSA",
        "primitive": CryptoPrimitive.SIGNATURE,
        "parameter": "P-384",
        "curve": "secp384r1",
        "usage": CryptoUsage.DIGITAL_SIGNATURE,
    },
    "ECC_NIST_P521": {
        "algorithm": "ECDSA",
        "primitive": CryptoPrimitive.SIGNATURE,
        "parameter": "P-521",
        "curve": "secp521r1",
        "usage": CryptoUsage.DIGITAL_SIGNATURE,
    },
    "ECC_SECG_P256K1": {
        "algorithm": "ECDSA",
        "primitive": CryptoPrimitive.SIGNATURE,
        "parameter": "secp256k1",
        "curve": "secp256k1",
        "usage": CryptoUsage.DIGITAL_SIGNATURE,
    },
    # SM2 (AWS China regions)
    "SM2": {
        "algorithm": "SM2",
        "primitive": CryptoPrimitive.SIGNATURE,
        "parameter": "SM2",
        "curve": "SM2",
        "usage": CryptoUsage.DIGITAL_SIGNATURE,
    },
}


# ---------------------------------------------------------------------------
# DescribeKey response -> NormalizedFinding
# ---------------------------------------------------------------------------

def _resolve_key(metadata: dict, region: str) -> NormalizedFinding | None:
    """Convert a ``KeyMetadata`` dict into a :class:`NormalizedFinding`.

    Returns ``None`` when the key is missing the fields we need. That is
    honest: some AWS pending-deletion / cross-account keys return a
    truncated ``KeyMetadata`` and we would rather skip them than fabricate.
    """
    key_id = metadata.get("KeyId")
    if not key_id:
        return None

    key_spec = metadata.get("KeySpec") or metadata.get("CustomerMasterKeySpec")
    key_usage = metadata.get("KeyUsage") or ""
    key_manager = metadata.get("KeyManager") or "CUSTOMER"
    key_state = metadata.get("KeyState") or "Unknown"
    origin = metadata.get("Origin") or "AWS_KMS"
    arn = metadata.get("Arn") or f"arn:aws:kms:{region}:*:key/{key_id}"

    resolved = _KEY_SPECS.get(key_spec) if key_spec else None
    if resolved is None:
        # Surface unknown key specs rather than dropping them. The report
        # will show them as an INVESTIGATE-tier finding.
        algorithm = f"KMS-{key_spec}" if key_spec else "KMS-Unknown"
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

    # Refine usage from the AWS KeyUsage field when it disagrees with the
    # spec default. AWS lets a P-256 key be either SIGN_VERIFY or
    # KEY_AGREEMENT depending on the customer's choice.
    if key_usage == "SIGN_VERIFY":
        usage = CryptoUsage.DIGITAL_SIGNATURE
    elif key_usage == "ENCRYPT_DECRYPT":
        usage = CryptoUsage.DATA_ENCRYPTION
    elif key_usage == "KEY_AGREEMENT":
        usage = CryptoUsage.KEY_ESTABLISHMENT
    elif key_usage == "GENERATE_VERIFY_MAC":
        usage = CryptoUsage.MESSAGE_AUTHENTICATION

    snippet = (
        f"aws-kms key_id={key_id} spec={key_spec or 'unknown'} "
        f"usage={key_usage or 'unknown'} manager={key_manager} "
        f"state={key_state} origin={origin}"
    )

    evidence = Evidence(
        file_path=arn,
        line_number=None,
        code_snippet=snippet,
        detection_method=DetectionMethod.AWS_KMS_ATTESTED,
        # HIGH band: AWS answered with the algorithm directly.
        confidence=0.95,
    )

    return NormalizedFinding(
        id=f"AWSKMS-{region}-{key_id[:24]}",
        algorithm=algorithm,
        primitive=primitive,
        parameter=parameter,
        parameter_status=parameter_status,
        curve=curve,
        usage=usage,
        artefact_type=ArtefactType.CLOUD_SERVICE,
        library="aws-kms",
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def scan_aws_kms(
    settings: Settings | None = None,
    *,
    client_factory=None,
) -> list[NormalizedFinding]:
    """Enumerate KMS keys in the configured AWS account.

    ``client_factory`` exists so tests can inject a boto3 client backed by
    moto without monkeypatching the module-level ``boto3`` reference. In
    production the argument is unused and boto3's default client is created
    with the region from settings (or the boto3 session default).

    Returns an empty list when:

    * the scanner is disabled,
    * ``boto3`` is not installed,
    * no AWS credentials are resolvable (``NoCredentialsError``),
    * the region rejects the caller or ``ListKeys`` fails outright.

    A returned empty list is not an error; it is the honest signal that
    the AWS side of the inventory is not observable under the current
    configuration.
    """
    settings = settings or get_settings()

    if not settings.aws_kms_scan_enabled:
        return []

    if client_factory is None:
        if _boto3 is None:
            logger.info(
                "AWS KMS scan enabled but boto3 is not installed; skipping."
            )
            return []

        def client_factory():
            region = settings.aws_kms_region.strip() or None
            return _boto3.client("kms", region_name=region)

    try:
        client = client_factory()
    except NoCredentialsError as exc:
        logger.warning(
            "AWS KMS scan: no credentials resolvable (%s); skipping.", exc
        )
        return []
    except Exception as exc:  # noqa: BLE001
        logger.warning("AWS KMS scan: could not build client: %s", exc)
        return []

    # Resolve the region from the client itself so the finding's evidence
    # is truthful even when the caller relies on boto3's default region.
    region = ""
    try:
        region = getattr(client.meta, "region_name", "") or ""
    except Exception:  # noqa: BLE001
        region = settings.aws_kms_region

    findings: list[NormalizedFinding] = []
    max_keys = settings.aws_kms_max_keys
    seen: set[str] = set()

    for key_id in _iter_key_ids(client, max_keys=max_keys):
        if key_id in seen:
            continue
        seen.add(key_id)
        try:
            desc = client.describe_key(KeyId=key_id)
        except (ClientError, BotoCoreError) as exc:
            logger.warning("DescribeKey failed for %s: %s", key_id, exc)
            continue
        metadata = desc.get("KeyMetadata") or {}
        resolved = _resolve_key(metadata, region=region or "unknown")
        if resolved is not None:
            findings.append(resolved)

    logger.info(
        "AWS KMS scan: %d attested key(s) in region=%s.",
        len(findings),
        region or "<default>",
    )
    return findings


def _iter_key_ids(client, *, max_keys: int):
    """Yield up to *max_keys* KMS key IDs, following pagination if needed."""
    try:
        paginator = client.get_paginator("list_keys")
    except (ClientError, BotoCoreError) as exc:
        logger.warning("Could not construct list_keys paginator: %s", exc)
        return
    remaining = max_keys
    try:
        for page in paginator.paginate():
            for entry in page.get("Keys") or []:
                key_id = entry.get("KeyId")
                if not key_id:
                    continue
                yield key_id
                remaining -= 1
                if remaining <= 0:
                    return
    except (ClientError, BotoCoreError) as exc:
        logger.warning("ListKeys failed: %s", exc)
        return
