"""CycloneDX CBOM builder.

Maps each :class:`~app.models.finding.NormalizedFinding` onto a CycloneDX 1.6
``cryptographic-asset`` component carrying:

* ``bom-ref`` — stable, deterministic
* ``cryptoProperties.assetType``
* ``cryptoProperties.algorithmProperties.primitive``
* ``parameterSetIdentifier`` — key size or curve where resolved
* ``mode`` — cipher mode where detected
* ``cryptoFunctions`` — keygen, encrypt, sign, etc.
* ``evidence.occurrences`` — source file and line

The output is a JSON-serialisable dict that passes CycloneDX schema validation.
All downstream stages read the normalized findings, not this CBOM, so analysis
and the export artefact always describe the same scan.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentEvidence, ComponentType
from cyclonedx.model.component_evidence import Occurrence
from cyclonedx.model.crypto import (
    AlgorithmProperties,
    CryptoAssetType,
)
from cyclonedx.model.crypto import (
    CryptoFunction as CDXFunction,
)
from cyclonedx.model.crypto import (
    CryptoMode as CDXMode,
)
from cyclonedx.model.crypto import (
    CryptoPrimitive as CDXPrimitive,
)
from cyclonedx.model.crypto import (
    CryptoProperties,
)
from cyclonedx.output.json import JsonV1Dot6

from app.models.asset import CipherMode, CryptoPrimitive
from app.models.finding import NormalizedFinding

logger = logging.getLogger(__name__)


# ── Enum mapping tables ──────────────────────────────────────────────────
# Our domain enums → CycloneDX library enums.

_PRIMITIVE_MAP: dict[CryptoPrimitive, CDXPrimitive] = {
    CryptoPrimitive.PKE: CDXPrimitive.PKE,
    CryptoPrimitive.KEY_AGREE: CDXPrimitive.KEY_AGREE,
    CryptoPrimitive.SIGNATURE: CDXPrimitive.SIGNATURE,
    CryptoPrimitive.HASH: CDXPrimitive.HASH,
    CryptoPrimitive.BLOCK_CIPHER: CDXPrimitive.BLOCK_CIPHER,
    CryptoPrimitive.STREAM_CIPHER: CDXPrimitive.STREAM_CIPHER,
    CryptoPrimitive.AE: CDXPrimitive.AE,
    CryptoPrimitive.MAC: CDXPrimitive.MAC,
    CryptoPrimitive.KDF: CDXPrimitive.KDF,
    CryptoPrimitive.KEM: CDXPrimitive.KEM,
    CryptoPrimitive.DRBG: CDXPrimitive.DRBG,
    CryptoPrimitive.XOF: CDXPrimitive.XOF,
    CryptoPrimitive.COMBINER: CDXPrimitive.COMBINER,
    CryptoPrimitive.OTHER: CDXPrimitive.OTHER,
    CryptoPrimitive.UNKNOWN: CDXPrimitive.UNKNOWN,
}

_MODE_MAP: dict[CipherMode, CDXMode] = {
    CipherMode.CBC: CDXMode.CBC,
    CipherMode.ECB: CDXMode.ECB,
    CipherMode.GCM: CDXMode.GCM,
    CipherMode.CTR: CDXMode.CTR,
    CipherMode.CFB: CDXMode.CFB,
    CipherMode.OFB: CDXMode.OFB,
    CipherMode.CCM: CDXMode.CCM,
    CipherMode.OTHER: CDXMode.OTHER,
    CipherMode.UNKNOWN: CDXMode.UNKNOWN,
}

_FUNCTION_MAP: dict[str, CDXFunction] = {
    "keygen": CDXFunction.KEYGEN,
    "encrypt": CDXFunction.ENCRYPT,
    "decrypt": CDXFunction.DECRYPT,
    "sign": CDXFunction.SIGN,
    "verify": CDXFunction.VERIFY,
    "digest": CDXFunction.DIGEST,
    "keyderive": CDXFunction.KEYDERIVE,
    "generate": CDXFunction.GENERATE,
    "encapsulate": CDXFunction.ENCAPSULATE,
    "decapsulate": CDXFunction.DECAPSULATE,
    "tag": CDXFunction.TAG,
    "other": CDXFunction.OTHER,
    "unknown": CDXFunction.UNKNOWN,
}


def _finding_to_component(finding: NormalizedFinding) -> Component:
    """Convert a single NormalizedFinding into a CycloneDX Component."""

    # Determine the crypto function from the evidence rule.
    crypto_functions: list[CDXFunction] = []
    rule_id = finding.evidence.rule_id or ""
    for keyword, cdx_fn in _FUNCTION_MAP.items():
        if keyword in rule_id.lower():
            crypto_functions.append(cdx_fn)
            break

    # If we couldn't determine from rule, infer from usage.
    if not crypto_functions:
        usage_to_fn = {
            "key_generation": CDXFunction.KEYGEN,
            "key_establishment": CDXFunction.KEYDERIVE,
            "key_transport": CDXFunction.ENCRYPT,
            "data_encryption": CDXFunction.ENCRYPT,
            "data_at_rest_encryption": CDXFunction.ENCRYPT,
            "transport_encryption": CDXFunction.ENCRYPT,
            "digital_signature": CDXFunction.SIGN,
            "session_signature": CDXFunction.SIGN,
            "certificate_signing": CDXFunction.SIGN,
            "code_signing": CDXFunction.SIGN,
            "integrity_hash": CDXFunction.DIGEST,
            "password_hashing": CDXFunction.DIGEST,
            "message_authentication": CDXFunction.TAG,
            "key_derivation": CDXFunction.KEYDERIVE,
        }
        fn = usage_to_fn.get(finding.usage.value)
        if fn:
            crypto_functions.append(fn)

    # Build algorithm properties.
    cdx_primitive = _PRIMITIVE_MAP.get(finding.primitive, CDXPrimitive.UNKNOWN)
    cdx_mode = _MODE_MAP.get(finding.mode, CDXMode.UNKNOWN) if finding.mode else None

    param_set = finding.parameter
    if not param_set and finding.curve:
        param_set = finding.curve

    algo_props = AlgorithmProperties(
        primitive=cdx_primitive,
        parameter_set_identifier=param_set,
        curve=finding.curve,
        mode=cdx_mode,
        crypto_functions=crypto_functions or [CDXFunction.UNKNOWN],
    )

    crypto_props = CryptoProperties(
        asset_type=CryptoAssetType.ALGORITHM,
        algorithm_properties=algo_props,
    )

    # Build evidence occurrence.
    occurrence = Occurrence(
        location=finding.evidence.file_path,
        line=finding.evidence.line_number,
        additional_context=finding.evidence.code_snippet[:200] if finding.evidence.code_snippet else None,
    )

    evidence = ComponentEvidence(occurrences=[occurrence])

    return Component(
        name=finding.display_name,
        type=ComponentType.CRYPTOGRAPHIC_ASSET,
        bom_ref=finding.id,
        description=(
            f"{finding.algorithm} detected in {finding.evidence.file_path}"
            f" at line {finding.evidence.line_number}"
            f" (confidence: {finding.evidence.confidence:.0%})"
        ),
        crypto_properties=crypto_props,
        evidence=evidence,
    )


def build_cbom(
    findings: list[NormalizedFinding],
    *,
    project_name: str = "Blindspot ECDAT Scan",
) -> dict[str, Any]:
    """Build a CycloneDX 1.6 CBOM from normalized findings.

    Returns a JSON-serialisable dict. The actual JSON string and file writing
    happens in the storage layer.
    """
    if not findings:
        logger.warning("No findings to include in the CBOM.")

    bom = Bom()

    # Add components.
    seen_refs: set[str] = set()
    for finding in findings:
        if finding.id in seen_refs:
            continue
        try:
            component = _finding_to_component(finding)
            bom.components.add(component)
            seen_refs.add(finding.id)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Failed to convert finding %s to CBOM component: %s",
                finding.id,
                exc,
            )

    # Serialize via the library's JSON outputter.
    outputter = JsonV1Dot6(bom)
    raw_json = outputter.output_as_string()
    document = json.loads(raw_json)

    # Add Blindspot metadata that the CycloneDX schema allows as properties.
    document.setdefault("metadata", {})
    document["metadata"]["timestamp"] = datetime.now(timezone.utc).isoformat()

    logger.info(
        "CBOM built: %d components from %d findings (CycloneDX 1.6).",
        len(document.get("components", [])),
        len(findings),
    )

    return document


def build_cbom_json(
    findings: list[NormalizedFinding],
    *,
    project_name: str = "Blindspot ECDAT Scan",
) -> str:
    """Build the CBOM and return it as a formatted JSON string."""
    document = build_cbom(findings, project_name=project_name)
    return json.dumps(document, indent=2, ensure_ascii=False)
