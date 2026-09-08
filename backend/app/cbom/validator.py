"""CBOM schema validation.

The exported CBOM must validate against the CycloneDX 1.6 JSON schema.
A CBOM that only "looks right" is not interoperable.

Uses ``jsonschema`` to validate against the official schema bundled with
``cyclonedx-python-lib``.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import jsonschema

logger = logging.getLogger(__name__)

# The CycloneDX 1.6 JSON schema URL for $schema reference.
CDX_1_6_SCHEMA_URL = "http://cyclonedx.org/schema/bom-1.6.schema.json"


def _get_bundled_schema() -> dict[str, Any] | None:
    """Try to load the CycloneDX 1.6 JSON schema from the installed library."""
    try:
        import importlib.resources as resources

        # cyclonedx-python-lib bundles schemas.
        schema_candidates = [
            ("cyclonedx.schema", "_res", "bom-1.6.schema.json"),
            ("cyclonedx.schema", "_res", "bom-1.6.SNAPSHOT.schema.json"),
        ]

        for package, subpackage, filename in schema_candidates:
            try:
                ref = resources.files(f"{package}.{subpackage}").joinpath(filename)
                text = ref.read_text(encoding="utf-8")
                return json.loads(text)
            except (ModuleNotFoundError, FileNotFoundError, TypeError):
                continue

        # Try walking the package directory.
        import cyclonedx.schema
        schema_dir = getattr(cyclonedx.schema, "__path__", None)
        if schema_dir:
            from pathlib import Path
            for base in schema_dir:
                for candidate in Path(base).rglob("*1.6*schema*.json"):
                    return json.loads(candidate.read_text(encoding="utf-8"))

    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not load bundled CycloneDX schema: %s", exc)

    return None


def validate_cbom(document: dict[str, Any]) -> tuple[bool, list[str]]:
    """Validate a CBOM document against the CycloneDX 1.6 schema.

    Returns ``(is_valid, errors)`` where errors is a list of human-readable
    validation messages.

    Three-tier validation:
    1. Structural checks (always run, no schema needed).
    2. JSON Schema validation against the bundled CycloneDX schema.
    3. Crypto-specific field presence checks.
    """
    errors: list[str] = []

    # ── Tier 1: Structural checks ────────────────────────────────────────
    if not isinstance(document, dict):
        return False, ["Document is not a JSON object."]

    bom_format = document.get("bomFormat")
    if bom_format != "CycloneDX":
        errors.append(f"bomFormat must be 'CycloneDX', got {bom_format!r}.")

    spec_version = document.get("specVersion")
    if spec_version not in ("1.6", "1.5", "1.4"):
        errors.append(f"specVersion {spec_version!r} is not a supported CycloneDX version.")

    components = document.get("components", [])
    if not isinstance(components, list):
        errors.append("'components' must be an array.")
        components = []

    if not components:
        errors.append("CBOM contains no components.")

    # ── Tier 2: JSON Schema validation ───────────────────────────────────
    schema = _get_bundled_schema()
    if schema:
        try:
            jsonschema.validate(instance=document, schema=schema)
            logger.info("CBOM passed JSON Schema validation (CycloneDX 1.6).")
        except jsonschema.ValidationError as exc:
            path = " -> ".join(str(p) for p in exc.absolute_path) if exc.absolute_path else "root"
            errors.append(f"Schema validation error at {path}: {exc.message}")
        except jsonschema.SchemaError as exc:
            errors.append(f"Schema itself is invalid: {exc.message}")
            logger.warning("CycloneDX schema appears invalid: %s", exc.message)
    else:
        logger.info(
            "Bundled CycloneDX schema not found; running structural checks only."
        )

    # ── Tier 3: Crypto-specific field checks ─────────────────────────────
    for i, comp in enumerate(components):
        prefix = f"components[{i}]"

        if comp.get("type") != "cryptographic-asset":
            errors.append(f"{prefix}: type must be 'cryptographic-asset', got {comp.get('type')!r}.")

        bom_ref = comp.get("bom-ref")
        if not bom_ref:
            errors.append(f"{prefix}: missing bom-ref.")

        name = comp.get("name")
        if not name:
            errors.append(f"{prefix}: missing name.")

        crypto = comp.get("cryptoProperties") or comp.get("crypto-properties", {})
        if not crypto:
            errors.append(f"{prefix} ({name}): missing cryptoProperties.")
            continue

        asset_type = crypto.get("assetType")
        if not asset_type:
            errors.append(f"{prefix} ({name}): missing assetType.")

        algo = crypto.get("algorithmProperties", {})
        if asset_type == "algorithm" and not algo:
            errors.append(f"{prefix} ({name}): algorithm asset has no algorithmProperties.")

        primitive = algo.get("primitive")
        if asset_type == "algorithm" and not primitive:
            errors.append(f"{prefix} ({name}): missing primitive in algorithmProperties.")

    is_valid = len(errors) == 0
    if is_valid:
        logger.info("CBOM validation passed: %d components, 0 errors.", len(components))
    else:
        logger.warning("CBOM validation found %d errors.", len(errors))

    return is_valid, errors
