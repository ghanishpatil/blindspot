"""PKCS#11 HSM attestation scanner -- R7.

The PS names *hardware modules* as an artefact class to catalogue. The
existing ``app/scanner/infra.py`` covers the *declared* side (Terraform
resources, config files, SDK imports); this module handles the *attested*
side: it opens a real PKCS#11 session against a configured module, reads
public attributes off every key object, and emits one high-confidence
finding per key.

Discipline that keeps this honest:

1. **The scanner is opt-in.** ``settings.pkcs11_scan_enabled`` defaults to
   ``False``. When the flag is off (the demo default) the scanner
   short-circuits before touching any HSM.
2. **The dependency is optional.** ``python-pkcs11`` is imported inside a
   ``try/except ImportError``. When it is not installed the scanner logs
   once and returns an empty list. Nothing downstream cares.
3. **Only public attributes are read.** ``CKA_KEY_TYPE``,
   ``CKA_MODULUS_BITS``, ``CKA_EC_PARAMS``, ``CKA_LABEL``, ``CKA_ID``. No
   sensitive material is extracted. Signing / decrypting is never
   attempted.
4. **A PIN is optional.** Most HSMs expose the public-key metadata we care
   about (algorithm, key size, curve) without a login. When
   ``pkcs11_pin`` is empty the session is opened read-only against public
   objects; when it is set the session logs in as ``USER`` first. Either
   way the private material stays on the token.
"""

from __future__ import annotations

import logging
from pathlib import Path

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
# Optional dependency import.
#
# ``python-pkcs11`` is not in requirements.in. Operators who want live HSM
# attestation install it themselves against the PKCS#11 shim they already
# have. Making it optional keeps the demo runnable on any workstation.
# ---------------------------------------------------------------------------
try:  # pragma: no cover -- exercised through monkeypatch in tests
    import pkcs11 as _pkcs11
except Exception:  # noqa: BLE001 -- any import-time failure is treated the same
    _pkcs11 = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# EC curve OID -> friendly name lookup.
#
# ``CKA_EC_PARAMS`` is a DER-encoded OID. python-pkcs11 hands it back as
# bytes; the values here are the DER form for the common curves so the
# scanner can name them without shelling out to a full ASN.1 parser.
# Anything outside the table lands as parameter=None with UNRESOLVED.
# ---------------------------------------------------------------------------
_EC_PARAMS: dict[bytes, tuple[str, str]] = {
    # secp256r1 / P-256    OID 1.2.840.10045.3.1.7
    b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07": ("P-256", "secp256r1"),
    # secp384r1 / P-384    OID 1.3.132.0.34
    b"\x06\x05\x2b\x81\x04\x00\x22": ("P-384", "secp384r1"),
    # secp521r1 / P-521    OID 1.3.132.0.35
    b"\x06\x05\x2b\x81\x04\x00\x23": ("P-521", "secp521r1"),
    # secp256k1            OID 1.3.132.0.10
    b"\x06\x05\x2b\x81\x04\x00\x0a": ("secp256k1", "secp256k1"),
    # X25519 / Ed25519 named curves (RFC 8410)   OID 1.3.101.110 / 112
    b"\x06\x03\x2b\x65\x6e": ("X25519", "X25519"),
    b"\x06\x03\x2b\x65\x70": ("Ed25519", "Ed25519"),
}


# ---------------------------------------------------------------------------
# Attribute extraction -- accepts either a python-pkcs11 object OR a plain
# dict (for tests). This lets the tests exercise the full extraction path
# without importing python-pkcs11 or standing up SoftHSM.
# ---------------------------------------------------------------------------

def _get_attr(obj, name: str, default=None):
    """Fetch ``obj[Attribute.<name>]`` for real pkcs11 objects, or
    ``obj[name]`` when a dict is supplied by tests.

    Returns *default* if the attribute is not readable (common on private
    objects without a login) or is not present at all.
    """
    if isinstance(obj, dict):
        return obj.get(name, default)

    # Real python-pkcs11 objects: ``obj[Attribute.<name>]`` raises on
    # missing attributes. Guard both paths.
    if _pkcs11 is None:
        return default
    try:
        attr = getattr(_pkcs11.Attribute, name)
    except AttributeError:
        return default
    try:
        return obj[attr]
    except Exception:  # noqa: BLE001 -- pkcs11 raises many attribute errors
        return default


def _resolve_object(  # noqa: C901 -- shape follows the CKA enum
    obj,
    *,
    token_label: str,
    module_path: str,
) -> NormalizedFinding | None:
    """Turn one PKCS#11 object into a :class:`NormalizedFinding` or ``None``.

    Objects whose class is not a key / certificate are ignored -- data
    objects, mechanisms, and public-only markers do not describe an
    algorithm we can catalogue.
    """
    object_class = _get_attr(obj, "CLASS")
    if object_class is None:
        return None

    # python-pkcs11 exposes CLASS as an ObjectClass enum; tests pass plain
    # strings. Normalise both.
    class_name = getattr(object_class, "name", None) or str(object_class)
    if class_name not in {
        "PUBLIC_KEY", "PRIVATE_KEY", "SECRET_KEY", "CERTIFICATE",
    }:
        return None

    key_type_raw = _get_attr(obj, "KEY_TYPE")
    key_type_name = (
        getattr(key_type_raw, "name", None) or (str(key_type_raw) if key_type_raw is not None else "")
    ).upper()

    label = _get_attr(obj, "LABEL", default="") or ""
    if isinstance(label, bytes):
        try:
            label = label.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            label = repr(label)

    key_id = _get_attr(obj, "ID", default=b"")
    if isinstance(key_id, bytes):
        key_id_str = key_id.hex() if key_id else ""
    else:
        key_id_str = str(key_id) if key_id is not None else ""

    algorithm: str | None = None
    parameter: str | None = None
    curve: str | None = None
    parameter_status = ParameterStatus.NOT_APPLICABLE
    primitive = CryptoPrimitive.UNKNOWN
    usage = CryptoUsage.KEY_GENERATION

    if key_type_name in {"RSA"}:
        algorithm = "RSA"
        primitive = CryptoPrimitive.PKE
        usage = CryptoUsage.KEY_ESTABLISHMENT
        modulus_bits = _get_attr(obj, "MODULUS_BITS")
        if modulus_bits:
            parameter = str(int(modulus_bits))
            parameter_status = ParameterStatus.RESOLVED
        else:
            # Some tokens omit MODULUS_BITS; fall back to len(MODULUS)*8.
            modulus = _get_attr(obj, "MODULUS")
            if isinstance(modulus, (bytes, bytearray)) and modulus:
                parameter = str(len(modulus) * 8)
                parameter_status = ParameterStatus.RESOLVED
            else:
                parameter_status = ParameterStatus.UNRESOLVED

    elif key_type_name in {"EC", "ECDSA"}:
        algorithm = "ECDSA"
        primitive = CryptoPrimitive.SIGNATURE
        usage = CryptoUsage.DIGITAL_SIGNATURE
        ec_params = _get_attr(obj, "EC_PARAMS")
        if isinstance(ec_params, (bytes, bytearray)):
            resolved = _EC_PARAMS.get(bytes(ec_params))
            if resolved is not None:
                parameter, curve = resolved
                parameter_status = ParameterStatus.RESOLVED
            else:
                parameter_status = ParameterStatus.UNRESOLVED
        else:
            parameter_status = ParameterStatus.UNRESOLVED

    elif key_type_name in {"EC_EDWARDS", "EDWARDS", "ED25519"}:
        algorithm = "Ed25519"
        primitive = CryptoPrimitive.SIGNATURE
        usage = CryptoUsage.DIGITAL_SIGNATURE
        parameter = "255"
        curve = "Ed25519"
        parameter_status = ParameterStatus.RESOLVED

    elif key_type_name in {"EC_MONTGOMERY", "MONTGOMERY", "X25519"}:
        algorithm = "X25519"
        primitive = CryptoPrimitive.KEY_AGREE
        usage = CryptoUsage.KEY_ESTABLISHMENT
        parameter = "255"
        curve = "X25519"
        parameter_status = ParameterStatus.RESOLVED

    elif key_type_name in {"DSA"}:
        algorithm = "DSA"
        primitive = CryptoPrimitive.SIGNATURE
        usage = CryptoUsage.DIGITAL_SIGNATURE
        # DSA reports PRIME_BITS or the length of PRIME.
        prime_bits = _get_attr(obj, "PRIME_BITS")
        if prime_bits:
            parameter = str(int(prime_bits))
            parameter_status = ParameterStatus.RESOLVED
        else:
            parameter_status = ParameterStatus.UNRESOLVED

    elif key_type_name in {"AES"}:
        algorithm = "AES"
        primitive = CryptoPrimitive.BLOCK_CIPHER
        usage = CryptoUsage.DATA_ENCRYPTION
        value_len = _get_attr(obj, "VALUE_LEN")
        if value_len:
            parameter = str(int(value_len) * 8)
            parameter_status = ParameterStatus.RESOLVED
        else:
            parameter_status = ParameterStatus.UNRESOLVED

    elif key_type_name in {"DES3", "TDES"}:
        algorithm = "3DES"
        primitive = CryptoPrimitive.BLOCK_CIPHER
        usage = CryptoUsage.DATA_ENCRYPTION
        parameter_status = ParameterStatus.NOT_APPLICABLE

    else:
        # Unrecognised key type -- surface it verbatim so an operator can
        # see what the HSM contains, but mark parameter as unresolved.
        if key_type_name:
            algorithm = f"PKCS11-{key_type_name}"
        else:
            # Certificate objects with no KEY_TYPE: still worth cataloguing.
            algorithm = "PKCS11-CERT" if class_name == "CERTIFICATE" else "PKCS11-UNKNOWN"
        parameter_status = ParameterStatus.UNRESOLVED

    # Human-readable evidence snippet: the label + class + module. Real
    # sessions provide labels for the operator to identify keys with.
    display_label = label or f"id={key_id_str}" if key_id_str else "unlabelled"
    snippet = (
        f"pkcs11 token={token_label!r} class={class_name} "
        f"type={key_type_name or 'unknown'} label={display_label!r}"
    )

    evidence = Evidence(
        file_path=f"pkcs11://{module_path}#{token_label or 'default'}",
        line_number=None,
        code_snippet=snippet,
        detection_method=DetectionMethod.PKCS11_ATTESTED,
        # HIGH band: the module answered with these attributes directly.
        confidence=0.95,
    )

    return NormalizedFinding(
        id=(
            f"PKCS11-{token_label or 'default'}-{class_name}-"
            f"{key_id_str or hash(display_label) & 0xFFFFFFFF:x}"
        ),
        algorithm=algorithm,
        primitive=primitive,
        parameter=parameter,
        parameter_status=parameter_status,
        curve=curve,
        usage=usage,
        artefact_type=ArtefactType.HARDWARE_MODULE,
        library="pkcs11",
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def scan_pkcs11(settings: Settings | None = None) -> list[NormalizedFinding]:
    """Enumerate keys on the configured PKCS#11 module.

    Returns an empty list when:

    * the scanner is disabled (``pkcs11_scan_enabled`` is false),
    * ``python-pkcs11`` is not installed,
    * ``pkcs11_module_path`` is empty or does not point at a file,
    * the module fails to load or expose any tokens.

    A returned empty list is not an error; it is the honest signal that
    there is nothing to attest under the current configuration.
    """
    settings = settings or get_settings()

    if not settings.pkcs11_scan_enabled:
        return []

    if _pkcs11 is None:
        logger.info(
            "PKCS#11 scan enabled but python-pkcs11 is not installed; "
            "skipping. Install it with `pip install python-pkcs11`."
        )
        return []

    module_path = settings.pkcs11_module_path.strip()
    if not module_path:
        logger.info("PKCS#11 scan enabled but no module path configured; skipping.")
        return []

    module_file = Path(module_path)
    if not module_file.is_file():
        logger.warning(
            "PKCS#11 module path %s does not exist; skipping HSM scan.",
            module_path,
        )
        return []

    findings: list[NormalizedFinding] = []
    try:
        lib = _pkcs11.lib(str(module_file))
    except Exception as exc:  # noqa: BLE001 -- pkcs11 raises many types
        logger.warning("Could not load PKCS#11 module %s: %s", module_path, exc)
        return []

    for token in _iter_tokens(lib, settings.pkcs11_token_label):
        try:
            findings.extend(_scan_token(token, settings=settings, module_path=module_path))
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "PKCS#11 token %s failed to enumerate: %s",
                getattr(token, "label", "?"),
                exc,
            )

    logger.info("PKCS#11 scan: %d attested key/cert finding(s).", len(findings))
    return findings


def _iter_tokens(lib, want_label: str):
    """Yield tokens from *lib*, filtered by label if one is configured."""
    try:
        tokens = list(lib.get_tokens())
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not enumerate PKCS#11 tokens: %s", exc)
        return
    for token in tokens:
        actual_label = (getattr(token, "label", "") or "").strip()
        if want_label and actual_label != want_label:
            continue
        yield token


def _scan_token(token, *, settings: Settings, module_path: str) -> list[NormalizedFinding]:
    """Open a read-only session on *token* and collect findings."""
    pin = settings.pkcs11_pin or None
    label = (getattr(token, "label", "") or "default").strip() or "default"

    session_cm = token.open(user_pin=pin) if pin else token.open()
    findings: list[NormalizedFinding] = []
    with session_cm as session:
        for obj in session.get_objects({}):
            resolved = _resolve_object(obj, token_label=label, module_path=module_path)
            if resolved is not None:
                findings.append(resolved)
    return findings
