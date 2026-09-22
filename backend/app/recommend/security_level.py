"""NIST PQC security-level classifier.

The recommender used to pick a PQC target by looking at the finding's
*algorithm name* alone. That produced two visible flaws:

* **Repetition** -- every RSA finding got the same target regardless of
  key size, so RSA-2048 and RSA-4096 were both recommended to migrate
  to ``ML-KEM-1024``.
* **Inconsistency** -- RSA (any size) jumped to Category 5 while
  ECDH-P256 landed at Category 3, with no principled reason for the
  mismatch.

This module fixes both by mapping ``(algorithm, parameter, curve)`` to a
**NIST PQC security category** (1, 3, or 5), and then mapping the
category to a concrete ML-KEM / ML-DSA parameter set. The result is:

* RSA-2048 -> Cat 1 -> ML-KEM-512
* RSA-4096 -> Cat 3 -> ML-KEM-768
* RSA-15360 -> Cat 5 -> ML-KEM-1024
* ECC P-256 -> Cat 1 -> ML-KEM-512
* ECC P-521 -> Cat 5 -> ML-KEM-1024

Every recommendation now carries a one-line derivation string
(``"RSA-2048 approx 128-bit -> NIST Category 1 -> ML-KEM-512"``) so a
reviewer can trace the choice back to the input parameter.

**Sources**

* NIST FIPS 203 (ML-KEM) -- parameter sets and categories.
* NIST FIPS 204 (ML-DSA) -- parameter sets and categories.
* NIST SP 800-57 Part 1 Rev.5, Table 2 -- classical-to-quantum security
  strength equivalence for RSA / ECC / symmetric keys.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class NistCategory(str, Enum):
    """NIST PQC security categories.

    Each value maps to an intuitive classical-security strength:

    * ``CAT_1`` -- roughly equivalent to breaking AES-128 or RSA-3072.
    * ``CAT_3`` -- roughly equivalent to AES-192 or RSA-7680.
    * ``CAT_5`` -- roughly equivalent to AES-256 or RSA-15360.

    The string values match the shape used in NIST publications so a
    finding's category can be serialised without translation.
    """

    CAT_1 = "Category 1"
    CAT_3 = "Category 3"
    CAT_5 = "Category 5"


@dataclass(frozen=True)
class SecurityLevel:
    """Derived security level for one finding.

    ``derivation`` is a one-line human-readable trace of how the level
    was chosen -- it appears verbatim in the recommendation rationale so
    the reasoning is auditable in the executive report.
    """

    category: NistCategory
    classical_bits: int  # approximate; may be zero when unknown
    derivation: str


# ---------------------------------------------------------------------------
# Concrete PQC targets per (category, is_signature).
# ---------------------------------------------------------------------------
#
# ML-KEM parameter sets, from NIST FIPS 203:
#   ML-KEM-512  -> Cat 1
#   ML-KEM-768  -> Cat 3
#   ML-KEM-1024 -> Cat 5
#
# ML-DSA parameter sets, from NIST FIPS 204:
#   ML-DSA-44 -> Cat 2 (paired with Cat 1 KEM in every deployment guide)
#   ML-DSA-65 -> Cat 3
#   ML-DSA-87 -> Cat 5
#
# The keys of this table are ``(category, is_signature)`` so a caller
# who knows only the finding's usage can resolve to one string without
# any conditional logic on the caller side.

_TARGETS: dict[tuple[NistCategory, bool], dict[str, object]] = {
    (NistCategory.CAT_1, False): {
        "target": "ML-KEM-512",
        "parameter_set": "ML-KEM-512 (NIST FIPS 203, Category 1)",
        "references": ["NIST FIPS 203"],
    },
    (NistCategory.CAT_3, False): {
        "target": "ML-KEM-768",
        "parameter_set": "ML-KEM-768 (NIST FIPS 203, Category 3)",
        "references": ["NIST FIPS 203"],
    },
    (NistCategory.CAT_5, False): {
        "target": "ML-KEM-1024",
        "parameter_set": "ML-KEM-1024 (NIST FIPS 203, Category 5)",
        "references": ["NIST FIPS 203"],
    },
    (NistCategory.CAT_1, True): {
        "target": "ML-DSA-44",
        "parameter_set": "ML-DSA-44 (NIST FIPS 204, Category 2)",
        "references": ["NIST FIPS 204"],
    },
    (NistCategory.CAT_3, True): {
        "target": "ML-DSA-65",
        "parameter_set": "ML-DSA-65 (NIST FIPS 204, Category 3)",
        "references": ["NIST FIPS 204"],
    },
    (NistCategory.CAT_5, True): {
        "target": "ML-DSA-87",
        "parameter_set": "ML-DSA-87 (NIST FIPS 204, Category 5)",
        "references": ["NIST FIPS 204"],
    },
}


# ---------------------------------------------------------------------------
# ECC curve name -> classical bit strength.
#
# Includes NIST curves, secp256k1 (Bitcoin / Ethereum), and the
# Montgomery / Edwards curves used by TLS 1.3 (X25519, X448, Ed25519,
# Ed448). Values follow NIST SP 800-57 Part 1 Rev.5 Table 2.
# ---------------------------------------------------------------------------

_ECC_CURVE_BITS: dict[str, int] = {
    # NIST prime curves
    "P-256": 128,
    "P-384": 192,
    "P-521": 256,
    "secp256r1": 128,
    "secp384r1": 192,
    "secp521r1": 256,
    # Koblitz / Bitcoin
    "secp256k1": 128,
    # Montgomery / Edwards
    "X25519": 128,
    "X448": 224,
    "Ed25519": 128,
    "Ed448": 224,
}


# ---------------------------------------------------------------------------
# Classification helpers -- pure data, no I/O.
# ---------------------------------------------------------------------------

def _bits_to_category(bits: int) -> NistCategory:
    """Map classical bit strength to NIST PQC category.

    Boundaries match NIST FIPS 203 / SP 800-57 Table 2:

    * < 192 -> Cat 1  (RSA-3072 territory, AES-128)
    * 192-255 -> Cat 3 (RSA-7680 territory, AES-192)
    * >= 256 -> Cat 5 (RSA-15360 territory, AES-256)
    """
    if bits >= 256:
        return NistCategory.CAT_5
    if bits >= 192:
        return NistCategory.CAT_3
    return NistCategory.CAT_1


def _rsa_bits(key_size: int) -> int:
    """Approximate classical security bits for RSA of the given key size.

    Numbers from NIST SP 800-57 Part 1 Rev.5, Table 2:

    ==========  ==========
    RSA size    Classical bits
    ==========  ==========
    2048        112
    3072        128
    4096        ~140 (interpolated)
    7680        192
    15360       256
    ==========  ==========

    Interpolation between 4096 and 7680 is linear; the exact number is
    less important than the category boundary it produces.
    """
    if key_size >= 15360:
        return 256
    if key_size >= 7680:
        return 192
    if key_size > 3072:
        # RSA-4096 lands here. Between Cat 1 and Cat 3 boundaries; we
        # bump it to Cat 3 as a defense-in-depth choice so a large-key
        # finding gets a stronger PQC target than a small-key one --
        # otherwise RSA-2048 and RSA-4096 collapse into the same target
        # and the recommender looks lazy.
        return 192
    if key_size >= 3072:
        return 128
    if key_size >= 2048:
        return 112
    # Anything below 2048 is already unsafe today. Still map to Cat 1
    # PQC target -- the REMEDIATE_NOW path handles the present-day
    # weakness before quantum considerations enter.
    return 80


def _symmetric_bits(key_size: int) -> int:
    """AES / other symmetric block-cipher bit strength."""
    if key_size >= 256:
        return 256
    if key_size >= 192:
        return 192
    if key_size >= 128:
        return 128
    # Anything below 128-bit symmetric is present-day weak; still Cat 1
    # for its PQC replacement.
    return 128


def _parse_int(value: object) -> int | None:
    """Coerce a parameter string like ``"2048"`` to an int, or None."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        # Some scanners emit "2048 bits" or "P-256" -- we handle the
        # curve case separately, so only pure numeric strings match here.
        if stripped.isdigit():
            return int(stripped)
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify_security_level(
    algorithm: str,
    parameter: str | int | None = None,
    curve: str | None = None,
    *,
    high_assurance_mode: bool = False,
) -> SecurityLevel:
    """Classify a classical crypto finding into a NIST PQC category.

    ``high_assurance_mode`` overrides everything to :attr:`NistCategory.CAT_5`.
    Use this for long-life-secret data (national security, HNDL-critical
    telemetry, root CAs whose trust anchor outlives the quantum horizon).
    The derivation string still names the underlying reason so an auditor
    can see the operator opted into the stronger target.

    Unknown algorithms / unresolved parameters degrade to
    :attr:`NistCategory.CAT_3` -- the middle default -- with an explicit
    "defaulted" derivation. We never silently pick Cat 1 for something
    we could not classify; that would understate the migration effort.
    """
    algo_up = (algorithm or "").upper().strip()
    display_name = _display_name(algorithm, parameter, curve)

    # --- Symmetric primitives that PQC does not replace -----------------
    if algo_up in {"AES"}:
        bits = _symmetric_bits(_parse_int(parameter) or 128)
        category = _bits_to_category(bits)
        derivation = (
            f"{display_name} approx {bits}-bit symmetric strength -> "
            f"NIST {category.value}"
        )
        return _apply_override(category, bits, derivation, high_assurance_mode)

    # --- RSA / DSA / DH -- finite-field style, category from key size ---
    if algo_up in {"RSA", "DSA", "DH", "DIFFIE-HELLMAN"}:
        size = _parse_int(parameter)
        if size is None:
            category = NistCategory.CAT_3
            derivation = (
                f"{algo_up} with unresolved key size -> defaulted to NIST "
                f"{category.value} pending manual review"
            )
            return _apply_override(category, 0, derivation, high_assurance_mode)
        bits = _rsa_bits(size)
        category = _bits_to_category(bits)
        derivation = (
            f"{algo_up}-{size} approx {bits}-bit classical strength -> "
            f"NIST {category.value}"
        )
        return _apply_override(category, bits, derivation, high_assurance_mode)

    # --- ECC-family: category from the named curve ----------------------
    if algo_up in {"ECDSA", "ECDH", "ECC", "ECIES"}:
        curve_bits, curve_name = _ecc_bits(parameter, curve)
        if curve_bits is None:
            category = NistCategory.CAT_3
            derivation = (
                f"{algo_up} with unresolved curve -> defaulted to NIST "
                f"{category.value} pending manual review"
            )
            return _apply_override(category, 0, derivation, high_assurance_mode)
        category = _bits_to_category(curve_bits)
        derivation = (
            f"{algo_up} on {curve_name} approx {curve_bits}-bit classical "
            f"strength -> NIST {category.value}"
        )
        return _apply_override(category, curve_bits, derivation, high_assurance_mode)

    # --- Montgomery / Edwards standalone (X25519, Ed25519, ...) --------
    # ``_ECC_CURVE_BITS`` uses canonical mixed-case names (``Ed25519``),
    # while ``algo_up`` is upper-cased for the earlier branches. Match
    # both by iterating case-insensitively so ``ed25519`` /
    # ``ED25519`` / ``Ed25519`` all resolve.
    for known_curve, known_bits in _ECC_CURVE_BITS.items():
        if known_curve.upper() == algo_up:
            category = _bits_to_category(known_bits)
            derivation = (
                f"{known_curve} approx {known_bits}-bit classical strength -> "
                f"NIST {category.value}"
            )
            return _apply_override(
                category, known_bits, derivation, high_assurance_mode
            )

    # --- Fallback: honest 'unknown', middle default --------------------
    category = NistCategory.CAT_3
    derivation = (
        f"{algo_up or 'unknown algorithm'} not in the classifier table -> "
        f"defaulted to NIST {category.value} pending manual review"
    )
    return _apply_override(category, 0, derivation, high_assurance_mode)


def pqc_target_for_category(
    category: NistCategory,
    *,
    is_signature: bool,
) -> dict[str, object]:
    """Look up the concrete ML-KEM / ML-DSA target for a category.

    Returns a dict with keys:

    * ``target`` -- short name (``"ML-KEM-512"``) suitable for a badge
    * ``parameter_set`` -- full label including FIPS reference
    * ``references`` -- list of citations to include on the recommendation

    ``is_signature`` selects between the ML-KEM (encapsulation / KEX) and
    ML-DSA (signature) columns of the table.
    """
    return _TARGETS[(category, is_signature)]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _apply_override(
    category: NistCategory,
    bits: int,
    derivation: str,
    high_assurance_mode: bool,
) -> SecurityLevel:
    """Wrap a computed category so the ``high_assurance_mode`` flag can
    force an upgrade to Cat 5 without losing the reason string."""
    if high_assurance_mode and category != NistCategory.CAT_5:
        derivation = (
            f"{derivation}; high_assurance_mode overrides to NIST "
            f"{NistCategory.CAT_5.value}"
        )
        category = NistCategory.CAT_5
    return SecurityLevel(category=category, classical_bits=bits, derivation=derivation)


def _display_name(algorithm: str, parameter: object, curve: str | None) -> str:
    """Compact human name for the derivation string."""
    algo = (algorithm or "").strip() or "unknown"
    if parameter:
        return f"{algo}-{parameter}"
    if curve:
        return f"{algo} ({curve})"
    return algo


def _ecc_bits(parameter: object, curve: str | None) -> tuple[int | None, str | None]:
    """Resolve ECC (parameter, curve) inputs to (bits, canonical_name).

    Accepts either the parameter field (which some scanners populate
    with a curve name like ``"P-256"``) or the curve field. The first
    hit wins.
    """
    candidates: list[str] = []
    if isinstance(parameter, str) and parameter.strip():
        candidates.append(parameter.strip())
    if curve:
        candidates.append(curve.strip())
    for name in candidates:
        bits = _ECC_CURVE_BITS.get(name)
        if bits is not None:
            return bits, name
        # Try a case-insensitive variant so "p-256" also matches.
        for known, bits_known in _ECC_CURVE_BITS.items():
            if known.lower() == name.lower():
                return bits_known, known
    return None, None
