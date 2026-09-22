"""Tests for the NIST security-level classifier.

Two contracts these tests protect:

1. **Classification is derived from key size, not algorithm name.**
   RSA-2048 and RSA-4096 must land in different categories so their PQC
   targets differ. Same for ECC across curves. This is the fix for the
   original repetition / inconsistency complaint.

2. **Every derivation string is human-readable and audit-friendly.**
   The rationale on the recommendation quotes it verbatim, so an
   auditor can trace the choice back to the input parameter without
   re-running the classifier.
"""

from __future__ import annotations

import pytest

from app.recommend.security_level import (
    NistCategory,
    classify_security_level,
    pqc_target_for_category,
)


# ---------------------------------------------------------------------------
# RSA -- size drives the category
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("size, expected_category, expected_bits", [
    (1024, NistCategory.CAT_1,  80),   # already broken today; PQC target still Cat 1
    (2048, NistCategory.CAT_1, 112),
    (3072, NistCategory.CAT_1, 128),
    (4096, NistCategory.CAT_3, 192),   # visibly stronger than 2048
    (7680, NistCategory.CAT_3, 192),
    # 8192 sits between the 7680 (Cat 3) and 15360 (Cat 5) NIST landmarks
    # -- honest tables place it at ~200-bit classical strength, still
    # Cat 3. Only 15360+ is truly Cat 5.
    (8192, NistCategory.CAT_3, 192),
    (15360, NistCategory.CAT_5, 256),
])
def test_rsa_category_from_key_size(
    size: int, expected_category: NistCategory, expected_bits: int
) -> None:
    level = classify_security_level("RSA", parameter=str(size))
    assert level.category == expected_category
    assert level.classical_bits == expected_bits
    # Derivation must name the input so it is inspectable.
    assert f"RSA-{size}" in level.derivation
    assert expected_category.value in level.derivation


def test_rsa_2048_and_rsa_4096_produce_different_pqc_targets() -> None:
    """The user-reported bug in one line: this must NOT be equal."""
    two_k = classify_security_level("RSA", parameter="2048")
    four_k = classify_security_level("RSA", parameter="4096")

    kem_two_k = pqc_target_for_category(two_k.category, is_signature=False)
    kem_four_k = pqc_target_for_category(four_k.category, is_signature=False)

    assert kem_two_k["target"] != kem_four_k["target"], (
        "RSA-2048 and RSA-4096 must resolve to different PQC targets. "
        f"Got {kem_two_k['target']} for both."
    )
    assert kem_two_k["target"] == "ML-KEM-512"
    assert kem_four_k["target"] == "ML-KEM-768"


def test_rsa_with_unresolved_parameter_defaults_to_cat_3() -> None:
    """The classifier must never silently pick Cat 1 when it does not
    know the key size -- that would understate the migration effort."""
    level = classify_security_level("RSA", parameter=None)
    assert level.category == NistCategory.CAT_3
    assert "defaulted" in level.derivation.lower()


# ---------------------------------------------------------------------------
# ECC / ECDSA / ECDH -- curve drives the category
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("curve, expected_category, expected_bits", [
    ("P-256",    NistCategory.CAT_1, 128),
    ("P-384",    NistCategory.CAT_3, 192),
    ("P-521",    NistCategory.CAT_5, 256),
    ("secp256r1",NistCategory.CAT_1, 128),
    ("secp384r1",NistCategory.CAT_3, 192),
    ("secp521r1",NistCategory.CAT_5, 256),
    ("secp256k1",NistCategory.CAT_1, 128),
])
def test_ecdh_category_from_curve(
    curve: str, expected_category: NistCategory, expected_bits: int
) -> None:
    level = classify_security_level("ECDH", curve=curve)
    assert level.category == expected_category
    assert level.classical_bits == expected_bits
    assert curve in level.derivation


def test_ecdsa_uses_the_curve_from_the_parameter_field_too() -> None:
    """Some scanners emit the curve name in the ``parameter`` field
    rather than a dedicated ``curve`` field. Both must work."""
    from_param = classify_security_level("ECDSA", parameter="P-256")
    from_curve = classify_security_level("ECDSA", curve="P-256")
    assert from_param.category == from_curve.category == NistCategory.CAT_1


def test_ecc_with_unknown_curve_defaults_to_cat_3() -> None:
    level = classify_security_level("ECDSA", curve="brainpoolP256r1")
    assert level.category == NistCategory.CAT_3
    assert "defaulted" in level.derivation.lower()


# ---------------------------------------------------------------------------
# Montgomery / Edwards standalone
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("algo, expected_category, expected_bits", [
    ("X25519",  NistCategory.CAT_1, 128),
    ("Ed25519", NistCategory.CAT_1, 128),
    ("X448",    NistCategory.CAT_3, 224),
    ("Ed448",   NistCategory.CAT_3, 224),
])
def test_montgomery_edwards_standalone(
    algo: str, expected_category: NistCategory, expected_bits: int
) -> None:
    level = classify_security_level(algo)
    assert level.category == expected_category
    assert level.classical_bits == expected_bits


# ---------------------------------------------------------------------------
# Symmetric (AES)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("size, expected_category", [
    (128, NistCategory.CAT_1),
    (192, NistCategory.CAT_3),
    (256, NistCategory.CAT_5),
])
def test_aes_category_from_key_size(size: int, expected_category: NistCategory) -> None:
    level = classify_security_level("AES", parameter=str(size))
    assert level.category == expected_category


# ---------------------------------------------------------------------------
# high_assurance_mode
# ---------------------------------------------------------------------------

def test_high_assurance_mode_upgrades_cat_1_to_cat_5() -> None:
    level = classify_security_level("RSA", parameter="2048", high_assurance_mode=True)
    assert level.category == NistCategory.CAT_5
    # Derivation must show BOTH the original derivation and the override,
    # so the auditor sees the operator opted in rather than a silent bump.
    assert "112-bit" in level.derivation
    assert "high_assurance_mode" in level.derivation


def test_high_assurance_mode_is_a_no_op_at_cat_5() -> None:
    """A finding that is already Cat 5 must not gain a redundant
    'override' phrase -- the derivation stays clean."""
    level = classify_security_level("RSA", parameter="15360", high_assurance_mode=True)
    assert level.category == NistCategory.CAT_5
    assert "high_assurance_mode" not in level.derivation


def test_high_assurance_default_off_preserves_natural_level() -> None:
    level = classify_security_level("RSA", parameter="2048")
    assert level.category == NistCategory.CAT_1


# ---------------------------------------------------------------------------
# pqc_target_for_category -- exact target strings
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cat, is_sig, expected_target, expected_label_category", [
    # KEM ladder maps cleanly Cat 1/3/5 -> ML-KEM-512/768/1024, matching
    # the FIPS 203 label exactly.
    (NistCategory.CAT_1, False, "ML-KEM-512",  "Category 1"),
    (NistCategory.CAT_3, False, "ML-KEM-768",  "Category 3"),
    (NistCategory.CAT_5, False, "ML-KEM-1024", "Category 5"),
    # Signature ladder is one step offset: FIPS 204 does not define a
    # Category 1 signature primitive; ML-DSA-44 sits at Category 2, which
    # is the closest defense against a Category-1 threat and what every
    # PQC migration guide (NIST SP 1800-38, ETSI) pairs with a Category 1
    # KEM. The label reflects the honest FIPS 204 category number.
    (NistCategory.CAT_1, True,  "ML-DSA-44", "Category 2"),
    (NistCategory.CAT_3, True,  "ML-DSA-65", "Category 3"),
    (NistCategory.CAT_5, True,  "ML-DSA-87", "Category 5"),
])
def test_pqc_target_lookup_exhaustive(
    cat: NistCategory,
    is_sig: bool,
    expected_target: str,
    expected_label_category: str,
) -> None:
    target = pqc_target_for_category(cat, is_signature=is_sig)
    assert target["target"] == expected_target
    assert expected_label_category in str(target["parameter_set"])


def test_pqc_target_parameter_set_names_the_fips_reference() -> None:
    """The parameter_set string must include the FIPS reference so the
    executive report can show it verbatim."""
    kem = pqc_target_for_category(NistCategory.CAT_3, is_signature=False)
    sig = pqc_target_for_category(NistCategory.CAT_3, is_signature=True)
    assert "FIPS 203" in str(kem["parameter_set"])
    assert "FIPS 204" in str(sig["parameter_set"])


# ---------------------------------------------------------------------------
# Unknown algorithms
# ---------------------------------------------------------------------------

def test_unknown_algorithm_defaults_to_cat_3() -> None:
    level = classify_security_level("SomeFutureAlgo", parameter="42")
    assert level.category == NistCategory.CAT_3
    assert "defaulted" in level.derivation.lower()


def test_dh_and_dsa_use_the_same_rsa_size_ladder() -> None:
    """Finite-field DH and DSA share RSA's classical strength curve, so
    they must land in the same category for the same size."""
    dh = classify_security_level("DH", parameter="3072")
    dsa = classify_security_level("DSA", parameter="3072")
    rsa = classify_security_level("RSA", parameter="3072")
    assert dh.category == dsa.category == rsa.category == NistCategory.CAT_1
