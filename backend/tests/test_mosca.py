"""Mosca risk engine tests.

Tests the inequality calculation, tier assignment, current/quantum risk
assessment, and the critical separation between present-day weakness and
quantum migration urgency.
"""

from __future__ import annotations

import pytest

from app.risk.mosca import assess, assess_current_risk, assess_quantum_risk


# ── Core inequality ──────────────────────────────────────────────────────

def test_overdue_case_from_specification() -> None:
    """X=15, Y=3, Z=10 → 15 + 3 > 10 → overdue."""
    result = assess(15, 3, 10, z_source="test")
    assert result.result is True
    assert result.tier.value == "overdue"
    assert result.equation == "15 + 3 > 10"
    assert result.margin_years == 8
    assert result.applicable is True


def test_transitional_case() -> None:
    """X=3, Y=3, Z=10 → 3 + 3 > 10 is false, but 6 > 5 (Z/2) → transitional."""
    result = assess(3, 3, 10, z_source="test")
    assert result.result is False
    assert result.tier.value == "transitional"
    assert result.margin_years == -4


def test_low_risk_case() -> None:
    """X=0.04, Y=3, Z=10 → 3.04 < 5 (Z/2) → low-risk."""
    result = assess(0.04, 3, 10, z_source="test")
    assert result.result is False
    assert result.tier.value == "low-risk"


def test_z_provenance_is_always_carried() -> None:
    result = assess(15, 3, 10, z_source="India CII 2027")
    assert result.z_source == "India CII 2027"


def test_equation_matches_actual_numbers() -> None:
    result = assess(7.5, 2.5, 8, z_source="test")
    assert result.equation == "7.5 + 2.5 > 8"
    assert result.result is True  # 10 > 8
    assert result.margin_years == 2.0


# ── Non-Shor algorithms: Mosca not applicable ────────────────────────────

def test_mosca_not_applicable_for_symmetric() -> None:
    """AES, 3DES, hashes — Grover only halves security, Shor doesn't break."""
    result = assess(15, 3, 10, z_source="test", quantum_vulnerable=False)
    assert result.applicable is False
    assert result.tier.value == "low-risk"
    assert "not vulnerable to Shor" in result.notes


# ── Quantum risk assessment ──────────────────────────────────────────────

def test_rsa_is_shor_breakable() -> None:
    qr = assess_quantum_risk("RSA")
    assert qr.is_quantum_vulnerable is True
    assert qr.threat.value == "shor_breaks"


def test_ecdh_is_shor_breakable() -> None:
    qr = assess_quantum_risk("ECDH")
    assert qr.is_quantum_vulnerable is True


def test_ecdsa_is_shor_breakable() -> None:
    qr = assess_quantum_risk("ECDSA")
    assert qr.is_quantum_vulnerable is True


def test_aes_is_grover_weakened_not_broken() -> None:
    qr = assess_quantum_risk("AES")
    assert qr.is_quantum_vulnerable is False
    assert qr.threat.value == "grover_weakens"


def test_md5_is_grover_weakened_not_broken() -> None:
    qr = assess_quantum_risk("MD5")
    assert qr.is_quantum_vulnerable is False


# ── Current risk assessment ──────────────────────────────────────────────

def test_md5_is_currently_weak() -> None:
    cr = assess_current_risk("MD5")
    assert cr.is_currently_weak is True
    assert cr.severity.value == "high"


def test_des_is_currently_critical() -> None:
    cr = assess_current_risk("DES")
    assert cr.is_currently_weak is True
    assert cr.severity.value == "critical"


def test_3des_is_currently_weak() -> None:
    cr = assess_current_risk("3DES")
    assert cr.is_currently_weak is True
    assert cr.severity.value == "high"


def test_sha1_is_currently_weak() -> None:
    cr = assess_current_risk("SHA-1")
    assert cr.is_currently_weak is True


def test_rsa_is_not_currently_weak() -> None:
    cr = assess_current_risk("RSA")
    assert cr.is_currently_weak is False
    assert cr.severity.value == "none"


def test_aes_is_not_currently_weak() -> None:
    cr = assess_current_risk("AES")
    assert cr.is_currently_weak is False


# ── The axis separation case (MD5) ──────────────────────────────────────

def test_md5_broken_today_but_low_quantum_tier() -> None:
    """Case 4: MD5 is broken TODAY. But its quantum tier should be low,
    because Grover only halves hash security. These are independent axes.
    Reporting MD5 as quantum-urgent would be wrong."""
    cr = assess_current_risk("MD5")
    qr = assess_quantum_risk("MD5")

    assert cr.is_currently_weak is True
    assert qr.is_quantum_vulnerable is False

    # If we run Mosca, it should be not-applicable for a non-Shor algorithm.
    mosca = assess(1, 3, 10, z_source="test", quantum_vulnerable=False)
    assert mosca.applicable is False
    assert mosca.tier.value == "low-risk"
