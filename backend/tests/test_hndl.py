"""Harvest-Now-Decrypt-Later (HNDL) exposure tests.

HNDL is a *derived* label, not a new judgement: a finding is exposed only when
it protects confidentiality, is quantum-vulnerable (Shor-breakable), and is
overdue under Mosca. These tests pin that definition and the summary count.
"""

from __future__ import annotations

from app.models.asset import SecurityGoal
from app.models.finding import (
    Classification,
    Criticality,
    DetectionMethod,
    Evidence,
    Finding,
)
from app.models.risk import RiskTier
from app.pipeline import _build_summary
from app.risk import mosca


def make_finding(
    fid: str,
    algorithm: str,
    *,
    goal: SecurityGoal,
    tier: RiskTier | None,
    classify: bool = True,
) -> Finding:
    """Build a finding with a chosen security goal, real quantum risk, and tier."""
    evidence = Evidence(
        file_path="a.py",
        line_number=10,
        code_snippet="x",
        detection_method=DetectionMethod.SEMGREP_API_PATTERN,
        confidence=0.9,
    )
    classification = (
        Classification(
            security_goal=goal,
            data_lifetime_years=10.0,
            criticality=Criticality.HIGH,
        )
        if classify
        else None
    )
    return Finding(
        id=fid,
        algorithm=algorithm,
        evidence=evidence,
        classification=classification,
        quantum_risk=mosca.assess_quantum_risk(algorithm),
        risk_tier=tier,
    )


# ── The three conditions ────────────────────────────────────────────────────

def test_confidential_quantum_overdue_is_exposed() -> None:
    f = make_finding("C1", "RSA", goal=SecurityGoal.CONFIDENTIALITY, tier=RiskTier.OVERDUE)
    assert f.is_hndl_exposed is True


def test_authenticity_is_not_exposed() -> None:
    """A signature recorded today can't be forged later — HNDL doesn't apply."""
    f = make_finding("C1", "RSA", goal=SecurityGoal.AUTHENTICITY, tier=RiskTier.OVERDUE)
    assert f.is_hndl_exposed is False


def test_non_quantum_vulnerable_is_not_exposed() -> None:
    """AES isn't Shor-breakable, so harvesting its ciphertext gains nothing."""
    f = make_finding("C1", "AES", goal=SecurityGoal.CONFIDENTIALITY, tier=RiskTier.OVERDUE)
    assert f.is_hndl_exposed is False


def test_not_overdue_is_not_exposed() -> None:
    """Data whose secrecy window ends before the quantum horizon isn't exposed."""
    f = make_finding("C1", "RSA", goal=SecurityGoal.CONFIDENTIALITY, tier=RiskTier.TRANSITIONAL)
    assert f.is_hndl_exposed is False


def test_no_classification_is_not_exposed() -> None:
    f = make_finding("C1", "RSA", goal=SecurityGoal.CONFIDENTIALITY, tier=RiskTier.OVERDUE, classify=False)
    assert f.is_hndl_exposed is False


# ── Summary count ───────────────────────────────────────────────────────────

def test_summary_counts_hndl_exposed() -> None:
    findings = [
        make_finding("C1", "RSA", goal=SecurityGoal.CONFIDENTIALITY, tier=RiskTier.OVERDUE),  # yes
        make_finding("C2", "ECDH", goal=SecurityGoal.CONFIDENTIALITY, tier=RiskTier.OVERDUE),  # yes
        make_finding("C3", "RSA", goal=SecurityGoal.AUTHENTICITY, tier=RiskTier.OVERDUE),      # no (auth)
        make_finding("C4", "AES", goal=SecurityGoal.CONFIDENTIALITY, tier=RiskTier.OVERDUE),   # no (not vuln)
        make_finding("C5", "RSA", goal=SecurityGoal.CONFIDENTIALITY, tier=RiskTier.LOW_RISK),  # no (not overdue)
    ]
    summary = _build_summary(findings)
    assert summary.hndl_exposed == 2


def test_hndl_flag_serialises_camelcase() -> None:
    f = make_finding("C1", "RSA", goal=SecurityGoal.CONFIDENTIALITY, tier=RiskTier.OVERDUE)
    data = f.serialise()
    assert data["isHndlExposed"] is True
    # And the Firestore flatten carries it too.
    assert f.to_firestore_document()["isHndlExposed"] is True
