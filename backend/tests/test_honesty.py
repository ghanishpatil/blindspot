"""Honesty / confidence surfacing tests.

A finding is flagged for manual verification when the tool is not confident:
either the detection confidence is low, or a parameter the risk model depends
on could not be resolved. This is a derived trust signal, not a new judgement.
"""

from __future__ import annotations

from app.models.asset import ParameterStatus
from app.models.finding import (
    Classification,
    Criticality,
    DetectionMethod,
    Evidence,
    Finding,
)
from app.pipeline import _build_summary


def make_finding(
    fid: str,
    *,
    confidence: float,
    parameter_status: ParameterStatus = ParameterStatus.RESOLVED,
) -> Finding:
    evidence = Evidence(
        file_path="a.py",
        line_number=10,
        code_snippet="x",
        detection_method=DetectionMethod.SEMGREP_STRING_MATCH,
        confidence=confidence,
    )
    return Finding(
        id=fid,
        algorithm="RSA",
        parameter_status=parameter_status,
        evidence=evidence,
        classification=Classification(data_lifetime_years=5.0, criticality=Criticality.MEDIUM),
    )


# ── The two conditions ──────────────────────────────────────────────────────

def test_low_confidence_needs_verification() -> None:
    # confidence < 0.6 bands to LOW.
    f = make_finding("C1", confidence=0.4)
    assert f.evidence.confidence_level.value == "low"
    assert f.needs_verification is True


def test_unresolved_parameter_needs_verification() -> None:
    # High confidence, but a parameter is unresolved.
    f = make_finding("C1", confidence=0.95, parameter_status=ParameterStatus.UNRESOLVED)
    assert f.needs_verification is True


def test_high_confidence_resolved_is_clear() -> None:
    f = make_finding("C1", confidence=0.95, parameter_status=ParameterStatus.RESOLVED)
    assert f.needs_verification is False


def test_medium_confidence_resolved_is_clear() -> None:
    # 0.6 <= confidence < 0.85 bands to MEDIUM — not flagged on confidence alone.
    f = make_finding("C1", confidence=0.7)
    assert f.evidence.confidence_level.value == "medium"
    assert f.needs_verification is False


# ── Summary count ───────────────────────────────────────────────────────────

def test_summary_counts_needs_verification() -> None:
    findings = [
        make_finding("C1", confidence=0.4),                                        # low conf → yes
        make_finding("C2", confidence=0.95, parameter_status=ParameterStatus.UNRESOLVED),  # unresolved → yes
        make_finding("C3", confidence=0.95),                                       # clear → no
        make_finding("C4", confidence=0.7),                                        # medium → no
    ]
    summary = _build_summary(findings)
    assert summary.needs_verification == 2


def test_flags_serialise_camelcase() -> None:
    f = make_finding("C1", confidence=0.4)
    data = f.serialise()
    # needsVerification is a top-level computed field; the confidence band is
    # nested under evidence (where it is computed).
    assert data["needsVerification"] is True
    assert data["evidence"]["confidenceLevel"] == "low"
    # The Firestore flatten promotes both to top level.
    doc = f.to_firestore_document()
    assert doc["needsVerification"] is True
    assert doc["confidenceLevel"] == "low"
