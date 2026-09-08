"""Domain model validation tests.

These models are the contract every pipeline stage depends on, so the
invariants that protect the demo's honesty are tested here:

* evidence confidence stays within 0.0-1.0
* an unresolved parameter is a valid, representable state
* a Mosca assessment cannot disagree with its own numbers
* the Firestore document shape matches the specification
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.models import (
    ArtefactType,
    Classification,
    ConfidenceLevel,
    Criticality,
    CryptoPrimitive,
    CryptoUsage,
    CurrentRisk,
    DetectionMethod,
    Evidence,
    Finding,
    MigrationStrategy,
    MoscaAssessment,
    NormalizedFinding,
    ParameterStatus,
    QuantumRisk,
    QuantumThreat,
    Recommendation,
    RiskTier,
    Scan,
    ScanStatus,
    SecurityGoal,
    Severity,
)


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------
def test_evidence_captures_file_line_and_method() -> None:
    evidence = Evidence(
        file_path="auth.py",
        line_number=42,
        code_snippet="RSA.generate(2048)",
        detection_method=DetectionMethod.SEMGREP_API_PATTERN,
        confidence=0.98,
    )

    assert evidence.file_path == "auth.py"
    assert evidence.line_number == 42
    assert evidence.code_snippet == "RSA.generate(2048)"
    assert evidence.detection_method is DetectionMethod.SEMGREP_API_PATTERN


@pytest.mark.parametrize(
    ("confidence", "expected"),
    [
        (0.98, ConfidenceLevel.HIGH),
        (0.85, ConfidenceLevel.HIGH),
        (0.70, ConfidenceLevel.MEDIUM),
        (0.60, ConfidenceLevel.MEDIUM),
        (0.40, ConfidenceLevel.LOW),
    ],
)
def test_confidence_banding(confidence: float, expected: ConfidenceLevel) -> None:
    evidence = Evidence(file_path="a.py", confidence=confidence)
    assert evidence.confidence_level is expected


@pytest.mark.parametrize("confidence", [-0.1, 1.1])
def test_confidence_must_be_a_probability(confidence: float) -> None:
    with pytest.raises(ValidationError):
        Evidence(file_path="a.py", confidence=confidence)


def test_evidence_serialises_to_camel_case() -> None:
    """Wire format must match the specification's field names."""
    payload = Evidence(
        file_path="auth.py",
        line_number=42,
        code_snippet="RSA.generate(2048)",
        detection_method=DetectionMethod.SEMGREP_API_PATTERN,
        confidence=0.98,
    ).serialise()

    assert payload["filePath"] == "auth.py"
    assert payload["lineNumber"] == 42
    assert payload["detectionMethod"] == "semgrep_api_pattern"
    assert "file_path" not in payload


# ---------------------------------------------------------------------------
# Normalized findings
# ---------------------------------------------------------------------------
def _rsa_evidence() -> Evidence:
    return Evidence(
        file_path="auth.py",
        line_number=42,
        code_snippet="RSA.generate(2048)",
        detection_method=DetectionMethod.SEMGREP_API_PATTERN,
        confidence=0.98,
    )


def test_normalized_finding_matches_specification_shape() -> None:
    finding = NormalizedFinding(
        id="CRYPTO-001",
        algorithm="RSA",
        primitive=CryptoPrimitive.PKE,
        parameter="2048",
        parameter_status=ParameterStatus.RESOLVED,
        usage=CryptoUsage.KEY_ESTABLISHMENT,
        artefact_type=ArtefactType.KEY_EXCHANGE,
        evidence=_rsa_evidence(),
    )

    assert finding.display_name == "RSA-2048"
    assert finding.file_path == "auth.py"
    assert finding.line_number == 42

    payload = finding.serialise()
    assert payload["artefactType"] == "key-exchange"
    assert payload["parameter"] == "2048"


def test_algorithm_must_not_be_blank() -> None:
    with pytest.raises(ValidationError):
        NormalizedFinding(id="X", algorithm="   ", evidence=_rsa_evidence())


def test_unresolved_parameter_is_a_first_class_state() -> None:
    """Case 5: RSA detected, key size unknown. Honesty over a guess."""
    finding = NormalizedFinding(
        id="CRYPTO-005",
        algorithm="RSA",
        primitive=CryptoPrimitive.PKE,
        parameter=None,
        parameter_status=ParameterStatus.UNRESOLVED,
        usage=CryptoUsage.KEY_GENERATION,
        artefact_type=ArtefactType.KEY_EXCHANGE,
        unresolved_parameters=["key_size"],
        evidence=Evidence(
            file_path="config_crypto.py",
            line_number=17,
            code_snippet="RSA.generate(KEY_SIZE)",
            detection_method=DetectionMethod.CONFIG_INFERENCE,
            confidence=0.55,
        ),
    )

    assert finding.parameter is None
    assert finding.parameter_status is ParameterStatus.UNRESOLVED
    assert "key_size" in finding.unresolved_parameters
    assert finding.display_name == "RSA", "no parameter must not be invented"
    assert finding.evidence.confidence_level is ConfidenceLevel.LOW


# ---------------------------------------------------------------------------
# Mosca
# ---------------------------------------------------------------------------
def test_mosca_overdue_case_from_specification() -> None:
    mosca = MoscaAssessment(
        x=15,
        y=3,
        z=10,
        equation="15 + 3 > 10",
        result=True,
        tier=RiskTier.OVERDUE,
        margin_years=8,
        z_source="Demo assumption",
    )

    assert mosca.result is True
    assert mosca.tier is RiskTier.OVERDUE
    assert mosca.equation == "15 + 3 > 10"
    assert mosca.margin_years == 8


def test_mosca_rejects_a_result_that_contradicts_its_numbers() -> None:
    """A cached tier or hand-written string must not drift from the arithmetic."""
    with pytest.raises(ValidationError):
        MoscaAssessment(
            x=1,
            y=1,
            z=10,
            equation="1 + 1 > 10",
            result=True,  # 2 > 10 is false
            tier=RiskTier.OVERDUE,
            margin_years=-8,
            z_source="Demo assumption",
        )


def test_mosca_rejects_an_inconsistent_margin() -> None:
    with pytest.raises(ValidationError):
        MoscaAssessment(
            x=15,
            y=3,
            z=10,
            equation="15 + 3 > 10",
            result=True,
            margin_years=99,  # should be 8
            tier=RiskTier.OVERDUE,
            z_source="Demo assumption",
        )


def test_mosca_z_provenance_is_required() -> None:
    """Z is an assumption and must always carry its source."""
    with pytest.raises(ValidationError):
        MoscaAssessment(
            x=15, y=3, z=10, equation="15 + 3 > 10", result=True, margin_years=8
        )


def test_mosca_can_be_marked_not_applicable() -> None:
    """Some primitives have no known quantum vulnerability; say so explicitly."""
    mosca = MoscaAssessment(
        x=0.1,
        y=3,
        z=10,
        equation="0.1 + 3 > 10",
        result=False,
        tier=RiskTier.LOW_RISK,
        margin_years=-6.9,
        z_source="Demo assumption",
        applicable=False,
        notes="Symmetric primitive; Grover only halves the security level.",
    )

    assert mosca.applicable is False
    assert mosca.result is False


# ---------------------------------------------------------------------------
# Risk separation
# ---------------------------------------------------------------------------
def test_current_weakness_is_modelled_separately_from_quantum_risk() -> None:
    """Case 4: MD5 is broken today. That is not a quantum finding."""
    current = CurrentRisk(
        is_currently_weak=True,
        severity=Severity.HIGH,
        reason="MD5 is collision-vulnerable and unsuitable for any security purpose.",
    )
    quantum = QuantumRisk(
        is_quantum_vulnerable=False,
        threat=QuantumThreat.GROVER_WEAKENS,
        reason="Hash preimage resistance is only quadratically reduced by Grover.",
    )

    assert current.is_currently_weak is True
    assert quantum.is_quantum_vulnerable is False


# ---------------------------------------------------------------------------
# Recommendation
# ---------------------------------------------------------------------------
def test_recommendation_names_strategy_algorithm_and_rationale() -> None:
    recommendation = Recommendation(
        strategy=MigrationStrategy.HYBRID,
        algorithm="X25519 + ML-KEM-768",
        parameter_set="ML-KEM-768 (NIST Category 3)",
        rationale=(
            "Provides a transition path while reducing disruption to an existing "
            "classical key-establishment mechanism."
        ),
        replaces="X25519",
    )

    assert recommendation.strategy is MigrationStrategy.HYBRID
    assert "ML-KEM-768" in recommendation.algorithm
    assert recommendation.rationale

    payload = recommendation.serialise()
    assert payload["parameterSet"] == "ML-KEM-768 (NIST Category 3)"


def test_remediate_now_is_not_a_quantum_recommendation() -> None:
    recommendation = Recommendation(
        strategy=MigrationStrategy.REMEDIATE_NOW,
        algorithm="SHA-256",
        rationale="MD5 is broken today; replace it regardless of quantum timelines.",
        replaces="MD5",
        is_quantum_recommendation=False,
    )

    assert recommendation.is_quantum_recommendation is False


# ---------------------------------------------------------------------------
# Full finding / Firestore shape
# ---------------------------------------------------------------------------
def test_finding_firestore_document_matches_specified_fields() -> None:
    finding = Finding(
        id="CRYPTO-001",
        scan_id="scan-1",
        project_id="demo",
        algorithm="RSA",
        primitive=CryptoPrimitive.PKE,
        parameter="2048",
        parameter_status=ParameterStatus.RESOLVED,
        usage=CryptoUsage.KEY_ESTABLISHMENT,
        artefact_type=ArtefactType.KEY_EXCHANGE,
        evidence=_rsa_evidence(),
        classification=Classification(
            artefact_type=ArtefactType.KEY_EXCHANGE,
            security_goal=SecurityGoal.CONFIDENTIALITY,
            data_lifetime_years=15,
            criticality=Criticality.HIGH,
        ),
        current_risk=CurrentRisk(
            is_currently_weak=False,
            severity=Severity.NONE,
            reason="RSA-2048 remains classically sound today.",
        ),
        quantum_risk=QuantumRisk(
            is_quantum_vulnerable=True,
            threat=QuantumThreat.SHOR_BREAKS,
            reason="Shor's algorithm breaks RSA outright.",
        ),
        mosca=MoscaAssessment(
            x=15,
            y=3,
            z=10,
            equation="15 + 3 > 10",
            result=True,
            tier=RiskTier.OVERDUE,
            margin_years=8,
            z_source="Demo assumption",
        ),
        risk_tier=RiskTier.OVERDUE,
        recommendation=Recommendation(
            strategy=MigrationStrategy.PQC,
            algorithm="ML-KEM-1024",
            parameter_set="ML-KEM-1024 (NIST Category 5)",
            rationale="Long-lived confidential data with an overdue Mosca result.",
            replaces="RSA-2048",
        ),
    )

    document = finding.to_firestore_document()

    required = {
        "scanId",
        "projectId",
        "algorithm",
        "primitive",
        "parameter",
        "mode",
        "usage",
        "artefactType",
        "filePath",
        "lineNumber",
        "evidence",
        "detectionMethod",
        "confidence",
        "dataLifetimeYears",
        "criticality",
        "currentRisk",
        "quantumRisk",
        "mosca",
        "riskTier",
        "recommendation",
        "rationale",
        "createdAt",
    }
    missing = required - document.keys()
    assert not missing, f"Firestore document is missing {missing}"

    assert document["filePath"] == "auth.py"
    assert document["lineNumber"] == 42
    assert document["evidence"] == "RSA.generate(2048)"
    assert document["dataLifetimeYears"] == 15
    assert document["riskTier"] == "overdue"
    assert document["mosca"]["equation"] == "15 + 3 > 10"
    assert document["rationale"] == finding.recommendation.rationale
    assert document["isQuantumSensitive"] is True
    assert document["isCurrentlyWeak"] is False


def test_finding_without_analysis_is_valid() -> None:
    """A finding must be inspectable mid-pipeline, not only when complete."""
    finding = Finding(id="CRYPTO-009", algorithm="AES", evidence=_rsa_evidence())

    assert finding.classification is None
    assert finding.mosca is None
    assert finding.is_quantum_sensitive is False
    assert finding.is_currently_weak is False


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------
def test_scan_duration_is_none_until_completed() -> None:
    scan = Scan(id="scan-1", project_id="demo", repository="demo-repo")
    assert scan.status is ScanStatus.PENDING
    assert scan.duration_seconds is None


def test_scan_firestore_document_shape() -> None:
    scan = Scan(id="scan-1", project_id="demo", repository="demo-repo")
    document = scan.to_firestore_document()

    for field in ("projectId", "ownerId", "status", "repository", "startedAt", "summary"):
        assert field in document
