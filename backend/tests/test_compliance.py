"""Compliance sensitivity tests.

Cover the evaluator's core promise: the *same* finding re-tiers as the quantum
horizon (Z) changes, the tiers are produced by the same Mosca engine the
pipeline uses, findings Shor cannot break never flip, and the per-preset
summaries (incl. the overdue delta vs. baseline) are correct. Plus the API
round-trip.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.compliance.evaluator import evaluate_compliance
from app.models.finding import (
    Classification,
    Criticality,
    DetectionMethod,
    Evidence,
    Finding,
)
from app.risk import mosca


def make_finding(
    fid: str,
    algorithm: str,
    x: float,
    *,
    y: float = 3.0,
    criticality: Criticality = Criticality.MEDIUM,
    file_path: str = "a.py",
) -> Finding:
    """Build an enriched Finding the way the pipeline does.

    Uses the real ``mosca`` helpers so ``quantum_risk`` and ``mosca`` carry
    the same values the pipeline would produce for this algorithm.
    """
    evidence = Evidence(
        file_path=file_path,
        line_number=10,
        code_snippet="x",
        detection_method=DetectionMethod.SEMGREP_API_PATTERN,
        confidence=0.9,
    )
    classification = Classification(data_lifetime_years=x, criticality=criticality)
    quantum_risk = mosca.assess_quantum_risk(algorithm)
    current_risk = mosca.assess_current_risk(algorithm)
    assessment = mosca.assess(
        x, y, 10.0, quantum_vulnerable=quantum_risk.is_quantum_vulnerable
    )
    return Finding(
        id=fid,
        algorithm=algorithm,
        evidence=evidence,
        classification=classification,
        quantum_risk=quantum_risk,
        current_risk=current_risk,
        mosca=assessment,
        risk_tier=assessment.tier,
    )


# ── Presets ────────────────────────────────────────────────────────────────

def test_presets_loaded_with_baseline() -> None:
    ev = evaluate_compliance([make_finding("C1", "RSA", 3.0)])
    # config ships seven named presets; the first is the baseline.
    assert len(ev.presets) == 7
    assert ev.baseline_preset_name == ev.presets[0].name
    assert ev.baseline_preset_name == "Demo default"


# ── The core behaviour: a finding re-tiers as Z changes ─────────────────────

def test_quantum_finding_flips_tier_across_presets() -> None:
    """RSA with X=3, Y=3 (X+Y=6): low-risk under a 15y CRQC estimate,
    transitional under the 10y demo default, overdue under India's 2027 CII
    deadline (Z=1). The shift is real Mosca output, not presentation."""
    ev = evaluate_compliance([make_finding("C1", "RSA", 3.0, y=3.0)])
    f = ev.findings[0]

    crqc = next(p for p in ev.presets if p.z == 15.0)
    india_a = next(p for p in ev.presets if p.target_year == 2027)

    assert f.tiers_by_preset[crqc.name].tier == "low-risk"
    assert f.tiers_by_preset[ev.baseline_preset_name].tier == "transitional"
    assert f.tiers_by_preset[india_a.name].tier == "overdue"
    # And every preset's result is marked applicable for a Shor-breakable algo.
    assert all(t.applicable for t in f.tiers_by_preset.values())


def test_non_vulnerable_finding_never_flips() -> None:
    """Symmetric / hash algorithms Shor can't break stay low-risk and
    not-applicable under every preset, regardless of Z."""
    ev = evaluate_compliance(
        [make_finding("A", "AES", 20.0), make_finding("M", "MD5", 20.0)]
    )
    for f in ev.findings:
        assert f.is_quantum_vulnerable is False
        for tier in f.tiers_by_preset.values():
            assert tier.applicable is False
            assert tier.tier == "low-risk"


def test_baseline_tier_matches_baseline_preset() -> None:
    ev = evaluate_compliance([make_finding("C1", "RSA", 3.0)])
    f = ev.findings[0]
    assert f.baseline_tier == f.tiers_by_preset[ev.baseline_preset_name].tier


# ── Summaries ───────────────────────────────────────────────────────────────

def test_summary_overdue_delta_vs_baseline() -> None:
    """One RSA finding: transitional at baseline (delta 0), overdue under the
    2027 deadline (delta +1)."""
    ev = evaluate_compliance([make_finding("C1", "RSA", 3.0)])

    baseline_summary = ev.summary_by_preset[ev.baseline_preset_name]
    assert baseline_summary.overdue == 0
    assert baseline_summary.overdue_delta == 0

    india_a = next(p for p in ev.presets if p.target_year == 2027)
    india_summary = ev.summary_by_preset[india_a.name]
    assert india_summary.overdue == 1
    assert india_summary.overdue_delta == 1


def test_summary_tiers_sum_to_total() -> None:
    findings = [
        make_finding("C1", "RSA", 3.0),
        make_finding("C2", "ECDH", 15.0),
        make_finding("C3", "AES", 20.0),
        make_finding("C4", "MD5", 5.0),
    ]
    ev = evaluate_compliance(findings)
    for summary in ev.summary_by_preset.values():
        assert summary.overdue + summary.transitional + summary.low_risk == summary.total
        assert summary.total == len(findings)


# ── Determinism ─────────────────────────────────────────────────────────────

def test_evaluation_is_deterministic() -> None:
    findings = [make_finding("C1", "RSA", 3.0), make_finding("C2", "ECDSA", 10.0)]
    first = evaluate_compliance(findings)
    second = evaluate_compliance(findings)

    def shape(ev) -> list:
        return [
            (f.finding_id, {name: t.tier for name, t in f.tiers_by_preset.items()})
            for f in ev.findings
        ]

    assert shape(first) == shape(second)


# ── API endpoint ────────────────────────────────────────────────────────────

def test_compliance_requires_auth(client: TestClient) -> None:
    assert client.get("/api/compliance").status_code == 401


def test_compliance_404_before_scan(auth_bypassed_client: TestClient) -> None:
    from app.api import scan as scan_module

    scan_module._last_scan = None
    scan_module._last_findings = None
    scan_module._last_cbom = None

    assert auth_bypassed_client.get("/api/compliance").status_code == 404


def test_compliance_returns_matrix_after_scan(auth_bypassed_client: TestClient) -> None:
    """Endpoint reconstructs findings from stored results and re-tiers them."""
    from app.api import scan as scan_module

    findings = [
        make_finding("C1", "RSA", 3.0, criticality=Criticality.HIGH),
        make_finding("C2", "AES", 20.0),
    ]
    scan_module._last_scan = {"id": "scan-x"}
    scan_module._last_findings = [f.serialise() for f in findings]
    scan_module._last_cbom = "{}"

    response = auth_bypassed_client.get("/api/compliance")
    assert response.status_code == 200

    body = response.json()
    assert body["scanId"] == "scan-x"
    assert body["totalFindings"] == 2
    assert len(body["presets"]) == 7
    assert body["baselinePresetName"] == "Demo default"
    # camelCase serialisation is intact.
    first = body["findings"][0]
    assert "tiersByPreset" in first
    assert "isQuantumVulnerable" in first

    # Cleanup shared module state.
    scan_module._last_scan = None
    scan_module._last_findings = None
    scan_module._last_cbom = None
