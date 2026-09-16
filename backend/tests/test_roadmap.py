"""Migration roadmap tests — the hero feature.

Cover the planner's wave grouping, deterministic ordering, the separate
present-day-weakness track, and the API endpoint round-trip.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.models.finding import (
    Classification,
    Criticality,
    DetectionMethod,
    Evidence,
    Finding,
)
from app.models.recommendation import MigrationStrategy, Recommendation
from app.models.risk import CurrentRisk, RiskTier, Severity
from app.roadmap.planner import build_roadmap


def make_finding(
    fid: str,
    algorithm: str,
    strategy: MigrationStrategy,
    *,
    tier: RiskTier | None = None,
    criticality: Criticality = Criticality.MEDIUM,
    file_path: str = "a.py",
    weak: bool = False,
    target: str = "ML-KEM-768",
) -> Finding:
    """Build a fully enriched Finding for planner tests."""
    evidence = Evidence(
        file_path=file_path,
        line_number=10,
        code_snippet="x",
        detection_method=DetectionMethod.SEMGREP_API_PATTERN,
        confidence=0.9,
    )
    classification = Classification(data_lifetime_years=5.0, criticality=criticality)
    recommendation = Recommendation(
        strategy=strategy,
        algorithm=target,
        rationale="test rationale",
        replaces=algorithm,
    )
    current_risk = CurrentRisk(
        is_currently_weak=weak,
        severity=Severity.HIGH if weak else Severity.NONE,
        reason="weak" if weak else "sound",
    )
    return Finding(
        id=fid,
        algorithm=algorithm,
        evidence=evidence,
        classification=classification,
        risk_tier=tier,
        recommendation=recommendation,
        current_risk=current_risk,
    )


# ── Planner: wave grouping ────────────────────────────────────────────────

def test_waves_group_by_strategy() -> None:
    findings = [
        make_finding("C1", "RSA", MigrationStrategy.PQC, tier=RiskTier.OVERDUE, criticality=Criticality.HIGH),
        make_finding("C2", "ECDH", MigrationStrategy.HYBRID, tier=RiskTier.TRANSITIONAL),
        make_finding("C3", "ECDSA", MigrationStrategy.DEFER, tier=RiskTier.LOW_RISK, criticality=Criticality.LOW),
        make_finding("C4", "MD5", MigrationStrategy.REMEDIATE_NOW, tier=RiskTier.LOW_RISK, criticality=Criticality.HIGH, weak=True),
        make_finding("C5", "RSA", MigrationStrategy.INVESTIGATE, criticality=Criticality.MEDIUM),
    ]
    roadmap = build_roadmap(findings, scan_id="scan-1")

    by_key = {wave.key: wave for wave in roadmap.waves}
    assert by_key["remediate_now"].item_count == 1
    assert by_key["wave_1"].item_count == 1
    assert by_key["wave_2"].item_count == 1
    assert by_key["wave_3"].item_count == 1
    assert by_key["investigate"].item_count == 1
    assert roadmap.total_items == 5
    assert roadmap.scan_id == "scan-1"


def test_wave_order_is_stable() -> None:
    roadmap = build_roadmap([])
    keys = [wave.key for wave in roadmap.waves]
    assert keys == ["remediate_now", "wave_1", "wave_2", "wave_3", "investigate"]


# ── Planner: ordering within a wave ───────────────────────────────────────

def test_ordering_within_wave_by_priority() -> None:
    """Higher business criticality ranks first within the same tier/wave."""
    findings = [
        make_finding("C_low", "RSA", MigrationStrategy.PQC, tier=RiskTier.OVERDUE, criticality=Criticality.LOW, file_path="a.py"),
        make_finding("C_high", "RSA", MigrationStrategy.PQC, tier=RiskTier.OVERDUE, criticality=Criticality.HIGH, file_path="b.py"),
    ]
    roadmap = build_roadmap(findings)
    wave1 = next(w for w in roadmap.waves if w.key == "wave_1")
    assert wave1.items[0].finding_id == "C_high"
    assert wave1.items[1].finding_id == "C_low"


def test_blast_radius_counts_colocated_findings() -> None:
    """Two findings in the same file each report a blast radius of 2."""
    findings = [
        make_finding("C1", "RSA", MigrationStrategy.PQC, tier=RiskTier.OVERDUE, file_path="same.py"),
        make_finding("C2", "ECDSA", MigrationStrategy.PQC, tier=RiskTier.OVERDUE, file_path="same.py"),
        make_finding("C3", "ECDH", MigrationStrategy.PQC, tier=RiskTier.OVERDUE, file_path="other.py"),
    ]
    roadmap = build_roadmap(findings)
    wave1 = next(w for w in roadmap.waves if w.key == "wave_1")
    by_id = {it.finding_id: it for it in wave1.items}
    assert by_id["C1"].blast_radius == 2
    assert by_id["C2"].blast_radius == 2
    assert by_id["C3"].blast_radius == 1


# ── Planner: present-day-weakness track ───────────────────────────────────

def test_currently_weak_goes_to_remediation_track() -> None:
    findings = [
        make_finding("C1", "MD5", MigrationStrategy.REMEDIATE_NOW, tier=RiskTier.LOW_RISK, criticality=Criticality.HIGH, weak=True),
    ]
    roadmap = build_roadmap(findings)
    remediation = next(w for w in roadmap.waves if w.key == "remediate_now")
    assert remediation.item_count == 1
    assert remediation.items[0].is_current_weakness is True
    # It must NOT appear in the quantum waves.
    for key in ("wave_1", "wave_2", "wave_3"):
        wave = next(w for w in roadmap.waves if w.key == key)
        assert wave.item_count == 0


# ── Planner: determinism ──────────────────────────────────────────────────

def test_roadmap_is_deterministic() -> None:
    findings = [
        make_finding("C1", "RSA", MigrationStrategy.PQC, tier=RiskTier.OVERDUE, criticality=Criticality.HIGH),
        make_finding("C2", "ECDH", MigrationStrategy.HYBRID, tier=RiskTier.TRANSITIONAL),
    ]
    first = build_roadmap(findings)
    second = build_roadmap(findings)

    def shape(rm) -> list:
        return [(w.key, [it.finding_id for it in w.items]) for w in rm.waves]

    assert shape(first) == shape(second)


# ── API endpoint ──────────────────────────────────────────────────────────

def test_roadmap_requires_auth(client: TestClient) -> None:
    assert client.get("/api/roadmap").status_code == 401


def test_roadmap_404_before_scan(auth_bypassed_client: TestClient) -> None:
    from app.api import scan as scan_module

    scan_module._last_scan = None
    scan_module._last_findings = None
    scan_module._last_cbom = None

    assert auth_bypassed_client.get("/api/roadmap").status_code == 404


def test_roadmap_returns_waves_after_scan(auth_bypassed_client: TestClient) -> None:
    """Endpoint reconstructs findings from stored results and builds the roadmap."""
    from app.api import scan as scan_module

    findings = [
        make_finding("C1", "RSA", MigrationStrategy.PQC, tier=RiskTier.OVERDUE, criticality=Criticality.HIGH),
        make_finding("C2", "MD5", MigrationStrategy.REMEDIATE_NOW, tier=RiskTier.LOW_RISK, weak=True),
    ]
    scan_module._last_scan = {"id": "scan-x"}
    scan_module._last_findings = [f.serialise() for f in findings]
    scan_module._last_cbom = "{}"

    response = auth_bypassed_client.get("/api/roadmap")
    assert response.status_code == 200

    body = response.json()
    assert body["totalItems"] == 2
    assert body["scanId"] == "scan-x"
    keys = {wave["key"] for wave in body["waves"]}
    assert {"remediate_now", "wave_1", "wave_2", "wave_3", "investigate"} == keys

    # Cleanup shared module state.
    scan_module._last_scan = None
    scan_module._last_findings = None
    scan_module._last_cbom = None
