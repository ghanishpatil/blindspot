"""Compliance sensitivity evaluator.

``evaluate_compliance`` takes enriched findings and, for every named Z preset
in configuration, re-runs Mosca's inequality to produce that finding's tier
under that policy. It does **not** re-scan, re-classify, or invent new inputs:
it reuses each finding's already-computed X (data lifetime) and Y (migration
time) and the same :func:`app.risk.mosca.assess` the pipeline uses, so a tier
shown here is identical to the tier the pipeline would produce if that Z were
the active one.

The point is to make the policy dependency visible: the same RSA-2048 key can
be "low-risk" under a 15-year CRQC estimate and "overdue" under India's 2027
CII deadline. That shift is a genuine, defensible output of the model, not a
presentation trick.

Determinism: same findings + same configuration -> same matrix
(``generated_at`` is metadata only).
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.config import Settings, get_settings
from app.models.compliance import (
    ComplianceEvaluation,
    ComplianceFinding,
    CompliancePreset,
    ComplianceSummary,
    ComplianceTier,
)
from app.models.finding import Finding
from app.models.risk import RiskTier
from app.risk import mosca


def _load_presets(settings: Settings) -> list[CompliancePreset]:
    """Read the named Z presets from configuration into typed models."""
    presets: list[CompliancePreset] = []
    for raw in settings.z_presets:
        presets.append(
            CompliancePreset(
                name=str(raw["name"]),
                z=float(raw["z"]),  # type: ignore[arg-type]
                target_year=float(raw["targetYear"]),  # type: ignore[arg-type]
                source=str(raw["source"]),
            )
        )
    return presets


def _tier_under(finding: Finding, preset: CompliancePreset, settings: Settings) -> ComplianceTier:
    """Re-evaluate one finding's Mosca urgency under one preset's Z."""
    m = finding.mosca

    # A finding that never went through the Mosca stage (no X/Y) can't be
    # re-tiered. Report it as not-applicable rather than fabricating numbers.
    if m is None:
        return ComplianceTier(
            tier=(finding.risk_tier.value if finding.risk_tier else RiskTier.LOW_RISK.value),
            applicable=False,
            x=0.0,
            y=0.0,
            z=preset.z,
            equation="n/a",
            margin_years=0.0,
        )

    quantum_vulnerable = bool(finding.quantum_risk and finding.quantum_risk.is_quantum_vulnerable)
    assessment = mosca.assess(
        m.x,
        m.y,
        preset.z,
        z_source=preset.source,
        quantum_vulnerable=quantum_vulnerable,
        settings=settings,
    )
    return ComplianceTier(
        tier=assessment.tier.value,
        applicable=assessment.applicable,
        x=assessment.x,
        y=assessment.y,
        z=assessment.z,
        equation=assessment.equation,
        margin_years=assessment.margin_years,
    )


def _summarise(
    findings: list[ComplianceFinding], preset_name: str, baseline_overdue: int
) -> ComplianceSummary:
    """Count tiers across all findings under one preset."""
    overdue = transitional = low_risk = not_applicable = 0
    for f in findings:
        tier = f.tiers_by_preset[preset_name]
        if not tier.applicable:
            not_applicable += 1
            # A not-applicable finding still carries a tier (low-risk); count it
            # there too so the tiers sum to the total and the UI stays honest.
        if tier.tier == RiskTier.OVERDUE.value:
            overdue += 1
        elif tier.tier == RiskTier.TRANSITIONAL.value:
            transitional += 1
        else:
            low_risk += 1
    return ComplianceSummary(
        overdue=overdue,
        transitional=transitional,
        low_risk=low_risk,
        not_applicable=not_applicable,
        total=len(findings),
        overdue_delta=overdue - baseline_overdue,
    )


def evaluate_compliance(
    findings: list[Finding],
    scan_id: str | None = None,
    settings: Settings | None = None,
) -> ComplianceEvaluation:
    """Build the compliance-sensitivity matrix for a set of findings.

    The first preset (``Demo default``) is the baseline every other preset's
    ``overdue_delta`` is measured against.
    """
    settings = settings or get_settings()
    presets = _load_presets(settings)

    # Guard: configuration always ships presets, but never index blindly.
    baseline_name = presets[0].name if presets else "Demo default"

    compliance_findings: list[ComplianceFinding] = []
    for finding in findings:
        tiers = {p.name: _tier_under(finding, p, settings) for p in presets}
        baseline_tier = (
            tiers[baseline_name].tier if baseline_name in tiers else RiskTier.LOW_RISK.value
        )
        criticality = (
            finding.classification.criticality.value if finding.classification else None
        )
        compliance_findings.append(
            ComplianceFinding(
                finding_id=finding.id,
                display_name=finding.display_name,
                algorithm=finding.algorithm,
                file_path=finding.file_path,
                line_number=finding.line_number,
                criticality=criticality,
                is_quantum_vulnerable=bool(
                    finding.quantum_risk and finding.quantum_risk.is_quantum_vulnerable
                ),
                baseline_tier=baseline_tier,
                tiers_by_preset=tiers,
            )
        )

    # Baseline overdue count, then per-preset summaries relative to it.
    baseline_overdue = sum(
        1
        for f in compliance_findings
        if f.tiers_by_preset[baseline_name].tier == RiskTier.OVERDUE.value
    ) if compliance_findings else 0

    summary_by_preset = {
        p.name: _summarise(compliance_findings, p.name, baseline_overdue) for p in presets
    }

    return ComplianceEvaluation(
        scan_id=scan_id,
        generated_at=datetime.now(timezone.utc),
        baseline_preset_name=baseline_name,
        total_findings=len(compliance_findings),
        presets=presets,
        findings=compliance_findings,
        summary_by_preset=summary_by_preset,
    )
