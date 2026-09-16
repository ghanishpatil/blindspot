"""Compliance sensitivity models.

The pipeline computes each finding's Mosca urgency under one active quantum
horizon (Z). But *which* deadline you measure against is a policy choice, not a
fact: India's CII advisory, NIST IR 8547's 2030/2035 dates, and a mid-range
CRQC estimate all imply different Z values, and the *same* finding can be
"low-risk" under one and "overdue" under another.

These models express that re-evaluation. Nothing here re-scans or re-derives
X or Y — it reuses each finding's already-computed X (data lifetime) and Y
(migration time) and re-runs the *same* ``mosca.assess`` under every preset Z,
so the tiers are consistent with the rest of the platform by construction.

Structure:

* :class:`CompliancePreset` — a named Z (regulatory deadline / research estimate).
* :class:`ComplianceTier` — one finding's Mosca result under one preset.
* :class:`ComplianceFinding` — one finding with its tier under every preset.
* :class:`ComplianceSummary` — per-preset tier counts plus the overdue delta
  against the baseline preset.
* :class:`ComplianceEvaluation` — the full matrix for a scan: presets, findings,
  and per-preset summaries.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from app.models.base import BlindspotModel


class CompliancePreset(BlindspotModel):
    """A named quantum horizon the findings can be measured against."""

    name: str
    z: float = Field(description="Mosca Z: years until a CRQC under this policy.")
    target_year: float = Field(description="Calendar year Z resolves to.")
    source: str = Field(description="Provenance of this deadline / estimate.")


class ComplianceTier(BlindspotModel):
    """One finding's Mosca urgency under one preset's Z."""

    tier: str = Field(description="overdue | transitional | low-risk.")
    applicable: bool = Field(
        description="False when Mosca does not apply (algorithm Shor doesn't break)."
    )
    x: float = Field(description="Data secrecy lifetime, years.")
    y: float = Field(description="Migration time, years.")
    z: float = Field(description="Quantum horizon under this preset, years.")
    equation: str = Field(description="The X + Y > Z inequality, rendered verbatim.")
    margin_years: float = Field(description="(X + Y) - Z. Positive means overdue.")


class ComplianceFinding(BlindspotModel):
    """A finding with its tier under every preset, keyed by preset name."""

    finding_id: str
    display_name: str
    algorithm: str
    file_path: str
    line_number: int | None = None
    criticality: str | None = None
    is_quantum_vulnerable: bool = False

    baseline_tier: str = Field(description="Tier under the baseline preset.")
    tiers_by_preset: dict[str, ComplianceTier] = Field(
        default_factory=dict,
        description="Mosca result per preset, keyed by preset name.",
    )


class ComplianceSummary(BlindspotModel):
    """Tier counts for all findings under one preset."""

    overdue: int = Field(ge=0)
    transitional: int = Field(ge=0)
    low_risk: int = Field(ge=0)
    not_applicable: int = Field(ge=0)
    total: int = Field(ge=0)
    overdue_delta: int = Field(
        description="Change in overdue count versus the baseline preset."
    )


class ComplianceEvaluation(BlindspotModel):
    """The full compliance-sensitivity matrix for one scan."""

    scan_id: str | None = None
    generated_at: datetime = Field(description="UTC timestamp the matrix was produced.")
    baseline_preset_name: str = Field(description="Preset used as the comparison baseline.")
    total_findings: int = Field(ge=0)
    presets: list[CompliancePreset] = Field(default_factory=list)
    findings: list[ComplianceFinding] = Field(default_factory=list)
    summary_by_preset: dict[str, ComplianceSummary] = Field(
        default_factory=dict,
        description="Tier-count summary per preset, keyed by preset name.",
    )
