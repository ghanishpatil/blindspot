"""Migration roadmap planner.

``build_roadmap`` groups findings into strategy-based waves and orders each wave
by a deterministic priority score. The score composes three signals the
pipeline already produces:

    priority_score = tier_weight * 100 + criticality_weight * 10 + blast_radius

* **tier_weight** — Mosca urgency (overdue > transitional > low-risk)
* **criticality_weight** — business criticality (high > medium > low)
* **blast_radius** — co-located crypto usages in the same file, a proxy for
  change impact until the full dependency graph lands (Req 14 / 30).

Present-day-weak findings go on a separate immediate-remediation track;
unresolved-parameter findings go on an investigation track. This keeps
"broken today" distinct from "quantum migration urgency," exactly as the risk
engine does.

The function is deterministic: the same findings and configuration always
produce the same waves and ordering (``generated_at`` is metadata only).
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from app.models.finding import Criticality, Finding
from app.models.recommendation import MigrationStrategy
from app.models.risk import RiskTier
from app.models.roadmap import MigrationRoadmap, MigrationWave, RoadmapItem

# ── Scoring weights ───────────────────────────────────────────────────────
_TIER_WEIGHT: dict[RiskTier, int] = {
    RiskTier.OVERDUE: 3,
    RiskTier.TRANSITIONAL: 2,
    RiskTier.LOW_RISK: 1,
}
_CRIT_WEIGHT: dict[Criticality, int] = {
    Criticality.HIGH: 3,
    Criticality.MEDIUM: 2,
    Criticality.LOW: 1,
}

# ── Wave definitions, in display order ────────────────────────────────────
# (key, strategy, title, description)
_WAVE_DEFS: list[tuple[str, MigrationStrategy, str, str]] = [
    (
        "remediate_now",
        MigrationStrategy.REMEDIATE_NOW,
        "Immediate Remediation",
        "Cryptography that is already broken today. Fix now, independent of the "
        "quantum timeline.",
    ),
    (
        "wave_1",
        MigrationStrategy.PQC,
        "Wave 1 — Urgent PQC Migration",
        "Overdue under Mosca's inequality. Migrate to post-quantum algorithms first.",
    ),
    (
        "wave_2",
        MigrationStrategy.HYBRID,
        "Wave 2 — Hybrid Transition",
        "Approaching the migration window. Deploy hybrid classical + PQC.",
    ),
    (
        "wave_3",
        MigrationStrategy.DEFER,
        "Wave 3 — Monitor & Defer",
        "No immediate quantum urgency. Monitor and re-evaluate on schedule.",
    ),
    (
        "investigate",
        MigrationStrategy.INVESTIGATE,
        "Needs Investigation",
        "Parameters could not be resolved. Manual review is required before planning.",
    ),
]

_COST_BAND: dict[MigrationStrategy, str] = {
    MigrationStrategy.PQC: "high",
    MigrationStrategy.HYBRID: "medium",
    MigrationStrategy.DEFER: "low",
    MigrationStrategy.REMEDIATE_NOW: "low",
    MigrationStrategy.INVESTIGATE: "unknown",
}

_DEFAULT_EFFORT: dict[MigrationStrategy, str] = {
    MigrationStrategy.PQC: "high",
    MigrationStrategy.HYBRID: "moderate",
    MigrationStrategy.DEFER: "none",
    MigrationStrategy.REMEDIATE_NOW: "low",
    MigrationStrategy.INVESTIGATE: "investigation",
}


def _blast_radius_by_file(findings: list[Finding]) -> dict[str, int]:
    """Count crypto findings sharing each file path (change-impact proxy)."""
    counts: dict[str, int] = defaultdict(int)
    for finding in findings:
        counts[finding.file_path] += 1
    return counts


def _strategy_of(finding: Finding) -> MigrationStrategy:
    """The wave a finding belongs to — from its recommendation, or inferred."""
    if finding.recommendation is not None:
        return finding.recommendation.strategy

    # Fallback when a finding has not been through the recommender.
    if finding.is_currently_weak:
        return MigrationStrategy.REMEDIATE_NOW
    if finding.parameter_status.value == "unresolved":
        return MigrationStrategy.INVESTIGATE
    if finding.risk_tier == RiskTier.OVERDUE:
        return MigrationStrategy.PQC
    if finding.risk_tier == RiskTier.TRANSITIONAL:
        return MigrationStrategy.HYBRID
    return MigrationStrategy.DEFER


def _priority_score(finding: Finding, blast_radius: int) -> int:
    """Deterministic composite ordering score."""
    tier_weight = _TIER_WEIGHT.get(finding.risk_tier, 1) if finding.risk_tier else 1
    criticality = finding.classification.criticality if finding.classification else None
    crit_weight = _CRIT_WEIGHT.get(criticality, 2) if criticality else 2
    return tier_weight * 100 + crit_weight * 10 + blast_radius


def _to_item(finding: Finding, blast_radius: int) -> RoadmapItem:
    rec = finding.recommendation
    strategy = _strategy_of(finding)
    return RoadmapItem(
        finding_id=finding.id,
        display_name=finding.display_name,
        algorithm=finding.algorithm,
        file_path=finding.file_path,
        line_number=finding.line_number,
        strategy=strategy,
        current_algorithm=(rec.replaces if rec and rec.replaces else finding.display_name),
        target_algorithm=(rec.algorithm if rec else "Investigate"),
        parameter_set=(rec.parameter_set if rec else None),
        risk_tier=(finding.risk_tier.value if finding.risk_tier else None),
        criticality=(
            finding.classification.criticality.value if finding.classification else None
        ),
        priority_score=_priority_score(finding, blast_radius),
        blast_radius=blast_radius,
        effort=(rec.effort if rec and rec.effort else _DEFAULT_EFFORT[strategy]),
        cost_band=_COST_BAND[strategy],
        rationale=(rec.rationale if rec else "Recommendation pending."),
        is_current_weakness=finding.is_currently_weak,
    )


def build_roadmap(
    findings: list[Finding], scan_id: str | None = None
) -> MigrationRoadmap:
    """Build the prioritized, costed migration roadmap from enriched findings.

    Deterministic: the same input always yields the same waves and ordering.
    """
    blast = _blast_radius_by_file(findings)

    buckets: dict[MigrationStrategy, list[RoadmapItem]] = defaultdict(list)
    for finding in findings:
        item = _to_item(finding, blast.get(finding.file_path, 1))
        buckets[item.strategy].append(item)

    waves: list[MigrationWave] = []
    summary: dict[str, int] = {}
    total = 0

    for order, (key, strategy, title, description) in enumerate(_WAVE_DEFS, start=1):
        items = buckets.get(strategy, [])
        # Highest priority first; finding_id as a stable deterministic tiebreak.
        items.sort(key=lambda it: (-it.priority_score, it.finding_id))
        waves.append(
            MigrationWave(
                key=key,
                order=order,
                title=title,
                description=description,
                strategy=strategy,
                items=items,
            )
        )
        summary[key] = len(items)
        total += len(items)

    return MigrationRoadmap(
        scan_id=scan_id,
        generated_at=datetime.now(timezone.utc),
        total_items=total,
        waves=waves,
        summary=summary,
    )
