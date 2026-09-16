"""Migration roadmap models — the hero output.

The roadmap turns a flat list of findings into an ordered, costed migration
plan: *what to fix first, in what order, at what effort and cost*. This is the
capability the PS asks for under "preparedness, financial and operational
investment," and the one most discovery tools stop short of.

Structure:

* :class:`RoadmapItem` — one finding placed in the plan, with its priority
  score, target algorithm, effort, and cost band.
* :class:`MigrationWave` — an ordered group of items sharing a strategy
  (immediate remediation, urgent PQC, hybrid transition, monitor, investigate).
* :class:`MigrationRoadmap` — the full ordered set of waves plus summary counts.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, computed_field

from app.models.base import BlindspotModel
from app.models.recommendation import MigrationStrategy


class RoadmapItem(BlindspotModel):
    """One finding placed in the migration plan."""

    finding_id: str
    display_name: str
    algorithm: str
    file_path: str
    line_number: int | None = None

    strategy: MigrationStrategy
    current_algorithm: str = Field(description="The algorithm being replaced.")
    target_algorithm: str = Field(description="Recommended PQC/hybrid target, or action.")
    parameter_set: str | None = None

    risk_tier: str | None = Field(
        default=None, description="overdue | transitional | low-risk | null."
    )
    criticality: str | None = Field(default=None, description="low | medium | high.")

    priority_score: int = Field(
        description="Composite ordering score: tier x100 + criticality x10 + blast radius."
    )
    blast_radius: int = Field(
        default=0,
        ge=0,
        description=(
            "Co-located crypto usages in the same file — a proxy for change "
            "impact until the full dependency graph lands."
        ),
    )
    effort: str = Field(description="Rough migration effort: low | moderate | high | none.")
    cost_band: str = Field(description="Coarse relative cost: low | medium | high | unknown.")
    rationale: str
    is_current_weakness: bool = False


class MigrationWave(BlindspotModel):
    """An ordered group of roadmap items sharing a migration strategy."""

    key: str = Field(description="Stable identifier, e.g. 'wave_1'.")
    order: int = Field(description="Display order, 1-based.")
    title: str
    description: str
    strategy: MigrationStrategy
    items: list[RoadmapItem] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def item_count(self) -> int:
        """Number of items in this wave."""
        return len(self.items)


class MigrationRoadmap(BlindspotModel):
    """The full prioritized, costed migration plan for a scan."""

    scan_id: str | None = None
    generated_at: datetime = Field(description="UTC timestamp the roadmap was produced.")
    total_items: int = Field(ge=0)
    waves: list[MigrationWave] = Field(default_factory=list)
    summary: dict[str, int] = Field(
        default_factory=dict, description="Item count per wave key."
    )
