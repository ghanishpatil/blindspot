"""Scan lifecycle models."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import Field, computed_field

from app.models.base import BlindspotModel


class ScanStatus(str, Enum):
    """Lifecycle state of a scan."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanMode(str, Enum):
    """Whether results came from a real scan or the cached fallback.

    The distinction is always surfaced in the UI. A cached result is never
    presented as a live scan.
    """

    LIVE = "live"
    CACHED = "cached"


class ScanSummary(BlindspotModel):
    """Aggregate counts backing the dashboard summary cards.

    ``quantum_sensitive`` and ``current_weak_crypto`` are counted separately and
    may overlap: an algorithm can be broken today *and* quantum vulnerable.
    """

    total_findings: int = Field(default=0, ge=0)
    quantum_sensitive: int = Field(default=0, ge=0)
    overdue: int = Field(default=0, ge=0)
    transitional: int = Field(default=0, ge=0)
    low_risk: int = Field(default=0, ge=0)
    current_weak_crypto: int = Field(default=0, ge=0)
    hndl_exposed: int = Field(
        default=0,
        ge=0,
        description=(
            "Confidentiality findings exposed to harvest-now-decrypt-later: "
            "quantum-vulnerable and overdue under Mosca."
        ),
    )
    needs_verification: int = Field(
        default=0,
        ge=0,
        description=(
            "Findings flagged for manual review: low detection confidence or "
            "an unresolved parameter the risk model depends on."
        ),
    )
    unresolved_parameters: int = Field(
        default=0, ge=0, description="Findings where a parameter could not be resolved."
    )
    by_algorithm: dict[str, int] = Field(default_factory=dict)
    by_artefact_type: dict[str, int] = Field(default_factory=dict)
    by_confidence_level: dict[str, int] = Field(default_factory=dict)
    files_scanned: int = Field(default=0, ge=0)


class ScanRequest(BlindspotModel):
    """Request body for ``POST /api/scan``."""

    project_id: str | None = Field(
        default=None, description="Target project. Defaults to the demo project."
    )
    repository_url: str | None = Field(
        default=None,
        description=(
            "Remote git repository URL (HTTPS, allowlisted host) to clone and "
            "scan. Takes precedence over repository_path for LIVE scans."
        ),
    )
    repository_path: str | None = Field(
        default=None,
        description=(
            "Local filesystem path to scan. Development use; deployed scans use "
            "repository_url. Defaults to the seeded demo repository."
        ),
    )
    image_ref: str | None = Field(
        default=None,
        description=(
            "Container image reference (e.g. 'python:3.11-slim') to pull with a "
            "host container CLI and scan. Layers are flattened and run through "
            "the same scanners as a repository."
        ),
    )
    image_archive_path: str | None = Field(
        default=None,
        description=(
            "Local path to a saved image archive ('docker save' / OCI "
            "docker-archive tarball) to scan. Development use only."
        ),
    )
    mode: ScanMode = Field(
        default=ScanMode.LIVE,
        description="LIVE performs a real scan; CACHED loads the last successful result.",
    )


class Scan(BlindspotModel):
    """A scan record, mirroring ``scans/{scanId}`` in Firestore."""

    id: str
    project_id: str
    owner_id: str | None = None
    status: ScanStatus = ScanStatus.PENDING
    mode: ScanMode = ScanMode.LIVE
    repository: str = Field(description="Path or name of the scanned repository.")
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    finding_count: int = Field(default=0, ge=0)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    cbom_path: str | None = Field(
        default=None, description="Storage path of the generated CBOM."
    )
    error: str | None = Field(
        default=None, description="Failure reason when status is FAILED."
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def duration_seconds(self) -> float | None:
        """Wall-clock scan duration, or None while still running."""
        if self.completed_at is None:
            return None
        return round((self.completed_at - self.started_at).total_seconds(), 3)

    def to_firestore_document(self) -> dict[str, Any]:
        """Flatten to the Firestore ``scans/{scanId}`` shape."""
        return {
            "projectId": self.project_id,
            "ownerId": self.owner_id,
            "status": self.status.value,
            "mode": self.mode.value,
            "repository": self.repository,
            "startedAt": self.started_at.isoformat(),
            "completedAt": self.completed_at.isoformat() if self.completed_at else None,
            "durationSeconds": self.duration_seconds,
            "findingCount": self.finding_count,
            "summary": self.summary.serialise(),
            "cbomPath": self.cbom_path,
            "error": self.error,
        }


class ScanResponse(BlindspotModel):
    """Response body for ``POST /api/scan``."""

    scan_id: str
    status: ScanStatus
    mode: ScanMode
    repository: str
    finding_count: int = Field(default=0, ge=0)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    duration_seconds: float | None = None
    cbom_available: bool = False
    message: str | None = None


class Project(BlindspotModel):
    """A scan target, mirroring ``projects/{projectId}`` in Firestore."""

    id: str
    name: str
    description: str | None = None
    owner_id: str | None = None
    repository_path: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
