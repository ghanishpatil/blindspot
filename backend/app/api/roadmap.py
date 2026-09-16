"""Migration roadmap endpoint.

``GET /api/roadmap`` builds the prioritized, costed migration plan from the
findings of the last scan. It reconstructs Finding objects from the stored
scan results (the same round-trip the fallback cache uses) and runs the
deterministic planner. No re-scan.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, status

from app.firebase.auth import CurrentUser
from app.models.finding import Finding
from app.roadmap.planner import build_roadmap

logger = logging.getLogger(__name__)

router = APIRouter(tags=["roadmap"])


@router.get("/roadmap", summary="Prioritized, costed migration roadmap")
async def get_roadmap(user: CurrentUser) -> dict:
    """Return the migration roadmap for the most recent scan."""
    from app.api.scan import get_last_scan_for

    scan, findings_data, _ = get_last_scan_for(user)
    if not findings_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No scan results available. Run a scan first.",
        )

    findings = [Finding.model_validate(item) for item in findings_data]
    scan_id = scan.get("id") if isinstance(scan, dict) else None

    roadmap = build_roadmap(findings, scan_id=scan_id)
    return roadmap.serialise()
