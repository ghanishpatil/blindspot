"""Compliance sensitivity endpoint.

``GET /api/compliance`` re-tiers the findings of the last scan under every
named quantum-horizon preset (India CII deadlines, NIST IR 8547 dates, CRQC
estimate, demo default). It reconstructs Finding objects from the stored scan
results — the same round-trip ``/roadmap`` uses — and runs the deterministic
evaluator. No re-scan.

The whole matrix (findings x presets) is returned in one payload so the GUI can
switch presets instantly without another round-trip.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, status

from app.compliance.evaluator import evaluate_compliance
from app.firebase.auth import CurrentUser
from app.models.finding import Finding

logger = logging.getLogger(__name__)

router = APIRouter(tags=["compliance"])


@router.get("/compliance", summary="Re-tier findings under regulatory Z presets")
async def get_compliance(user: CurrentUser) -> dict:
    """Return the compliance-sensitivity matrix for the most recent scan."""
    from app.api.scan import get_last_scan_for

    scan, findings_data, _ = get_last_scan_for(user)
    if not findings_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No scan results available. Run a scan first.",
        )

    findings = [Finding.model_validate(item) for item in findings_data]
    scan_id = scan.get("id") if isinstance(scan, dict) else None

    evaluation = evaluate_compliance(findings, scan_id=scan_id)
    return evaluation.serialise()
