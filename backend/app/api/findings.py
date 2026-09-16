"""Findings endpoints.

Serves findings from the in-memory store populated by POST /scan.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from app.firebase.auth import CurrentUser

router = APIRouter(tags=["findings"])


@router.get(
    "/findings",
    summary="List findings for a scan",
)
async def list_findings(
    user: CurrentUser,
    scan_id: str | None = Query(default=None, alias="scanId"),
    project_id: str | None = Query(default=None, alias="projectId"),
) -> list[dict]:
    """Return findings from the last scan."""
    from app.api.scan import get_last_scan_for

    _, findings, _ = get_last_scan_for(user)
    if findings is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No scan results available. Run a scan first.",
        )

    # Filter by scanId if provided.
    if scan_id:
        findings = [f for f in findings if f.get("scanId") == scan_id]

    return findings


@router.get(
    "/findings/{finding_id}",
    summary="Get one finding with full analysis",
)
async def get_finding(finding_id: str, user: CurrentUser) -> dict:
    """Return a single finding including evidence, risk, and recommendation."""
    from app.api.scan import get_last_scan_for

    _, findings, _ = get_last_scan_for(user)
    if findings is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No scan results available. Run a scan first.",
        )

    for f in findings:
        if f.get("id") == finding_id:
            return f

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Finding {finding_id!r} not found.",
    )
