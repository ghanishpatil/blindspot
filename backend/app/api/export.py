"""CBOM export endpoint.

Returns the generated CycloneDX CBOM as a downloadable JSON file.
The document served here is the same artefact produced during the scan.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import JSONResponse

from app.firebase.auth import CurrentUser

router = APIRouter(tags=["export"])


@router.get(
    "/export/cbom",
    summary="Download the generated CycloneDX CBOM",
    responses={
        200: {"content": {"application/json": {}}, "description": "CycloneDX CBOM."},
    },
)
async def export_cbom(
    user: CurrentUser,
    scan_id: str | None = Query(default=None, alias="scanId"),
) -> JSONResponse:
    """Return the CBOM for the last scan."""
    import json

    from app.api.scan import get_last_scan_data

    _, _, cbom_json = get_last_scan_data()
    if cbom_json is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No CBOM available. Run a scan first.",
        )

    cbom_doc = json.loads(cbom_json)

    return JSONResponse(
        content=cbom_doc,
        media_type="application/json",
        headers={
            "Content-Disposition": "attachment; filename=blindspot-cbom.json",
        },
    )
