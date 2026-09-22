"""Dependency-graph endpoint.

``GET /api/graph/{scanId}`` -- returns the bipartite blast-radius
graph for one scan. Nodes and edges are derived from the scan's
persisted findings; no additional scanning is performed.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.scans import (
    _iter_scan_files,
    _load_findings_json,
    _load_scan_json,
    _visible_to,
)
from app.config import Settings, get_settings
from app.firebase.auth import CurrentUser
from app.graph import build_dependency_graph

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/graph", tags=["graph"])


@router.get(
    "/{scan_id}",
    summary="Blast-radius / dependency graph for one scan",
)
async def get_graph(
    scan_id: str,
    user: CurrentUser,
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Return the bipartite (file, algorithm) graph for a scan.

    Owner-scoping matches ``GET /api/scans/{scanId}``: a 404 is
    returned for both missing and non-visible scans, so an attacker
    cannot probe for foreign scan ids.
    """
    for scan_file in _iter_scan_files(settings):
        record = _load_scan_json(scan_file)
        if record is None:
            continue
        if record.get("id") != scan_id:
            continue
        if not _visible_to(user, record):
            break

        findings = _load_findings_json(scan_file.parent)
        graph = build_dependency_graph(findings)
        return {
            "scanId": scan_id,
            "projectId": record.get("projectId"),
            "generatedAt": record.get("completedAt") or record.get("startedAt"),
            **graph.to_dict(),
        }

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"No scan with id {scan_id!r} was found on the local mirror.",
    )


__all__ = ["router"]
