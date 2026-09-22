"""Cross-scan diff endpoint.

``GET /api/scans/diff?base=<scanId>&head=<scanId>`` loads both scan
snapshots from the on-disk artefact mirror, runs
:func:`app.diff.cbom_diff.compute_diff`, and returns the structured
result. Reuses every helper from :mod:`app.api.scans`, so the two
endpoints share exactly one filesystem walker and one owner-scoping
rule -- a divergence there would be a bug across both.

Rules:

1. Both scan ids MUST be visible to the caller (same owner scoping as
   ``GET /api/scans/{scanId}``). Missing / unknown / unauthorised scans
   surface as 404 without leaking which of those three it is.
2. Read-only, no side effects. A diff never persists anywhere.
3. Air-gap-safe. Never touches Firebase.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.scans import (
    _iter_scan_files,
    _load_findings_json,
    _load_scan_json,
    _visible_to,
)
from app.config import Settings, get_settings
from app.diff.cbom_diff import compute_diff
from app.firebase.auth import AuthenticatedUser, CurrentUser

logger = logging.getLogger(__name__)

router = APIRouter(tags=["scans"])


def _load_visible_scan(
    scan_id: str,
    user: AuthenticatedUser,
    settings: Settings,
) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
    """Return ``(scan_record, findings)`` for one scan id, or ``None``.

    ``None`` is returned when:

    * the scan file does not exist,
    * the file exists but is unreadable / malformed,
    * the caller does not own the scan.

    We deliberately do NOT distinguish those cases in the return value --
    the endpoint translates every ``None`` into 404 so an attacker cannot
    probe for scan ids that belong to another user.
    """
    for scan_file in _iter_scan_files(settings):
        record = _load_scan_json(scan_file)
        if record is None:
            continue
        if record.get("id") != scan_id:
            continue
        if not _visible_to(user, record):
            return None
        findings = _load_findings_json(scan_file.parent)
        return record, findings
    return None


@router.get(
    "/scans/diff",
    summary="Compare two scans and return added / removed / changed findings",
)
async def diff_scans(
    user: CurrentUser,
    settings: Annotated[Settings, Depends(get_settings)],
    base: str = Query(description="Older / reference scan id."),
    head: str = Query(description="Newer / candidate scan id."),
) -> dict[str, Any]:
    """Diff two scans by scan id.

    Deltas are signed as ``head - base``: a *negative* overdue delta means
    the newer scan has fewer overdue findings, i.e. the migration has
    progressed. A *positive* delta means new quantum-vulnerable
    cryptography was introduced -- the shift-left regression signal.
    """
    if base == head:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Base and head scan ids must be different.",
        )

    base_loaded = _load_visible_scan(base, user, settings)
    if base_loaded is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No scan with id {base!r} was found on the local mirror.",
        )

    head_loaded = _load_visible_scan(head, user, settings)
    if head_loaded is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No scan with id {head!r} was found on the local mirror.",
        )

    base_scan, base_findings = base_loaded
    head_scan, head_findings = head_loaded

    result = compute_diff(base_scan, base_findings, head_scan, head_findings)
    return result.to_dict()
