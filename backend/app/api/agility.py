"""Crypto-agility score endpoint.

``GET /api/agility/{scanId}`` -- returns the 0-100 score, the letter
grade, the additive breakdown, and the inputs the score came from.

We deliberately do NOT expose a "run for arbitrary summary" endpoint.
The score's honesty guardrail is that it always references a real,
persisted scan the user can inspect. Accepting free-form summaries
would let a caller invent inputs, which is exactly the failure mode
we want to prevent.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status

from app.agility import compute_agility_score
from app.api.scans import (
    _iter_scan_files,
    _load_scan_json,
    _visible_to,
)
from app.config import Settings, get_settings
from app.firebase.auth import CurrentUser

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/agility", tags=["agility"])


@router.get(
    "/{scan_id}",
    summary="Crypto-agility score (0-100) for one scan",
)
async def get_agility_score(
    scan_id: str,
    user: CurrentUser,
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Compute the agility score off the persisted scan record.

    Owner-scoping mirrors :func:`app.api.scans.get_scan`. A 404 is
    returned for both "no such scan" and "not visible to this user",
    so an attacker cannot probe for foreign scan ids.
    """
    for scan_file in _iter_scan_files(settings):
        record = _load_scan_json(scan_file)
        if record is None:
            continue
        if record.get("id") != scan_id:
            continue
        if not _visible_to(user, record):
            break

        summary = record.get("summary") or {}
        score = compute_agility_score(summary)
        return {
            "scanId": scan_id,
            "projectId": record.get("projectId"),
            "generatedAt": record.get("completedAt") or record.get("startedAt"),
            **score.to_dict(),
        }

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"No scan with id {scan_id!r} was found on the local mirror.",
    )


__all__ = ["router"]
