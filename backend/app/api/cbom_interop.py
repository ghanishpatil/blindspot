"""CBOM interop-diff endpoint.

``POST /api/cbom/diff`` accepts two CycloneDX 1.6 CBOM documents in a
JSON body and returns their crypto-asset-level diff. Intended use:
demonstrate interoperability with third-party CBOM producers (IBM
CBOMkit, sonatype, ...). No scan is triggered; the endpoint is a pure
comparator over caller-supplied inputs.

Body shape::

    {
      "base": <CycloneDX BOM object>,
      "head": <CycloneDX BOM object>
    }

Response shape follows :class:`app.cbom.interop_diff.InteropDiffResult`.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.cbom.interop_diff import _extract_meta, compute_interop_diff
from app.firebase.auth import CurrentUser

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cbom", tags=["cbom"])


class CbomInteropDiffRequest(BaseModel):
    """Request body for POST /api/cbom/diff."""

    base: dict[str, Any] = Field(
        description=(
            "CycloneDX 1.6 CBOM to use as the reference / older side. "
            "Any tool's output that follows the spec works."
        ),
    )
    head: dict[str, Any] = Field(
        description="CycloneDX 1.6 CBOM to use as the candidate / newer side.",
    )


@router.post("/diff", summary="Diff two CycloneDX CBOMs at the crypto-asset level")
async def diff_cboms(
    payload: CbomInteropDiffRequest,
    _user: CurrentUser,
) -> dict[str, Any]:
    """Compute added / removed / changed / unchanged across two CBOMs.

    Both bodies must resolve to CycloneDX 1.6 JSON objects. The
    endpoint is tolerant of partial documents (spec fields are
    optional) -- an interop diff on incomplete data is still the
    correct signal for the operator, not an error.
    """
    if not isinstance(payload.base, dict) or not payload.base:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="`base` must be a non-empty CycloneDX BOM object.",
        )
    if not isinstance(payload.head, dict) or not payload.head:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="`head` must be a non-empty CycloneDX BOM object.",
        )

    try:
        result = compute_interop_diff(payload.base, payload.head)
    except Exception as exc:  # noqa: BLE001 -- surface pipeline crashes
        logger.exception("interop diff failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"CBOM interop diff failed: {exc}",
        ) from exc

    return result.to_dict(
        base_meta=_extract_meta(payload.base),
        head_meta=_extract_meta(payload.head),
    )


__all__ = ["router"]
