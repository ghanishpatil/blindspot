"""Helper for Phase 1 endpoint placeholders.

Every unimplemented endpoint responds with HTTP 501 and names the phase that
will implement it. This is deliberate: returning invented findings or an empty
success would be indistinguishable from a working pipeline, and the
specification is explicit that fabricated data must not stand in for the real
one.

A 501 cannot be mistaken for a result.
"""

from __future__ import annotations

from fastapi import HTTPException, status

from app.models.base import BlindspotModel


class NotImplementedDetail(BlindspotModel):
    """Structured body describing an endpoint that is not yet built."""

    error: str = "not_implemented"
    endpoint: str
    phase: str
    message: str
    implemented: bool = False


def not_implemented(endpoint: str, phase: str, message: str) -> HTTPException:
    """Build the 501 raised by placeholder endpoints."""
    detail = NotImplementedDetail(endpoint=endpoint, phase=phase, message=message)
    return HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=detail.serialise(),
    )
