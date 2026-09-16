"""Live TLS / certificate scan endpoint.

``POST /api/tls-scan`` connects to a hostname, reads the negotiated protocol
and the server certificate, and runs the certificate's public-key algorithm
through the same classify → risk → recommend analysis as a code finding.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import Field

from app.config import Settings, get_settings
from app.firebase.auth import CurrentUser
from app.models.base import BlindspotModel
from app.scanner.tls import TlsConnectionError, TlsScanError, scan_tls

logger = logging.getLogger(__name__)

router = APIRouter(tags=["tls"])


class TlsScanRequest(BlindspotModel):
    """Request body for ``POST /api/tls-scan``."""

    host: str = Field(description="Bare hostname to probe, e.g. 'example.com'.")
    port: int = Field(default=443, ge=1, le=65535)


@router.post("/tls-scan", summary="Probe a live TLS endpoint's certificate and protocol")
async def tls_scan(
    request: TlsScanRequest,
    user: CurrentUser,
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict:
    """Return observed TLS metadata plus enriched findings for the cert key."""
    from app.pipeline import _enrich_finding

    try:
        observed, findings = await asyncio.to_thread(
            scan_tls, request.host, request.port, settings
        )
    except TlsConnectionError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"TLS connection failed: {exc}",
        ) from exc
    except TlsScanError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"TLS scan error: {exc}",
        ) from exc

    enriched: list[dict] = []
    scan_id = f"tls-{observed.get('host', 'host')}"
    for nf in findings:
        try:
            finding = _enrich_finding(nf, scan_id=scan_id, project_id="tls", settings=settings)
            enriched.append(finding.serialise())
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to enrich TLS finding: %s", exc)

    observed["findings"] = enriched
    return observed
