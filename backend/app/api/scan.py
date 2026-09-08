"""Scan endpoint — runs the full pipeline.

``POST /scan`` executes:

    discovery → evidence → normalize → CBOM → classify → risk
    → recommend → persist → summarise

Everything runs synchronously in-process. The seeded repo scans in seconds.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from app.config import Settings, get_settings
from app.firebase.auth import CurrentUser
from app.firebase.storage import get_storage
from app.models.scan import ScanMode, ScanRequest, ScanResponse, ScanStatus
from app.pipeline import load_cached_result, run_pipeline, save_cache

logger = logging.getLogger(__name__)

router = APIRouter(tags=["scan"])

# In-memory store for demo. Findings and scans are kept here so GET endpoints
# can serve them without Firebase. Firebase persistence is additive — when
# configured, results are written there too.
_last_scan: dict | None = None
_last_findings: list | None = None
_last_cbom: str | None = None


def get_last_scan_data() -> tuple[dict | None, list | None, str | None]:
    """Access the in-memory scan store from other endpoints."""
    return _last_scan, _last_findings, _last_cbom


@router.post(
    "/scan",
    response_model=ScanResponse,
    summary="Start a cryptographic discovery scan",
)
async def start_scan(
    request: ScanRequest,
    user: CurrentUser,
    settings: Annotated[Settings, Depends(get_settings)],
) -> ScanResponse:
    """Run a scan and return the results.

    The owner is taken from the verified token, never from the request body.
    """
    global _last_scan, _last_findings, _last_cbom

    # Determine target.
    if request.repository_path:
        target = Path(request.repository_path).resolve()
    else:
        target = settings.demo_repo

    if not target.is_dir():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan target does not exist: {target}",
        )

    project_id = request.project_id or "demo"

    # Cached mode — load last successful result.
    if request.mode == ScanMode.CACHED:
        cached = load_cached_result(settings)
        if cached is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No cached scan result available. Run a live scan first.",
            )
        scan, findings, cbom_json = cached
        _last_scan = scan.serialise()
        _last_findings = [f.serialise() for f in findings]
        _last_cbom = cbom_json

        return ScanResponse(
            scan_id=scan.id,
            status=scan.status,
            mode=ScanMode.CACHED,
            repository=scan.repository,
            finding_count=scan.finding_count,
            summary=scan.summary,
            duration_seconds=scan.duration_seconds,
            cbom_available=True,
            message="Loaded from cached fallback.",
        )

    # Live scan.
    try:
        scan, findings, cbom_json = run_pipeline(
            target,
            project_id=project_id,
            owner_id=user.uid,
            settings=settings,
        )
    except Exception as exc:
        logger.exception("Scan failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed: {exc}",
        ) from exc

    # Store in memory for GET endpoints.
    _last_scan = scan.serialise()
    _last_findings = [f.serialise() for f in findings]
    _last_cbom = cbom_json

    # Save as fallback cache.
    try:
        save_cache(scan, findings, cbom_json, settings)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to save cache: %s", exc)

    # Save CBOM to local artifacts.
    try:
        storage = get_storage(settings)
        storage.write_local(project_id, scan.id, "cbom.json", cbom_json)
        storage.write_local(
            project_id,
            scan.id,
            "findings.json",
            json.dumps(_last_findings, indent=2, ensure_ascii=False),
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to write local artifacts: %s", exc)

    # Firebase Storage upload (best-effort).
    try:
        storage = get_storage(settings)
        if storage.available:
            storage.upload_text(project_id, scan.id, "cbom.json", cbom_json)
            storage.upload_text(
                project_id,
                scan.id,
                "findings.json",
                json.dumps(_last_findings, indent=2, ensure_ascii=False),
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Firebase Storage upload skipped: %s", exc)

    # Firestore persistence (best-effort).
    try:
        from app.firebase.firestore import get_firestore
        fs = get_firestore(settings)
        if fs.available:
            fs.set_document("scans", scan.id, scan.to_firestore_document())
            batch = {f.id: f.to_firestore_document() for f in findings}
            fs.write_batch("findings", batch)
            logger.info("Persisted scan and %d findings to Firestore.", len(findings))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Firestore persistence skipped: %s", exc)

    return ScanResponse(
        scan_id=scan.id,
        status=scan.status,
        mode=scan.mode,
        repository=str(target),
        finding_count=len(findings),
        summary=scan.summary,
        duration_seconds=scan.duration_seconds,
        cbom_available=True,
        message=f"Scan complete: {len(findings)} findings in {scan.duration_seconds:.1f}s.",
    )
