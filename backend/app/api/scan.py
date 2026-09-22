"""Scan endpoint — runs the full pipeline.

``POST /scan`` executes:

    discovery → evidence → normalize → CBOM → classify → risk
    → recommend → persist → summarise

The pipeline itself is synchronous; the endpoint runs it in a worker thread so
a long scan does not block the event loop, and guards against overlapping scans
with a single-flight lock (an abuse / resource-exhaustion mitigation).
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from app.config import Settings, get_settings
from app.firebase.auth import AuthenticatedUser, CurrentUser
from app.firebase.storage import get_storage
from app.models.scan import ScanMode, ScanRequest, ScanResponse
from app.pipeline import load_cached_result, run_pipeline, save_cache
from app.scanner.container import ContainerError, prepare_image
from app.scanner.repository import RepositoryError, clone_repository, remove_clone

logger = logging.getLogger(__name__)

router = APIRouter(tags=["scan"])

# In-memory store for demo. Findings and scans are kept here so GET endpoints
# can serve them without Firebase. Firebase persistence is additive — when
# configured, results are written there too.
_last_scan: dict | None = None
_last_findings: list | None = None
_last_cbom: str | None = None

# Single-flight guard: only one scan runs at a time per process. A second
# concurrent request gets 429 rather than piling expensive scans on top of
# each other. Also prevents the in-memory store from being corrupted by two
# scans writing the globals at once.
_scan_lock = asyncio.Lock()


def get_last_scan_data() -> tuple[dict | None, list | None, str | None]:
    """Access the in-memory scan store (unscoped) — internal use only."""
    return _last_scan, _last_findings, _last_cbom


def rehydrate_from_cache(settings: Settings | None = None) -> bool:
    """Repopulate the in-memory scan store from the on-disk fallback cache.

    Called by the application lifespan hook so a backend restart -- the
    common case in air-gapped / on-prem operation -- does not silently
    lose the last successful scan. Returns True when a cache was found
    and loaded, False when there was nothing to rehydrate.

    Failure is logged and swallowed: a corrupt cache must not prevent the
    API from starting. The next successful scan replaces the cache
    anyway, so there is no data loss.
    """
    global _last_scan, _last_findings, _last_cbom

    settings = settings or get_settings()
    try:
        cached = load_cached_result(settings)
    except Exception as exc:  # noqa: BLE001 -- honest degrade on startup
        logger.warning("Failed to load fallback cache on startup: %s", exc)
        return False

    if cached is None:
        return False

    scan, findings, cbom_json = cached
    _last_scan = scan.serialise()
    _last_findings = [f.serialise() for f in findings]
    _last_cbom = cbom_json
    logger.info(
        "Rehydrated last scan from cache: id=%s findings=%d",
        scan.id, len(findings),
    )
    return True


def get_last_scan_for(
    user: AuthenticatedUser,
) -> tuple[dict | None, list | None, str | None]:
    """Return the last scan only when the caller owns it.

    The in-memory store holds a single most-recent scan. Reads are scoped to
    the owner recorded on that scan so one authenticated user cannot read
    another's results. The demo principal (local ``AUTH_DISABLED`` mode) is a
    single-tenant context and always sees the last scan.

    A per-user, multi-scan store is the Firestore-primary migration (Phase 0);
    this is the correct isolation boundary for the in-memory interim.
    """
    if _last_scan is None:
        return (None, None, None)
    owner = _last_scan.get("ownerId")
    if getattr(user, "is_demo_principal", False) or owner == getattr(user, "uid", None):
        return (_last_scan, _last_findings, _last_cbom)
    return (None, None, None)


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

    # Single-flight: refuse overlapping scans rather than stacking expensive work.
    if _scan_lock.locked():
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="A scan is already in progress. Please retry shortly.",
        )

    is_development = settings.blindspot_env.strip().lower() == "development"

    async with _scan_lock:
        # Determine target, in precedence order for LIVE scans:
        #   repository URL → container image ref → image archive → local path → demo.
        # Temp directories/files created here are tracked for cleanup in `finally`.
        clone_dir: Path | None = None
        image_root: Path | None = None
        image_tar: Path | None = None

        if request.repository_url and request.mode == ScanMode.LIVE:
            try:
                clone_dir = await asyncio.to_thread(
                    clone_repository, request.repository_url, settings
                )
            except RepositoryError as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Repository error: {exc}",
                ) from exc
            target = clone_dir
        elif request.image_ref and request.mode == ScanMode.LIVE:
            try:
                image_root, image_tar = await asyncio.to_thread(
                    prepare_image, image_ref=request.image_ref, settings=settings
                )
            except ContainerError as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Container image error: {exc}",
                ) from exc
            target = image_root
        elif request.image_archive_path and request.mode == ScanMode.LIVE:
            # Local archive path is a filesystem-read surface — development only.
            if not is_development:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Local image-archive scanning is disabled here. Provide an imageRef.",
                )
            try:
                image_root, image_tar = await asyncio.to_thread(
                    prepare_image, archive_path=request.image_archive_path, settings=settings
                )
            except ContainerError as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Container image error: {exc}",
                ) from exc
            target = image_root
        elif request.repository_path:
            if not is_development:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Local path scanning is disabled here. Provide a repositoryUrl instead.",
                )
            target = Path(request.repository_path).resolve()
        else:
            target = settings.demo_repo

        def _cleanup_temp() -> None:
            if clone_dir is not None:
                remove_clone(clone_dir)
            if image_root is not None:
                remove_clone(image_root)
            if image_tar is not None and image_tar.exists():
                try:
                    image_tar.unlink()
                except OSError:
                    logger.warning("Could not remove temp image tar %s", image_tar)

        if not target.is_dir():
            _cleanup_temp()
            # Do not echo the resolved absolute path back to the client.
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Scan target is not accessible.",
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

        # Live scan — run the blocking pipeline off the event loop.
        try:
            scan, findings, cbom_json = await asyncio.to_thread(
                run_pipeline,
                target,
                project_id=project_id,
                owner_id=user.uid,
                settings=settings,
                tls_targets=request.tls_targets,
            )
        except Exception as exc:
            # Log the detail server-side; return a generic message to the client.
            logger.exception("Scan failed: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Scan failed due to an internal error.",
            ) from exc
        finally:
            # Remove any cloned repo / extracted image as soon as scanning is
            # done — evidence snippets are already captured inside the findings.
            _cleanup_temp()

        # Store in memory for GET endpoints.
        _last_scan = scan.serialise()
        _last_findings = [f.serialise() for f in findings]
        _last_cbom = cbom_json

        # Save as fallback cache.
        try:
            save_cache(scan, findings, cbom_json, settings)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to save cache: %s", exc)

        # Save CBOM, findings, and the scan record to local artifacts.
        # scan.json is what the cross-scan aggregation endpoints
        # (/api/scans, /api/scans/{id}, /api/scans/trend) walk to
        # produce a portfolio view -- without it there is no way for
        # the trend view to know a scan ever existed after a restart.
        try:
            storage = get_storage(settings)
            storage.write_local(project_id, scan.id, "cbom.json", cbom_json)
            storage.write_local(
                project_id,
                scan.id,
                "findings.json",
                json.dumps(_last_findings, indent=2, ensure_ascii=False),
            )
            storage.write_local(
                project_id,
                scan.id,
                "scan.json",
                json.dumps(_last_scan, indent=2, ensure_ascii=False),
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to write local artifacts: %s", exc)

        # Storage-backend selection. In 'local' mode we skip every
        # Firebase side effect -- no Storage upload, no Firestore write,
        # no warning noise. The local mirror + fallback cache above are
        # unconditional so an air-gapped operator still gets a full,
        # queryable inventory on disk.
        effective_backend = settings.effective_storage_backend

        if effective_backend != "local":
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
        else:
            logger.info(
                "STORAGE_BACKEND=local: skipping Firebase Storage upload and "
                "Firestore persistence. Scan mirrored to %s and cache %s.",
                settings.artifacts,
                settings.fallback_cache,
            )

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
