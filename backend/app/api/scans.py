"""Cross-scan aggregation endpoints.

Every scan writes ``scan.json`` + ``findings.json`` + ``cbom.json`` under
``settings.artifacts / {project_id} / {scan_id} /``. This module exposes
that mirror through three read endpoints so the demo can show a portfolio
view (all scans across a project) and a trend view (per-Risk_Tier counts
over time) without needing Firestore, a database, or a network round-trip.

Endpoints:

* ``GET /api/scans`` -- list every scan on disk, newest first.
* ``GET /api/scans/{scan_id}`` -- full record for one scan (scan, findings,
  cbom).
* ``GET /api/scans/trend?project_id=X`` -- time-ordered per-tier point set
  suitable for a line chart. Closes PS Req 13 (Trend-Over-Time Views).

Owner scoping mirrors ``get_last_scan_for`` in ``api/scan.py``: a caller
sees only scans whose ``ownerId`` matches their uid, or every scan when the
caller is the demo principal (single-tenant AUTH_DISABLED context).

Rules that keep this honest:

1. **Read-only.** These endpoints never mutate anything on disk. A missing
   artefact directory produces an empty list; a corrupt file produces a
   404 for the specific scan and does not sink the listing.
2. **No fabrication.** Values come straight out of the on-disk JSON. If a
   scan file is missing a field, we surface ``None`` -- we do not invent.
3. **No Firebase.** These endpoints work identically in local mode and in
   Firebase mode because they never look at either. The demo dashboard's
   'previous scans' panel therefore functions in air-gapped deployments.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.config import Settings, get_settings
from app.firebase.auth import AuthenticatedUser, CurrentUser

logger = logging.getLogger(__name__)

router = APIRouter(tags=["scans"])


# ---------------------------------------------------------------------------
# On-disk layout helpers
# ---------------------------------------------------------------------------

_SCAN_FILE = "scan.json"
_FINDINGS_FILE = "findings.json"
_CBOM_FILE = "cbom.json"


def _artifacts_root(settings: Settings) -> Path:
    """Return the artefacts root directory, or raise 404 when it does not
    exist. A missing directory is a valid state -- it means no scan has
    ever run -- so we translate that into an empty response upstream, not
    an error."""
    return settings.artifacts


def _iter_scan_files(settings: Settings) -> list[Path]:
    """Yield every ``{project}/{scan}/scan.json`` under the artefacts root.

    Sort order is unspecified here; callers order by ``started_at`` from
    the parsed JSON so the response is deterministic even if the filesystem
    is not.
    """
    root = _artifacts_root(settings)
    if not root.is_dir():
        return []
    # Two-level glob: artifacts/<project>/<scan-id>/scan.json.
    return sorted(root.glob("*/*/scan.json"))


def _load_scan_json(scan_file: Path) -> dict[str, Any] | None:
    """Load a single scan.json file. Returns None on any read/parse error
    so a corrupt file cannot sink the whole listing."""
    try:
        return json.loads(scan_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Ignoring unreadable scan.json at %s: %s", scan_file, exc)
        return None


def _load_findings_json(scan_dir: Path) -> list[dict[str, Any]]:
    """Load the findings.json next to a scan.json. Returns [] on error."""
    findings_file = scan_dir / _FINDINGS_FILE
    if not findings_file.is_file():
        return []
    try:
        data = json.loads(findings_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning(
            "Ignoring unreadable findings.json at %s: %s", findings_file, exc
        )
        return []
    return data if isinstance(data, list) else []


def _load_cbom_text(scan_dir: Path) -> str | None:
    """Load the cbom.json next to a scan.json as a raw JSON string.

    Returned as text so a caller who wants to hand it to a CycloneDX
    parser gets identical bytes to what was written. Not decoded to dict
    to avoid a re-serialisation round trip.
    """
    cbom_file = scan_dir / _CBOM_FILE
    if not cbom_file.is_file():
        return None
    try:
        return cbom_file.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("Ignoring unreadable cbom.json at %s: %s", cbom_file, exc)
        return None


def _visible_to(user: AuthenticatedUser, scan: dict[str, Any]) -> bool:
    """Owner-scoping predicate. Mirrors ``get_last_scan_for`` in scan.py.

    The demo principal (single-tenant local mode) sees every scan on
    disk. An authenticated Firebase user sees only their own scans -- the
    ``ownerId`` on the scan record must match their uid.
    """
    if getattr(user, "is_demo_principal", False):
        return True
    owner = scan.get("ownerId")
    return owner == getattr(user, "uid", None)


def _summary_row(scan: dict[str, Any]) -> dict[str, Any]:
    """Compact row for the /api/scans listing. Every value is copied
    verbatim from the scan record -- no re-derivation."""
    summary = scan.get("summary") or {}
    return {
        "scanId": scan.get("id"),
        "projectId": scan.get("projectId"),
        "ownerId": scan.get("ownerId"),
        "status": scan.get("status"),
        "mode": scan.get("mode"),
        "repository": scan.get("repository"),
        "startedAt": scan.get("startedAt"),
        "completedAt": scan.get("completedAt"),
        "findingCount": scan.get("findingCount", 0),
        "summary": {
            "totalFindings": summary.get("totalFindings", 0),
            "overdue": summary.get("overdue", 0),
            "transitional": summary.get("transitional", 0),
            "lowRisk": summary.get("lowRisk", 0),
            "hndlExposed": summary.get("hndlExposed", 0),
            "currentWeakCrypto": summary.get("currentWeakCrypto", 0),
        },
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "/scans",
    summary="List every scan on disk (newest first)",
)
async def list_scans(
    user: CurrentUser,
    settings: Annotated[Settings, Depends(get_settings)],
    project_id: str | None = Query(
        default=None,
        description="Optional filter: return only scans in this project.",
    ),
) -> dict[str, Any]:
    """Return a lightweight index of every scan the local mirror knows about.

    The response is intentionally small -- one JSON row per scan -- so the
    dashboard can render 'recent scans' or 'scan history' panels without
    also loading every finding. Callers wanting the full record for one
    scan should hit ``GET /api/scans/{scan_id}`` afterwards.
    """
    rows: list[dict[str, Any]] = []
    for scan_file in _iter_scan_files(settings):
        record = _load_scan_json(scan_file)
        if record is None:
            continue
        if not _visible_to(user, record):
            continue
        if project_id and record.get("projectId") != project_id:
            continue
        rows.append(_summary_row(record))

    # Deterministic newest-first ordering. String compare on ISO-8601 UTC
    # timestamps is a total order, so no timezone conversion needed.
    rows.sort(
        key=lambda r: r.get("startedAt") or "",
        reverse=True,
    )

    return {
        "count": len(rows),
        "scans": rows,
    }


@router.get(
    "/scans/trend",
    summary="Time-series of per-Risk_Tier counts across a project",
)
async def scan_trend(
    user: CurrentUser,
    settings: Annotated[Settings, Depends(get_settings)],
    project_id: str = Query(
        description="Project whose scan history to plot.",
    ),
) -> dict[str, Any]:
    """Return a chronological series of tier-count snapshots for one project.

    Each point is one scan. Charts consume this directly as X = startedAt,
    Y = one of the tier counters. Closes PS Req 13 (Trend-Over-Time Views).

    Sorted oldest-first so a chart library plots time on the X axis in the
    natural direction.
    """
    points: list[dict[str, Any]] = []
    for scan_file in _iter_scan_files(settings):
        record = _load_scan_json(scan_file)
        if record is None:
            continue
        if not _visible_to(user, record):
            continue
        if record.get("projectId") != project_id:
            continue
        summary = record.get("summary") or {}
        points.append({
            "scanId": record.get("id"),
            "startedAt": record.get("startedAt"),
            "totalFindings": summary.get("totalFindings", 0),
            "overdue": summary.get("overdue", 0),
            "transitional": summary.get("transitional", 0),
            "lowRisk": summary.get("lowRisk", 0),
            "hndlExposed": summary.get("hndlExposed", 0),
            "currentWeakCrypto": summary.get("currentWeakCrypto", 0),
        })

    points.sort(key=lambda p: p.get("startedAt") or "")

    return {
        "projectId": project_id,
        "count": len(points),
        "points": points,
    }


@router.get(
    "/scans/{scan_id}",
    summary="Full record for one scan (scan + findings + cbom)",
)
async def get_scan(
    scan_id: str,
    user: CurrentUser,
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Return one scan's scan record, its findings list, and its CBOM text.

    404 when no scan with that id exists on disk OR the caller does not
    own it. We do NOT distinguish between the two -- an authenticated user
    should not be able to probe for scan ids belonging to another user.
    """
    for scan_file in _iter_scan_files(settings):
        record = _load_scan_json(scan_file)
        if record is None:
            continue
        if record.get("id") != scan_id:
            continue
        if not _visible_to(user, record):
            # Deliberate 404 (not 403): do not leak existence to non-owners.
            break

        scan_dir = scan_file.parent
        findings = _load_findings_json(scan_dir)
        cbom = _load_cbom_text(scan_dir)
        return {
            "scan": record,
            "findings": findings,
            "cbom": cbom,
        }

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"No scan with id {scan_id!r} was found on the local mirror.",
    )
