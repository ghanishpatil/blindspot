"""Executive-report endpoint (R6).

``GET /api/report?format=html|pdf&scanId=...`` returns the branded, self-
contained executive report for the caller's most recent scan.

The endpoint reads only from the same in-memory store the other read
endpoints use (``/roadmap``, ``/compliance``, ``/export/cbom``). It never
re-scans, never re-derives risk, and never fabricates data -- it presents
what the pipeline already produced.

Two behaviours are worth calling out:

* **Owner scoping.** ``get_last_scan_for(user)`` enforces the same owner
  boundary every other read endpoint enforces. A caller without a scan on
  file gets 404, never someone else's scan.
* **PDF is optional.** When ``format=pdf`` is requested but no Chrome /
  Chromium / Edge is on PATH, the endpoint returns 503 with an honest
  message. The HTML variant is always available.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import HTMLResponse, Response

from app.compliance.evaluator import evaluate_compliance
from app.config import get_settings
from app.firebase.auth import CurrentUser
from app.models.finding import Finding
from app.models.scan import Scan
from app.report.executive import (
    ReportGenerationError,
    build_asset_csv,
    build_executive_html,
    build_executive_pdf,
    cbom_from_json_string,
)
from app.roadmap.planner import build_roadmap

logger = logging.getLogger(__name__)

router = APIRouter(tags=["report"])


@router.get(
    "/report",
    summary="Executive HTML or PDF report for the most recent scan",
    responses={
        200: {"description": "Executive report."},
        404: {"description": "No scan on file for this user."},
        503: {"description": "PDF rendering requested but no headless browser available."},
    },
)
async def get_report(
    user: CurrentUser,
    format: str = Query(default="html", pattern="^(html|pdf|csv)$"),
    scan_id: str | None = Query(default=None, alias="scanId"),
) -> Response:
    """Return the executive report for the caller's most recent scan.

    The ``scanId`` parameter is honoured only when it matches the last
    scan on file. This preserves the current in-memory contract while
    leaving the door open for multi-scan storage without changing the API.
    """
    from app.api.scan import get_last_scan_for

    scan_dict, findings_data, cbom_json = get_last_scan_for(user)
    if scan_dict is None or findings_data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No scan results available. Run a scan first.",
        )

    if scan_id is not None and scan_id != scan_dict.get("id"):
        # Explicit ID mismatch -- prefer refusing over silently returning the
        # wrong scan.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Scan {scan_id!r} not available. The most recent scan for "
                f"this user is {scan_dict.get('id')!r}."
            ),
        )

    settings = get_settings()
    scan = Scan.model_validate(scan_dict)
    findings = [Finding.model_validate(item) for item in findings_data]

    # CSV is a straight inventory dump -- no roadmap / compliance / CBOM
    # side channels needed. Serve it and return before spending cycles on
    # the richer builders.
    if format == "csv":
        csv_body = build_asset_csv(scan=scan, findings=findings)
        return Response(
            content=csv_body,
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="blindspot-assets-{scan.id or "scan"}.csv"'
                ),
            },
        )

    # Both auxiliary evaluations reuse the exact same code paths the /roadmap
    # and /compliance endpoints use. That is the honest way to keep the
    # report's numbers consistent with the interactive dashboard.
    try:
        roadmap = build_roadmap(findings, scan_id=scan.id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Report: roadmap unavailable (%s); rendering without it.", exc)
        roadmap = None

    try:
        compliance = evaluate_compliance(findings, scan_id=scan.id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Report: compliance unavailable (%s); rendering without it.", exc)
        compliance = None

    cbom = cbom_from_json_string(cbom_json)

    html = build_executive_html(
        scan=scan,
        findings=findings,
        roadmap=roadmap,
        compliance=compliance,
        cbom=cbom,
        app_version=settings.app_version,
    )

    if format == "html":
        return HTMLResponse(
            content=html,
            headers={
                # Use `inline` so a link click opens the report in-browser
                # while still hinting a sensible filename for save-as.
                "Content-Disposition": (
                    f'inline; filename="blindspot-report-{scan.id or "scan"}.html"'
                ),
            },
        )

    # format == "pdf"
    try:
        pdf_bytes = build_executive_pdf(html=html)
    except ReportGenerationError as exc:
        # HTML always works; PDF is a nice-to-have. 503 (Service Unavailable)
        # is the honest response when the *server* cannot render the format
        # the client asked for.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="blindspot-report-{scan.id or "scan"}.pdf"'
            ),
        },
    )
