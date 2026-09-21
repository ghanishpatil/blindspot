"""Executive-report generation (R6).

Turns a completed scan into a self-contained HTML report a non-engineer can
read, and optionally a PDF rendering of the same document via headless Chrome.

The report only *presents* data the pipeline already produced. It never
recomputes risk, latency, or cost. That discipline keeps the report
consistent with everything else the platform emits.
"""

from app.report.executive import (
    ReportGenerationError,
    build_asset_csv,
    build_executive_html,
    build_executive_pdf,
)

__all__ = [
    "ReportGenerationError",
    "build_asset_csv",
    "build_executive_html",
    "build_executive_pdf",
]
