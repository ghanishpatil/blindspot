"""HTTP API layer.

Routers are aggregated here under a single ``/api`` prefix so ``main.py`` has
one thing to include.
"""

from fastapi import APIRouter

from app.api import (
    agility,
    benchmark,
    cbom_interop,
    compliance,
    export,
    findings,
    graph,
    health,
    policy,
    report,
    roadmap,
    scan,
    scans,
    scans_diff,
    tls,
)

api_router = APIRouter(prefix="/api")
api_router.include_router(health.router)
api_router.include_router(scan.router)
# scans_diff MUST be included BEFORE scans -- the scans router carries a
# ``/scans/{scan_id}`` catch-all that would otherwise greedily match
# ``/scans/diff`` and 404 as "no scan with id 'diff'".
api_router.include_router(scans_diff.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(export.router)
api_router.include_router(roadmap.router)
api_router.include_router(compliance.router)
api_router.include_router(report.router)
api_router.include_router(tls.router)
api_router.include_router(policy.router)
api_router.include_router(benchmark.router)
api_router.include_router(agility.router)
api_router.include_router(cbom_interop.router)
api_router.include_router(graph.router)

__all__ = ["api_router"]
