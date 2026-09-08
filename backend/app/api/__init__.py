"""HTTP API layer.

Routers are aggregated here under a single ``/api`` prefix so ``main.py`` has
one thing to include.
"""

from fastapi import APIRouter

from app.api import export, findings, health, scan

api_router = APIRouter(prefix="/api")
api_router.include_router(health.router)
api_router.include_router(scan.router)
api_router.include_router(findings.router)
api_router.include_router(export.router)

__all__ = ["api_router"]
