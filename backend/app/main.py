"""FastAPI application entry point.

Run locally with::

    uvicorn app.main:app --reload --port 8000

The application is a single process with clear internal module boundaries
(scanner, evidence, cbom, classifier, risk, recommend, firebase). That is a
deliberate demo-scope decision: modular code, no distributed infrastructure.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import api_router
from app.config import get_settings
from app.firebase.client import get_firebase

logger = logging.getLogger(__name__)


def configure_logging(level: str = "INFO") -> None:
    """Set up basic structured-ish logging for local development."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Prepare local directories and probe Firebase on startup.

    Firebase is probed rather than required. A missing or invalid service
    account leaves the API running with authentication reporting itself as
    unavailable, which is far easier to diagnose than a process that will not
    boot.
    """
    settings = get_settings()
    configure_logging()
    settings.ensure_directories()

    logger.info(
        "Starting %s v%s (env=%s)",
        settings.app_name,
        settings.app_version,
        settings.blindspot_env,
    )

    firebase = get_firebase(settings)
    if firebase.available:
        logger.info("Firebase ready for project %s.", firebase.project_id)
    else:
        logger.warning("Firebase unavailable: %s", firebase.reason)

    if settings.auth_bypass_allowed():
        logger.warning(
            "AUTH_DISABLED is active. Requests run as the demo principal. "
            "Do not use this outside local development."
        )
    elif settings.auth_disabled and settings.is_production:
        logger.error(
            "AUTH_DISABLED was requested but refused because BLINDSPOT_ENV=production."
        )

    yield

    logger.info("Shutting down %s.", settings.app_name)


def create_app() -> FastAPI:
    """Application factory."""
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        summary="Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)",
        description=(
            "Blindspot discovers cryptographic artefacts in source code and "
            "dependencies, records the evidence behind every detection, builds a "
            "CycloneDX CBOM, and connects discovery to quantum migration urgency "
            "via Mosca's inequality — ending in an actionable PQC or hybrid "
            "recommendation.\n\n"
            "Current build phase: **1 — foundation**. Pipeline endpoints respond "
            "with HTTP 501 until their implementing phase lands."
        ),
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

    app.include_router(api_router)

    @app.get("/", tags=["meta"], summary="Service identity")
    async def root() -> dict[str, str]:
        return {
            "service": settings.app_name,
            "version": settings.app_version,
            "phase": "1 - foundation",
            "docs": "/docs",
            "health": "/api/health",
        }

    return app


app = create_app()
