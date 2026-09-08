"""Health and readiness endpoint.

Reports subsystem readiness rather than a bare "ok", so a missing scanner,
absent demo repository, or unconfigured Firebase project is visible *before* a
demo rather than during one.

``status`` is ``ok`` when the process is serving requests. Individual
subsystems report their own readiness, and ``degraded`` signals that the
service is up but part of the pipeline would not work.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends

from app.config import Settings, get_settings
from app.firebase.client import firebase_status
from app.scanner.semgrep import resolve_semgrep

router = APIRouter(tags=["health"])


@router.get("/health", summary="Liveness and subsystem readiness")
async def health(
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Return process health plus per-subsystem readiness detail."""
    firebase = firebase_status(settings)
    semgrep_executable = resolve_semgrep(settings)
    demo_repo = settings.demo_repo
    fallback_cache = settings.fallback_cache

    subsystems = {
        "firebase": firebase,
        "semgrep": {
            "available": semgrep_executable is not None,
            "configured": settings.semgrep_path,
            "resolvedPath": str(semgrep_executable) if semgrep_executable else None,
            "reason": None
            if semgrep_executable
            else (
                f"Could not locate '{settings.semgrep_path}'. Install backend "
                "requirements or set SEMGREP_PATH."
            ),
        },
        "demoRepository": {
            "available": demo_repo.is_dir(),
            "path": str(demo_repo),
            "reason": None if demo_repo.is_dir() else "Seeded repository not created yet (Phase 3).",
        },
        "fallbackCache": {
            "available": fallback_cache.is_file(),
            "path": str(fallback_cache),
            "reason": None if fallback_cache.is_file() else "No cached scan stored yet.",
        },
    }

    degraded = [
        name for name, detail in subsystems.items() if not detail.get("available")
    ]

    return {
        "status": "ok",
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.blindspot_env,
        "phase": "1 - foundation",
        "readiness": "ready" if not degraded else "degraded",
        "degradedSubsystems": degraded,
        "subsystems": subsystems,
        "mosca": {
            "activeZ": settings.quantum_horizon_years,
            "activeZSource": settings.quantum_horizon_source,
            "defaultY": settings.migration_time_years,
            "zPresets": settings.z_presets,
        },
    }
