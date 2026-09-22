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

    # Which subsystems are REQUIRED for the tool to be considered "ready".
    #
    # Firebase is optional whenever the operator has pinned local storage
    # (`STORAGE_BACKEND=local` / air-gap mode). Reporting the readiness
    # state as "degraded" for a subsystem the operator explicitly opted
    # out of would be dishonest: the tool is behaving exactly as
    # configured. The subsystem itself is still surfaced under
    # `subsystems.firebase` so an operator can see its state, but it
    # does not contribute to `readiness`.
    firebase_required = settings.effective_storage_backend != "local"

    degraded: list[str] = []
    for name, detail in subsystems.items():
        if detail.get("available"):
            continue
        if name == "firebase" and not firebase_required:
            continue
        degraded.append(name)

    return {
        "status": "ok",
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.blindspot_env,
        "phase": "1 - foundation",
        "readiness": "ready" if not degraded else "degraded",
        "degradedSubsystems": degraded,
        "subsystems": subsystems,
        "storage": {
            # requested = what the operator asked for ("auto" / "local" /
            # "firebase"). effective = what the system actually uses right
            # now. In air-gap mode both are "local" and this is the field
            # to point at when someone asks "prove nothing leaves the box".
            "requested": settings.storage_backend,
            "effective": settings.effective_storage_backend,
            "artifactsDir": str(settings.artifacts),
            "fallbackCachePath": str(settings.fallback_cache),
        },
        "mosca": {
            "activeZ": settings.quantum_horizon_years,
            "activeZSource": settings.quantum_horizon_source,
            "defaultY": settings.migration_time_years,
            "zPresets": settings.z_presets,
        },
    }
