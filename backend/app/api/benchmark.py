"""REST surface for the benchmark harness.

Two endpoints:

* ``POST /api/benchmark/run``    -- run the bundled dataset through
                                    the pipeline, cache the report to
                                    ``settings.artifacts / benchmark-latest.json``,
                                    and return it. Rate-limited on the
                                    server side (single in-flight run
                                    at a time) because the pipeline is
                                    expensive.
* ``GET  /api/benchmark/latest`` -- return the last cached report, or
                                    404 when nothing has run yet.

We intentionally do NOT persist to Firebase. The report is a
throwaway metric artefact: a fresh run is authoritative, and stale
data on Firebase would confuse operators. The local mirror gives us
"last known score" without cross-machine drift.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from threading import Lock
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status

from app.benchmark import (
    BenchmarkReport,
    load_bundled_dataset,
    run_benchmark,
)
from app.benchmark.dataset import BenchmarkError
from app.config import Settings, get_settings
from app.firebase.auth import CurrentUser

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/benchmark", tags=["benchmark"])


LATEST_FILENAME = "benchmark-latest.json"

# Serialise concurrent runs so two POSTs don't spawn duplicate scans.
_run_lock = Lock()


def _latest_path(settings: Settings) -> Path:
    return settings.artifacts / LATEST_FILENAME


def _persist_latest(report: BenchmarkReport, settings: Settings) -> None:
    """Cache the report to disk. Same directory the pipeline uses for
    other artefact mirrors -- consistent operational surface."""
    path = _latest_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"
    path.write_text(payload, encoding="utf-8")


def _load_latest(settings: Settings) -> dict[str, Any] | None:
    """Return the last cached report dict, or None when unavailable."""
    path = _latest_path(settings)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("cached benchmark report is unreadable: %s", exc)
        return None


@router.post("/run", summary="Run the bundled benchmark and cache the result")
async def post_run(
    _user: CurrentUser,
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Run the harness end-to-end.

    Concurrency: only one benchmark can run at a time. A second POST
    while one is running returns 409 Conflict; the caller should
    ``GET /latest`` to see the current score or retry after a moment.
    """
    acquired = _run_lock.acquire(blocking=False)
    if not acquired:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A benchmark run is already in progress.",
        )
    try:
        try:
            dataset = load_bundled_dataset()
        except BenchmarkError as exc:
            # Manifest is corrupt or missing files. Operator needs to fix
            # the bundled data -- not something the caller can retry.
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"benchmark dataset is invalid: {exc}",
            ) from exc

        try:
            report = run_benchmark(dataset, settings=settings)
        except BenchmarkError as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(exc),
            ) from exc
        except Exception as exc:  # noqa: BLE001 -- surface pipeline crashes
            logger.exception("benchmark run failed")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"benchmark run failed: {exc}",
            ) from exc

        _persist_latest(report, settings)
        return report.to_dict()
    finally:
        _run_lock.release()


@router.get(
    "/latest",
    summary="Return the last cached benchmark report",
)
async def get_latest(
    _user: CurrentUser,
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    cached = _load_latest(settings)
    if cached is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "No benchmark run has completed yet. "
                "POST /api/benchmark/run to produce a report."
            ),
        )
    return cached


__all__ = ["router"]
