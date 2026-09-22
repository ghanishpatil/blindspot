"""Full-scan JSON envelope builder for ``blindspot-scan scan``.

Runs the existing pipeline on a target path and wraps the ``(scan,
findings, cbom_json)`` triple into a versioned JSON envelope that CI
systems parse from stdout. The envelope shape is
``blindspot.scan.v1`` -- pinned so downstream tooling can rely on it
staying stable, and bumped only via an explicit new schema version.

Every field on the envelope comes from an existing pipeline value.
Nothing here computes; this module is a shape adapter.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app import __version__ as _APP_VERSION
from app.cli.git_meta import git_head_meta
from app.config import Settings, get_settings
from app.pipeline import run_pipeline


# Schema version. Bump only when the envelope's shape (not its
# contents) changes in a way a machine consumer must know about.
SCAN_SCHEMA_VERSION = "blindspot.scan.v1"

# CLI version tracks the pipeline for now. Separate namespace kept so
# the CLI can move independently if the two ever diverge.
CLI_VERSION = _APP_VERSION


def build_scan_envelope(
    target: Path,
    *,
    project_id: str = "ci",
    settings: Settings | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Run a scan against *target* and return the full envelope dict.

    The envelope matches the ``blindspot.scan.v1`` contract:

    ``schemaVersion`` -- the version string above.
    ``generatedAt``   -- UTC ISO-8601 timestamp of envelope construction.
    ``cli``           -- ``{"version": ...}``.
    ``pipeline``      -- ``{"version": ...}``. Bumps every time
                        ``app.__version__`` bumps.
    ``target``        -- ``{"path": abs_path, "gitRef": ..., "gitBranch": ...}``.
    ``summary``       -- verbatim :attr:`Scan.summary` serialised.
    ``findings``      -- list of :func:`Finding.to_firestore_document`
                        dicts. Camel-case, matches the on-disk
                        ``findings.json`` shape used by the rest of the
                        product.
    """
    settings = settings or get_settings()
    generated_at = (now or datetime.now(timezone.utc)).isoformat()

    target = Path(target).expanduser().resolve()
    scan, findings, _cbom_json = run_pipeline(
        target, project_id=project_id, settings=settings
    )

    git_meta = git_head_meta(target)

    return {
        "schemaVersion": SCAN_SCHEMA_VERSION,
        "generatedAt": generated_at,
        "cli": {"version": CLI_VERSION},
        "pipeline": {"version": _APP_VERSION},
        "target": {
            "path": str(target),
            "gitRef": git_meta["gitRef"],
            "gitBranch": git_meta["gitBranch"],
        },
        "summary": scan.summary.model_dump(by_alias=True) if scan.summary else {},
        "findings": [f.to_firestore_document() for f in findings],
    }


def dump_envelope(envelope: dict[str, Any]) -> str:
    """Serialise the envelope with a single trailing newline.

    Trailing newline matters for CI logs and for tools like ``jq`` --
    it's a small politeness that keeps stdout well-formed.
    """
    return json.dumps(envelope, indent=2, ensure_ascii=False) + "\n"
