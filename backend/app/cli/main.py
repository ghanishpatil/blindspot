"""``blindspot-scan`` CLI entrypoint.

Three subcommands:

* ``scan <path>``                          -> full scan JSON on stdout
* ``diff <path> --baseline <file>``        -> delta JSON on stdout
* ``gate <path> --baseline <file>``        -> scan + diff + policy check
                                              -> exit 2 on policy violation

Exit code contract (CI reads these):

* 0 -- success
* 1 -- runtime error (unreadable path, malformed baseline, pipeline exception)
* 2 -- policy violation (``gate`` only)
* 3 -- bad arguments / usage

stdout is JSON only on the success path. stderr carries progress and
error messages (suppressed by ``--quiet``). This split is the whole
CI contract -- do NOT mix them.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from app import __version__ as _APP_VERSION
from app.cli.diff import compute_delta
from app.cli.policy import (
    PolicyError,
    evaluate_policy,
    has_block_violations,
    load_policy,
)
from app.cli.report import (
    CLI_VERSION,
    SCAN_SCHEMA_VERSION,
    build_scan_envelope,
    dump_envelope,
)


# Exit codes.
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_POLICY_VIOLATION = 2
EXIT_USAGE = 3


# ---------------------------------------------------------------------------
# Argparse plumbing
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    """Top-level parser with three subcommands.

    Argparse's exit-code for its own errors is 2, which collides with
    our "policy violation" code. We override by wiring
    ``exit_on_error=False`` and handling ``argparse.ArgumentError``
    ourselves -- see :func:`main`.
    """
    parser = argparse.ArgumentParser(
        prog="blindspot-scan",
        description=(
            "Blindspot ECDAT CI/CD guardrail. Runs the scan pipeline, "
            "diffs against a baseline, and blocks PRs that introduce "
            "new quantum-vulnerable or currently-weak cryptography."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"blindspot-scan {CLI_VERSION} (pipeline {_APP_VERSION})",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress progress on stderr. stdout is unchanged.",
    )

    sub = parser.add_subparsers(dest="command")
    sub.required = True

    # ---- scan ------------------------------------------------------------
    p_scan = sub.add_parser(
        "scan",
        help="Run the pipeline on a path and emit the scan JSON envelope.",
    )
    p_scan.add_argument("path", type=Path, help="Directory to scan.")
    p_scan.add_argument(
        "--project-id", default="ci",
        help="Project id for provenance. Default: ci.",
    )
    p_scan.add_argument(
        "--out", type=Path, default=None,
        help="Write JSON to this file instead of stdout.",
    )

    # ---- diff ------------------------------------------------------------
    p_diff = sub.add_parser(
        "diff",
        help="Scan a path and emit the delta vs a baseline scan envelope.",
    )
    p_diff.add_argument("path", type=Path, help="Directory to scan.")
    p_diff.add_argument(
        "--baseline", type=Path, required=True,
        help="Path to a prior 'blindspot-scan scan' JSON envelope.",
    )
    p_diff.add_argument(
        "--project-id", default="ci",
        help="Project id for provenance. Default: ci.",
    )
    p_diff.add_argument(
        "--out", type=Path, default=None,
        help="Write JSON to this file instead of stdout.",
    )

    # ---- gate ------------------------------------------------------------
    p_gate = sub.add_parser(
        "gate",
        help="Scan + diff + policy check. Exit 2 on policy violation.",
    )
    p_gate.add_argument("path", type=Path, help="Directory to scan.")
    p_gate.add_argument(
        "--baseline", type=Path, required=True,
        help="Path to a prior 'blindspot-scan scan' JSON envelope.",
    )
    p_gate.add_argument(
        "--policy", type=Path, default=None,
        help="Path to a policy JSON. Missing -> use the built-in default.",
    )
    p_gate.add_argument(
        "--project-id", default="ci",
        help="Project id for provenance. Default: ci.",
    )
    p_gate.add_argument(
        "--out", type=Path, default=None,
        help="Write delta+policy JSON to this file (in addition to stdout).",
    )

    return parser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _configure_logging(quiet: bool) -> None:
    """Send pipeline logs to stderr. Never touches stdout."""
    level = logging.WARNING if quiet else logging.INFO
    logging.basicConfig(
        stream=sys.stderr,
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
        force=True,
    )


def _echo_stderr(message: str, *, quiet: bool) -> None:
    if not quiet:
        print(message, file=sys.stderr)


def _load_baseline_envelope(path: Path, *, quiet: bool) -> dict:
    """Load a baseline scan envelope from disk.

    A missing file is treated as an empty baseline (all current
    findings are 'introduced'). Any other read/parse failure is a
    runtime error -- the CI operator needs to see it, not have it
    silently swallowed as 'no baseline'.
    """
    if not path.exists():
        _echo_stderr(
            f"baseline file {path} not found; treating as empty baseline.",
            quiet=quiet,
        )
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"baseline file {path} could not be read: {exc}") from exc


def _envelope_meta(envelope: dict) -> dict:
    """Compact provenance block attached to each side of the delta."""
    return {
        "gitRef": (envelope.get("target") or {}).get("gitRef"),
        "gitBranch": (envelope.get("target") or {}).get("gitBranch"),
        "generatedAt": envelope.get("generatedAt"),
    }


def _emit(payload: dict, out: Path | None) -> None:
    """Write JSON payload to stdout or a file. Newline-terminated."""
    text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    if out is None:
        sys.stdout.write(text)
        return
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def _handle_scan(args: argparse.Namespace) -> int:
    target = args.path
    if not target.exists() or not target.is_dir():
        _echo_stderr(f"scan target must be an existing directory: {target}", quiet=False)
        return EXIT_ERROR

    _echo_stderr(f"blindspot-scan v{CLI_VERSION} scanning {target}…", quiet=args.quiet)
    try:
        envelope = build_scan_envelope(target, project_id=args.project_id)
    except Exception as exc:  # noqa: BLE001 -- the CLI must surface, not crash
        _echo_stderr(f"scan failed: {exc}", quiet=False)
        return EXIT_ERROR

    _emit(envelope, args.out)
    _echo_stderr(
        f"scan complete: {len(envelope['findings'])} finding(s).",
        quiet=args.quiet,
    )
    return EXIT_OK


def _handle_diff(args: argparse.Namespace) -> int:
    target = args.path
    if not target.exists() or not target.is_dir():
        _echo_stderr(f"scan target must be an existing directory: {target}", quiet=False)
        return EXIT_ERROR

    try:
        baseline_env = _load_baseline_envelope(args.baseline, quiet=args.quiet)
    except RuntimeError as exc:
        _echo_stderr(str(exc), quiet=False)
        return EXIT_ERROR

    _echo_stderr(f"blindspot-scan diff scanning {target}…", quiet=args.quiet)
    try:
        current_env = build_scan_envelope(target, project_id=args.project_id)
    except Exception as exc:  # noqa: BLE001
        _echo_stderr(f"scan failed: {exc}", quiet=False)
        return EXIT_ERROR

    baseline_findings = baseline_env.get("findings") or []
    current_findings = current_env.get("findings") or []
    delta = compute_delta(baseline_findings, current_findings)

    generated_at = datetime.now(timezone.utc).isoformat()
    payload = delta.to_dict(
        baseline_meta=_envelope_meta(baseline_env),
        current_meta=_envelope_meta(current_env),
        generated_at=generated_at,
    )
    _emit(payload, args.out)
    _echo_stderr(
        f"delta: introduced={len(delta.introduced)} "
        f"resolved={len(delta.resolved)} changed={len(delta.changed)} "
        f"unchanged={delta.unchanged_count}",
        quiet=args.quiet,
    )
    return EXIT_OK


def _handle_gate(args: argparse.Namespace) -> int:
    target = args.path
    if not target.exists() or not target.is_dir():
        _echo_stderr(f"scan target must be an existing directory: {target}", quiet=False)
        return EXIT_ERROR

    try:
        policy = load_policy(args.policy)
    except PolicyError as exc:
        _echo_stderr(f"policy load error: {exc}", quiet=False)
        return EXIT_USAGE

    try:
        baseline_env = _load_baseline_envelope(args.baseline, quiet=args.quiet)
    except RuntimeError as exc:
        _echo_stderr(str(exc), quiet=False)
        return EXIT_ERROR

    _echo_stderr(
        f"blindspot-scan gate scanning {target} against policy '{policy.name}'…",
        quiet=args.quiet,
    )
    try:
        current_env = build_scan_envelope(target, project_id=args.project_id)
    except Exception as exc:  # noqa: BLE001
        _echo_stderr(f"scan failed: {exc}", quiet=False)
        return EXIT_ERROR

    baseline_findings = baseline_env.get("findings") or []
    current_findings = current_env.get("findings") or []
    delta = compute_delta(baseline_findings, current_findings)

    violations = evaluate_policy(policy, delta)
    generated_at = datetime.now(timezone.utc).isoformat()
    payload = delta.to_dict(
        baseline_meta=_envelope_meta(baseline_env),
        current_meta=_envelope_meta(current_env),
        generated_at=generated_at,
    )
    payload["policy"] = {
        "name": policy.name,
        "violations": [v.to_dict() for v in violations],
    }
    _emit(payload, args.out)

    if has_block_violations(violations):
        block_count = sum(1 for v in violations if v.action == "block")
        warn_count = sum(1 for v in violations if v.action == "warn")
        _echo_stderr(
            f"gate FAILED: {block_count} block violation(s), "
            f"{warn_count} warn violation(s).",
            quiet=False,
        )
        return EXIT_POLICY_VIOLATION

    warn_count = sum(1 for v in violations if v.action == "warn")
    _echo_stderr(
        f"gate passed: 0 block violation(s), {warn_count} warn violation(s).",
        quiet=args.quiet,
    )
    return EXIT_OK


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

_HANDLERS = {
    "scan": _handle_scan,
    "diff": _handle_diff,
    "gate": _handle_gate,
}


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns the exit code; callers should sys.exit it."""
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse's default: 0 for --version/--help, 2 for parse errors.
        # We remap parse errors to our own usage code (3).
        code = exc.code if isinstance(exc.code, int) else EXIT_USAGE
        if code in (0, None):
            return EXIT_OK
        return EXIT_USAGE

    _configure_logging(quiet=args.quiet)
    handler = _HANDLERS[args.command]
    return handler(args)


if __name__ == "__main__":  # pragma: no cover -- console-script entry
    sys.exit(main())
