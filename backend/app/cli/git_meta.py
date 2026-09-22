"""Best-effort git metadata extraction for the scan envelope.

Reports the committed SHA and current branch of the scan target *when*
the target is a git working tree. Every failure mode -- no git binary,
not a working tree, detached HEAD, subprocess timeout -- collapses to
``(None, None)`` without raising. The CLI never fabricates a SHA.

The values are wrapped into ``target.gitRef`` / ``target.gitBranch`` on
the ``blindspot.scan.v1`` envelope so downstream consumers (the CI
guardrail, the report renderer, an auditor) can trace a scan back to
the exact commit that produced it -- when git can tell them.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# Short timeout: git rev-parse should be instantaneous on any healthy
# working tree. A slow answer is far more likely to be a hung command
# than a real one, and stalling the CI on rev-parse is unacceptable.
_TIMEOUT_SECONDS = 5


def _run(cmd: list[str], cwd: Path) -> str | None:
    """Run *cmd* in *cwd* and return stripped stdout, or ``None`` on any
    failure (missing binary, non-zero exit, timeout, decode error).

    Never raises. The caller assumes ``None`` means "git could not tell
    us" and puts that on the wire as null.
    """
    try:
        result = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SECONDS,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("git command %s failed: %s", cmd, exc)
        return None
    if result.returncode != 0:
        return None
    value = (result.stdout or "").strip()
    return value or None


def git_head_meta(target: Path | str) -> dict[str, str | None]:
    """Return ``{"gitRef": <sha or None>, "gitBranch": <branch or None>}``.

    * ``gitRef`` -- output of ``git rev-parse HEAD``.
    * ``gitBranch`` -- output of ``git rev-parse --abbrev-ref HEAD``,
      which is the branch name in a normal working tree and the literal
      ``"HEAD"`` in a detached checkout. We surface the raw value; the
      caller (or the operator reading the JSON) can interpret it.

    Both fields are ``None`` when the target is not inside a git working
    tree or git itself is unavailable. Never raises.
    """
    path = Path(target).expanduser().resolve()
    if not path.exists():
        return {"gitRef": None, "gitBranch": None}
    # Some scanners hand us a file (e.g. a lone key file); rev-parse
    # needs a directory, so climb up when necessary.
    cwd = path if path.is_dir() else path.parent

    ref = _run(["git", "rev-parse", "HEAD"], cwd)
    branch = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd)
    return {"gitRef": ref, "gitBranch": branch}
