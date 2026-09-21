"""Semgrep runner — source-level cryptographic discovery.

Phase 4 implements the scanning logic. What is established now is executable
resolution, because getting it wrong produces the worst possible failure mode:
a scan that reports zero findings because the scanner was never found.

Resolution order:

1. ``SEMGREP_PATH`` when it points directly at an existing executable.
2. ``shutil.which`` on ``SEMGREP_PATH`` — the activated-venv or system case.
3. The script directory beside the running interpreter. Semgrep is installed
   into the virtual environment, so this covers running ``uvicorn`` through
   ``.venv\\Scripts\\python.exe`` without activating the environment first.

Rules under ``rules/`` describe *what was found*, never *what to do about it*;
recommendation logic must not leak into rule metadata.
"""

from __future__ import annotations

import shutil
import sys
import sysconfig
from pathlib import Path

from app.config import Settings, get_settings, subprocess_timeout


class SemgrepNotAvailable(RuntimeError):
    """Raised when the semgrep executable cannot be found or run."""


def _interpreter_script_dirs() -> list[Path]:
    """Directories that hold console scripts for the running interpreter."""
    candidates: list[Path] = []

    for key in ("scripts", "purelib"):
        path = sysconfig.get_path(key)
        if path:
            candidates.append(Path(path))

    # Fallback for layouts sysconfig does not report as expected.
    executable_dir = Path(sys.executable).parent
    candidates.append(executable_dir)
    candidates.append(executable_dir / "Scripts")
    candidates.append(executable_dir / "bin")

    seen: set[Path] = set()
    unique: list[Path] = []
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            unique.append(candidate)
    return unique


def resolve_semgrep(settings: Settings | None = None) -> Path | None:
    """Locate the semgrep executable, or return None when unavailable."""
    settings = settings or get_settings()
    configured = settings.semgrep_path

    direct = Path(configured)
    if direct.is_file():
        return direct.resolve()

    found = shutil.which(configured)
    if found:
        return Path(found).resolve()

    stem = direct.stem or configured
    suffixes = [".exe", ".cmd", ".bat", ""] if sys.platform == "win32" else [""]
    for directory in _interpreter_script_dirs():
        for suffix in suffixes:
            candidate = directory / f"{stem}{suffix}"
            if candidate.is_file():
                return candidate.resolve()

    return None


def semgrep_available(settings: Settings | None = None) -> bool:
    """Whether semgrep can be invoked.

    Surfaced by the health endpoint so a missing scanner is visible before a
    demo rather than during one.
    """
    return resolve_semgrep(settings) is not None


def require_semgrep(settings: Settings | None = None) -> Path:
    """Return the semgrep executable path or raise with a fixable message."""
    resolved = resolve_semgrep(settings)
    if resolved is None:
        settings = settings or get_settings()
        raise SemgrepNotAvailable(
            f"Could not locate semgrep (configured as {settings.semgrep_path!r}). "
            "Install it with 'pip install -r requirements.txt' or set SEMGREP_PATH "
            "to the executable."
        )
    return resolved


class SemgrepScanError(RuntimeError):
    """Raised when semgrep exits with an error or produces unparseable output."""


# Location of the bundled rule files.
RULES_DIR = Path(__file__).resolve().parent / "rules"


def rules_dir() -> Path:
    """Path to the directory containing Blindspot's semgrep rule YAML files."""
    if not RULES_DIR.is_dir():
        raise SemgrepNotAvailable(
            f"Rules directory not found at {RULES_DIR}. "
            "Expected app/scanner/rules/ with .yaml rule files."
        )
    yamls = list(RULES_DIR.glob("*.yaml")) + list(RULES_DIR.glob("*.yml"))
    if not yamls:
        raise SemgrepNotAvailable(f"No rule files found in {RULES_DIR}.")
    return RULES_DIR


def run_semgrep(target: Path, settings: Settings | None = None) -> list[dict]:
    """Run semgrep against *target* and return the raw ``results`` list.

    Each result dict has the shape semgrep CE emits::

        {
            "check_id": "...",
            "path": "...",
            "start": {"line": N, "col": N, "offset": N},
            "end":   {"line": N, "col": N, "offset": N},
            "extra": {"message": "...", "metadata": {...}, "severity": "..."}
        }

    Semgrep CE does NOT emit ``metavars`` or matched source text (``lines``
    is ``"requires login"``).  Parameter extraction happens in the evidence
    extractor, not here.
    """
    import json
    import logging
    import subprocess

    logger = logging.getLogger(__name__)
    settings = settings or get_settings()

    executable = require_semgrep(settings)
    config_dir = rules_dir()
    target = target.resolve()

    if not target.exists():
        raise FileNotFoundError(f"Scan target does not exist: {target}")

    # Our rules target Python, C, Java, JavaScript, TypeScript, and Go.
    # Excluding non-source extensions keeps semgrep from walking (and
    # opening) binaries, archives, IaC, and generated files — separate
    # scanners own those. On Windows, real-time antivirus scans of large
    # or ELF-magic files can otherwise stall the semgrep process
    # indefinitely.
    _SEMGREP_EXCLUDES = (
        # Compiled / binary artefacts
        "*.so", "*.dll", "*.dylib", "*.exe", "*.sys", "*.pyd",
        "*.a", "*.lib", "*.o", "*.obj", "*.bundle", "*.bin",
        # Archives
        "*.zip", "*.tar", "*.tar.gz", "*.tgz", "*.gz", "*.7z", "*.rar",
        "*.jar", "*.war", "*.whl",
        # Images / media / docs — cannot contain matching source
        "*.png", "*.jpg", "*.jpeg", "*.gif", "*.webp", "*.pdf", "*.svg",
        "*.mp4", "*.mp3", "*.ico", "*.woff", "*.woff2", "*.ttf",
        # IaC / config live in the infra scanner, not here
        "*.tf", "*.tfvars", "*.tf.json", "*.tfstate",
        # Common noisy directories
        "node_modules", ".git", "dist", "build", "__pycache__", ".venv",
        "venv", ".mypy_cache", ".pytest_cache", ".semgrep",
    )

    cmd = [
        str(executable),
        "scan",
        "--config", str(config_dir),
        "--json",
        "--quiet",
        "--metrics=off",
        "--no-git-ignore",
    ]
    for pattern in _SEMGREP_EXCLUDES:
        cmd.extend(("--exclude", pattern))
    cmd.append(str(target))

    logger.info("Running: %s", " ".join(cmd))

    # Zero (the default) means "wait as long as needed". A large polyglot
    # repository can legitimately keep semgrep busy for many minutes; a
    # fixed cap would either be too short here (killing real scans) or
    # too long elsewhere (masking a truly stuck process).
    timeout = subprocess_timeout(settings.semgrep_timeout_seconds)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            # Semgrep emits UTF-8 JSON. Without an explicit encoding, Python
            # decodes the child output with the OS locale codec (cp1252 on
            # Windows), which crashes on any non-cp1252 byte (e.g. 0x9d) in a
            # scanned file's path or code snippet. Decode as UTF-8 and replace
            # undecodable bytes so a single odd byte never fails the scan.
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise SemgrepScanError(
            f"Semgrep was cancelled after {settings.semgrep_timeout_seconds}s "
            "(SEMGREP_TIMEOUT_SECONDS). Set SEMGREP_TIMEOUT_SECONDS=0 to let "
            "large scans run to completion."
        ) from exc

    # Semgrep returns exit code 0 on success (even with findings) and 1 on
    # errors.  Parse stdout regardless, because partial results plus errors
    # is a valid output shape. stdout may be None if the process produced
    # nothing, so guard against it before stripping.
    raw = (proc.stdout or "").strip()
    if not raw:
        stderr_snippet = (proc.stderr or "")[:500]
        raise SemgrepScanError(
            f"Semgrep produced no output (exit code {proc.returncode}). "
            f"stderr: {stderr_snippet}"
        )

    try:
        output = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SemgrepScanError(
            f"Semgrep output is not valid JSON: {exc}\n"
            f"First 300 chars: {raw[:300]}"
        ) from exc

    errors = output.get("errors", [])
    if errors:
        for err in errors:
            logger.warning(
                "Semgrep error: %s — %s",
                err.get("short_msg", "?"),
                (err.get("long_msg") or "")[:200],
            )

    results = output.get("results", [])
    scanned = output.get("paths", {}).get("scanned", [])
    logger.info(
        "Semgrep finished: %d matches across %d files (%d errors).",
        len(results),
        len(scanned),
        len(errors),
    )

    return results
