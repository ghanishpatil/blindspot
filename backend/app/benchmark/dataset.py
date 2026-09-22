"""Ground-truth dataset loading for the benchmark harness.

Manifest shape (``manifest.json``)::

    {
      "schemaVersion": "blindspot.benchmark.v1",
      "name": "blindspot-builtin",
      "description": "...",
      "cases": [
        {
          "id": "weak-rsa-1024",
          "file": "weak_rsa_1024.py",
          "category": "weak-crypto/rsa",
          "language": "python",
          "expected": [
            {"algorithm": "RSA", "parameter": "1024"}
          ],
          "notes": "1024-bit RSA is Overdue (NIST SP 800-131A rev 3)."
        }
      ]
    }

Rules for the schema:

* ``id`` -- kebab-case, unique across cases. Reports index by this.
* ``file`` -- path relative to the dataset root (``cases/`` directory).
* ``expected`` -- list of ``ExpectedFinding``. Empty list = a true-negative
  case: the scanner should find *nothing* on this file.
* ``expected[].parameter`` and ``curve`` -- optional. Match is by
  algorithm alone when omitted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


BENCHMARK_SCHEMA_VERSION = "blindspot.benchmark.v1"


class BenchmarkError(ValueError):
    """Raised when the manifest is malformed."""


@dataclass(frozen=True)
class ExpectedFinding:
    """One expected pipeline finding for a benchmark case."""

    algorithm: str
    parameter: str | None = None
    curve: str | None = None
    # Optional intent labels -- surfaced in the case-level report so a
    # reader can see *why* a finding was expected without cross-referencing
    # the case source.
    expected_tier: str | None = None
    notes: str | None = None

    def matches(self, finding: dict[str, Any]) -> bool:
        """True when *finding* satisfies this expectation.

        Match is by algorithm (case-insensitive), plus parameter and
        curve when the expectation names them. Extra fields on the
        finding are ignored -- we're matching intent, not shape.
        """
        algo_a = (self.algorithm or "").strip().upper()
        algo_b = str(finding.get("algorithm") or "").strip().upper()
        if algo_a != algo_b:
            return False
        if self.parameter is not None:
            param_a = str(self.parameter).strip()
            param_b = str(finding.get("parameter") or "").strip()
            if param_a != param_b:
                return False
        if self.curve is not None:
            curve_a = str(self.curve).strip().upper()
            curve_b = str(finding.get("curve") or "").strip().upper()
            if curve_a != curve_b:
                return False
        return True


@dataclass(frozen=True)
class BenchmarkCase:
    """One labelled case in a benchmark dataset."""

    case_id: str
    file: str
    category: str
    language: str
    expected: list[ExpectedFinding] = field(default_factory=list)
    notes: str | None = None

    @property
    def is_true_negative(self) -> bool:
        """A case that must produce zero findings to score."""
        return not self.expected


@dataclass(frozen=True)
class BenchmarkDataset:
    """A parsed benchmark manifest plus the directory that hosts its files."""

    name: str
    description: str
    root: Path
    cases: list[BenchmarkCase]

    def case_files(self) -> list[Path]:
        """Absolute paths of every case source file. Preserves order."""
        return [self.root / c.file for c in self.cases]

    def missing_files(self) -> list[BenchmarkCase]:
        """Cases whose source file does not exist on disk.

        Callers use this to fail fast in the API endpoint rather than
        silently score a case as TN just because its file is missing.
        """
        return [c for c in self.cases if not (self.root / c.file).is_file()]

    def by_id(self) -> dict[str, BenchmarkCase]:
        return {c.case_id: c for c in self.cases}


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

_VALID_EXPECTED_KEYS: set[str] = {
    "algorithm",
    "parameter",
    "curve",
    "expectedTier",
    "notes",
}
_VALID_CASE_KEYS: set[str] = {
    "id",
    "file",
    "category",
    "language",
    "expected",
    "notes",
}


def load_manifest(path: Path) -> BenchmarkDataset:
    """Read *path* and return a validated :class:`BenchmarkDataset`.

    The manifest directory becomes ``dataset.root`` -- case files are
    resolved relative to it. Every schema violation raises
    :class:`BenchmarkError` with a message that names the offending
    field / case index; the API endpoint surfaces that verbatim as
    HTTP 400 so operators can fix bad manifests quickly.
    """
    path = Path(path)
    if not path.is_file():
        raise BenchmarkError(f"manifest not found: {path}")

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkError(f"manifest is not valid JSON: {exc}") from exc

    if not isinstance(raw, dict):
        raise BenchmarkError("manifest root must be a JSON object")

    version = raw.get("schemaVersion")
    if version not in {BENCHMARK_SCHEMA_VERSION, None}:
        raise BenchmarkError(
            f"unsupported manifest schemaVersion: {version!r}; "
            f"expected {BENCHMARK_SCHEMA_VERSION!r}"
        )

    name = str(raw.get("name") or path.parent.name or "unnamed")
    description = str(raw.get("description") or "")

    raw_cases = raw.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise BenchmarkError("manifest.cases must be a non-empty list")

    cases = [_parse_case(idx, item) for idx, item in enumerate(raw_cases)]

    # Duplicate ids are silent bugs -- refuse the manifest.
    seen: set[str] = set()
    for c in cases:
        if c.case_id in seen:
            raise BenchmarkError(f"duplicate case id: {c.case_id!r}")
        seen.add(c.case_id)

    return BenchmarkDataset(
        name=name,
        description=description,
        root=path.parent,
        cases=cases,
    )


def _parse_case(index: int, item: Any) -> BenchmarkCase:
    if not isinstance(item, dict):
        raise BenchmarkError(f"cases[{index}] must be an object")

    unknown = set(item.keys()) - _VALID_CASE_KEYS
    if unknown:
        raise BenchmarkError(
            f"cases[{index}] has unknown keys: {sorted(unknown)}. "
            f"Allowed: {sorted(_VALID_CASE_KEYS)}"
        )

    case_id = item.get("id")
    if not isinstance(case_id, str) or not case_id.strip():
        raise BenchmarkError(f"cases[{index}].id must be a non-empty string")
    case_id = case_id.strip()

    file_field = item.get("file")
    if not isinstance(file_field, str) or not file_field.strip():
        raise BenchmarkError(f"cases[{index}].file must be a non-empty string")

    category = str(item.get("category") or "uncategorised")
    language = str(item.get("language") or "unknown")
    notes = item.get("notes")
    notes = str(notes) if notes is not None else None

    raw_expected = item.get("expected", [])
    if not isinstance(raw_expected, list):
        raise BenchmarkError(f"cases[{index}].expected must be a list")

    expected = [
        _parse_expected(case_id, ei, ex) for ei, ex in enumerate(raw_expected)
    ]

    return BenchmarkCase(
        case_id=case_id,
        file=file_field,
        category=category,
        language=language,
        expected=expected,
        notes=notes,
    )


def _parse_expected(case_id: str, index: int, item: Any) -> ExpectedFinding:
    if not isinstance(item, dict):
        raise BenchmarkError(
            f"cases[{case_id!r}].expected[{index}] must be an object"
        )

    unknown = set(item.keys()) - _VALID_EXPECTED_KEYS
    if unknown:
        raise BenchmarkError(
            f"cases[{case_id!r}].expected[{index}] has unknown keys: {sorted(unknown)}. "
            f"Allowed: {sorted(_VALID_EXPECTED_KEYS)}"
        )

    algorithm = item.get("algorithm")
    if not isinstance(algorithm, str) or not algorithm.strip():
        raise BenchmarkError(
            f"cases[{case_id!r}].expected[{index}].algorithm is required"
        )

    parameter = item.get("parameter")
    curve = item.get("curve")
    expected_tier = item.get("expectedTier")
    notes = item.get("notes")

    return ExpectedFinding(
        algorithm=algorithm.strip(),
        parameter=str(parameter).strip() if parameter is not None else None,
        curve=str(curve).strip() if curve is not None else None,
        expected_tier=str(expected_tier).strip() if expected_tier else None,
        notes=str(notes) if notes else None,
    )


# ---------------------------------------------------------------------------
# Bundled dataset accessor
# ---------------------------------------------------------------------------

_BUNDLED_MANIFEST = Path(__file__).parent / "data" / "manifest.json"


def load_bundled_dataset() -> BenchmarkDataset:
    """Load the dataset shipped inside ``app/benchmark/data/``.

    This is what ``POST /api/benchmark/run`` uses when the caller does
    not point at a custom manifest.
    """
    return load_manifest(_BUNDLED_MANIFEST)


__all__ = [
    "BENCHMARK_SCHEMA_VERSION",
    "BenchmarkCase",
    "BenchmarkDataset",
    "BenchmarkError",
    "ExpectedFinding",
    "load_bundled_dataset",
    "load_manifest",
]
