"""Cross-scan CBOM / findings diff engine.

Compares two scan snapshots (base and head) from the on-disk artefact
mirror and produces:

* ``added``     -- findings in head that are absent from base
* ``removed``   -- findings in base that are absent from head
* ``changed``   -- findings present in both, whose Mosca risk tier moved
* ``unchanged`` -- count of findings present in both, same tier (no list
  is returned; the count is what an operator wants for a summary)
* ``summaryDelta`` -- per-Risk_Tier and per-flag deltas (head - base)

Design rules that keep this honest:

1. **Pure function, no I/O.** ``compute_diff`` takes plain dicts, returns
   plain dicts. The endpoint layer loads the scans from disk; this
   module never touches the filesystem. Testable in isolation.
2. **No fabrication.** Every value in the output comes verbatim from the
   inputs; the module does not classify, re-tier, or reinterpret.
3. **Stable match key.** Two findings across scans are "the same" when
   their ``(algorithm, parameter, curve, filePath)`` tuple matches. Line
   numbers drift across commits, so line numbers are deliberately excluded
   from the match key -- otherwise every minor whitespace change would
   register as an added+removed pair, which is dishonest.
4. **Deterministic ordering.** Output lists are sorted so the API
   response is reproducible for testing and diff-of-diff review.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable


# ---------------------------------------------------------------------------
# Match-key + shaping helpers -- pure, no I/O
# ---------------------------------------------------------------------------

_TIER_FIELDS: tuple[str, ...] = (
    "totalFindings",
    "overdue",
    "transitional",
    "lowRisk",
    "hndlExposed",
    "currentWeakCrypto",
    "needsVerification",
    "quantumSensitive",
    "unresolvedParameters",
)


def _match_key(finding: dict[str, Any]) -> tuple[str, str, str, str]:
    """Stable identity for a finding across scans.

    We include algorithm, resolved parameter, curve, and file_path. Line
    number is left out on purpose: source drifts, and treating a whitespace
    reformat as ``removed X, added X`` would be dishonest noise.

    Missing fields are represented as empty strings so the tuple is fully
    hashable and comparable.
    """
    return (
        str(finding.get("algorithm") or ""),
        str(finding.get("parameter") or ""),
        str(finding.get("curve") or ""),
        str(finding.get("filePath") or finding.get("evidence", {}).get("filePath") or ""),
    )


def _row(finding: dict[str, Any]) -> dict[str, Any]:
    """Compact projection of a finding for the diff response.

    Renders the fields the diff panel cares about, dropping the full
    evidence + recommendation objects -- callers who want those hit
    ``GET /api/scans/{scanId}`` directly.
    """
    return {
        "id": finding.get("id"),
        "algorithm": finding.get("algorithm"),
        "displayName": finding.get("displayName") or finding.get("algorithm"),
        "parameter": finding.get("parameter"),
        "curve": finding.get("curve"),
        "filePath": finding.get("filePath") or finding.get("evidence", {}).get("filePath"),
        "lineNumber": finding.get("lineNumber") or finding.get("evidence", {}).get("lineNumber"),
        "riskTier": finding.get("riskTier"),
        "isHndlExposed": bool(finding.get("isHndlExposed")),
        "isCurrentlyWeak": bool(finding.get("isCurrentlyWeak")),
        "detectionMethod": (finding.get("evidence") or {}).get("detectionMethod"),
    }


def _changed_row(base: dict[str, Any], head: dict[str, Any]) -> dict[str, Any]:
    """Row for a finding whose risk tier moved between the two scans."""
    row = _row(head)
    row["previousTier"] = base.get("riskTier")
    row["currentTier"] = head.get("riskTier")
    row["previousLineNumber"] = (
        base.get("lineNumber") or base.get("evidence", {}).get("lineNumber")
    )
    return row


def _scan_meta(scan: dict[str, Any]) -> dict[str, Any]:
    """Compact scan header for the diff response."""
    return {
        "scanId": scan.get("id"),
        "projectId": scan.get("projectId"),
        "startedAt": scan.get("startedAt"),
        "completedAt": scan.get("completedAt"),
        "findingCount": scan.get("findingCount", 0),
        "summary": scan.get("summary") or {},
    }


def _summary_delta(
    base_summary: dict[str, Any], head_summary: dict[str, Any]
) -> dict[str, int]:
    """Compute head_summary[field] - base_summary[field] for every tier field.

    Missing fields on either side count as zero; the delta is what an
    operator sees in the diff header ("overdue -3, HNDL exposed -2").
    """
    delta: dict[str, int] = {}
    for field_name in _TIER_FIELDS:
        base_val = int(base_summary.get(field_name) or 0)
        head_val = int(head_summary.get(field_name) or 0)
        delta[field_name] = head_val - base_val
    return delta


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DiffResult:
    """Result of :func:`compute_diff`. Round-trips cleanly to JSON."""

    base: dict[str, Any]
    head: dict[str, Any]
    summary_delta: dict[str, int]
    added: list[dict[str, Any]]
    removed: list[dict[str, Any]]
    changed: list[dict[str, Any]]
    unchanged_count: int
    added_count: int
    removed_count: int
    changed_count: int

    def to_dict(self) -> dict[str, Any]:
        """Serialise to camelCase JSON shape used by the API + frontend."""
        return {
            "base": self.base,
            "head": self.head,
            "summaryDelta": self.summary_delta,
            "added": self.added,
            "removed": self.removed,
            "changed": self.changed,
            "unchangedCount": self.unchanged_count,
            "addedCount": self.added_count,
            "removedCount": self.removed_count,
            "changedCount": self.changed_count,
        }


def compute_diff(
    base_scan: dict[str, Any],
    base_findings: Iterable[dict[str, Any]],
    head_scan: dict[str, Any],
    head_findings: Iterable[dict[str, Any]],
) -> DiffResult:
    """Compare two scans and return a structured, ordered diff.

    ``base`` and ``head`` follow git terminology: ``base`` is the older /
    reference scan; ``head`` is the newer / candidate scan. Deltas are
    signed ``head - base``, so a *negative* overdue delta means the newer
    scan has fewer overdue findings -- the migration progressed.

    All output lists are sorted deterministically so the response is
    reproducible for testing and downstream diff-of-diff review.
    """
    base_list = list(base_findings)
    head_list = list(head_findings)

    base_by_key: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for f in base_list:
        base_by_key[_match_key(f)] = f

    head_by_key: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for f in head_list:
        head_by_key[_match_key(f)] = f

    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    unchanged_count = 0

    # Iterate the union so every key is visited exactly once.
    all_keys = set(base_by_key.keys()) | set(head_by_key.keys())
    for key in sorted(all_keys):
        b = base_by_key.get(key)
        h = head_by_key.get(key)
        if b is None and h is not None:
            added.append(_row(h))
        elif h is None and b is not None:
            removed.append(_row(b))
        elif b is not None and h is not None:
            if b.get("riskTier") != h.get("riskTier"):
                changed.append(_changed_row(b, h))
            else:
                unchanged_count += 1

    added.sort(key=_diff_row_sort_key)
    removed.sort(key=_diff_row_sort_key)
    changed.sort(key=_diff_row_sort_key)

    return DiffResult(
        base=_scan_meta(base_scan),
        head=_scan_meta(head_scan),
        summary_delta=_summary_delta(
            base_scan.get("summary") or {}, head_scan.get("summary") or {}
        ),
        added=added,
        removed=removed,
        changed=changed,
        unchanged_count=unchanged_count,
        added_count=len(added),
        removed_count=len(removed),
        changed_count=len(changed),
    )


def _diff_row_sort_key(row: dict[str, Any]) -> tuple[str, str, str, str]:
    """Stable sort: algorithm, then file, then parameter, then id."""
    return (
        str(row.get("algorithm") or ""),
        str(row.get("filePath") or ""),
        str(row.get("parameter") or ""),
        str(row.get("id") or ""),
    )


__all__ = ["DiffResult", "compute_diff"]
