"""Delta engine for ``blindspot-scan diff`` and ``gate``.

Compares two scan envelopes (baseline and current) and returns an
``introduced / resolved / changed / unchanged`` bucketing at the
individual-finding level. This is the "did a PR make things worse?"
signal the CI/CD guardrail acts on.

Design rules:

1. **Finding identity is a hash, not the id.** ``Finding.id`` is
   regenerated per scan and depends on iteration order. We identify a
   finding by a SHA-256 fingerprint of its evidence tuple:
   ``(algorithm, parameter, curve, filePath, lineNumber, ruleId)``.
2. **Line-move tolerance is one hop deep.** When a fingerprint miss
   would otherwise mark the same finding as ``resolved + introduced``
   just because a line number shifted, we fall back to a *file-level*
   fingerprint (line stripped). The fallback never reaches across
   files -- that would be lossy in a way that hides real drift.
3. **Change detection is field-list-driven.** A matched finding whose
   ``riskTier`` / ``isCurrentlyWeak`` / ``isQuantumSensitive`` /
   ``isHndlExposed`` / ``parameter`` / ``parameterStatus`` /
   ``needsVerification`` differs from the baseline is ``changed``.
   Everything else is ``unchanged``.
4. **Pure function, no I/O.** ``compute_delta`` takes and returns
   plain dicts. Tests exercise it without a filesystem.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable


# Schema for the delta envelope emitted by ``blindspot-scan diff``.
DELTA_SCHEMA_VERSION = "blindspot.delta.v1"


# Fields we compare between matched findings. Anything not in this set
# is either provenance (id, createdAt), or a computed rendering, and
# does not deserve a ``changed`` classification on its own.
_TRACKED_CHANGE_FIELDS: tuple[str, ...] = (
    "riskTier",
    "isCurrentlyWeak",
    "isQuantumSensitive",
    "isHndlExposed",
    "parameter",
    "parameterStatus",
    "needsVerification",
)


def _s(value: Any) -> str:
    """Compact stable-string coercion for the fingerprint hash.

    ``None`` becomes empty, everything else is ``str()`` -- we do NOT
    JSON-encode because JSON's ordering can differ between Python
    releases for equivalent-looking values.
    """
    if value is None:
        return ""
    return str(value)


def _evidence_dict(finding: dict[str, Any]) -> dict[str, Any]:
    """Return a dict view of a finding's evidence, tolerant of shape.

    The live pipeline stores ``evidence`` as a code-snippet **string**
    and the structured metadata under ``evidenceDetail``. Older
    fixtures and simple tests pass ``evidence`` directly as a dict.
    We accept either -- production baselines and synthetic inputs both
    fingerprint the same way.
    """
    detail = finding.get("evidenceDetail")
    if isinstance(detail, dict):
        return detail
    evidence = finding.get("evidence")
    if isinstance(evidence, dict):
        return evidence
    return {}


def fingerprint(finding: dict[str, Any]) -> str:
    """SHA-256 hex fingerprint of one finding's evidence tuple.

    The tuple is joined with ``\\x1f`` (ASCII unit separator, byte 31)
    to guarantee no field boundary collides with an in-value ``|`` or
    similar. Deterministic across process restarts.
    """
    evidence = _evidence_dict(finding)
    parts = [
        _s(finding.get("algorithm")),
        _s(finding.get("parameter")),
        _s(finding.get("curve")),
        _s(finding.get("filePath") or evidence.get("filePath")),
        _s(finding.get("lineNumber") or evidence.get("lineNumber")),
        _s(evidence.get("ruleId")),
    ]
    payload = "\x1f".join(parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def fingerprint_no_line(finding: dict[str, Any]) -> str:
    """Fallback fingerprint used when a line-number moved.

    Uses the same tuple minus ``lineNumber`` so a whitespace-only
    reformat that shifts everything by a few lines still matches the
    baseline. Never reaches across files.
    """
    evidence = _evidence_dict(finding)
    parts = [
        _s(finding.get("algorithm")),
        _s(finding.get("parameter")),
        _s(finding.get("curve")),
        _s(finding.get("filePath") or evidence.get("filePath")),
        _s(evidence.get("ruleId")),
    ]
    payload = "\x1f".join(parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class DeltaResult:
    """Result of :func:`compute_delta`. Round-trips cleanly to JSON."""

    introduced: list[dict[str, Any]]
    resolved: list[dict[str, Any]]
    changed: list[dict[str, Any]]
    unchanged_count: int

    def to_dict(
        self,
        *,
        baseline_meta: dict[str, Any] | None = None,
        current_meta: dict[str, Any] | None = None,
        generated_at: str | None = None,
    ) -> dict[str, Any]:
        """Serialise with a schema-versioned envelope."""
        return {
            "schemaVersion": DELTA_SCHEMA_VERSION,
            "generatedAt": generated_at,
            "baseline": baseline_meta or {},
            "current": current_meta or {},
            "counts": {
                "introduced": len(self.introduced),
                "resolved": len(self.resolved),
                "changed": len(self.changed),
                "unchanged": self.unchanged_count,
            },
            "introduced": self.introduced,
            "resolved": self.resolved,
            "changed": self.changed,
        }


def compute_delta(
    baseline_findings: Iterable[dict[str, Any]],
    current_findings: Iterable[dict[str, Any]],
) -> DeltaResult:
    """Compute the introduced / resolved / changed / unchanged bucketing.

    Two-pass matching:

    1. **Exact fingerprint pass** -- the primary path. Every finding is
       hashed with :func:`fingerprint`; pairs where the baseline and
       current hashes agree are matched.
    2. **File-fallback pass** -- for still-unmatched findings, hash
       with :func:`fingerprint_no_line` and match at the file level.
       This handles pure line drift from a whitespace edit without
       claiming a spurious "removed + added" pair.

    Anything unmatched after both passes is ``introduced`` (only in
    current) or ``resolved`` (only in baseline). Matched pairs are
    classified as ``changed`` when any tracked field differs, else
    ``unchanged``.
    """
    baseline_list = list(baseline_findings)
    current_list = list(current_findings)

    # First pass: index everything by exact fingerprint.
    base_by_fp: dict[str, dict[str, Any]] = {}
    for f in baseline_list:
        base_by_fp.setdefault(fingerprint(f), f)

    cur_by_fp: dict[str, dict[str, Any]] = {}
    for f in current_list:
        cur_by_fp.setdefault(fingerprint(f), f)

    matched_base_ids: set[int] = set()
    matched_cur_ids: set[int] = set()
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []

    for fp, cur in cur_by_fp.items():
        base = base_by_fp.get(fp)
        if base is not None:
            pairs.append((base, cur))
            matched_base_ids.add(id(base))
            matched_cur_ids.add(id(cur))

    # Second pass: file-level fallback for what's left over. This is
    # where line drift is forgiven. Careful: we only match a file-level
    # fingerprint to at most one leftover on each side, so a file with
    # multiple identical findings does not collapse.
    unmatched_base = [f for f in baseline_list if id(f) not in matched_base_ids]
    unmatched_cur = [f for f in current_list if id(f) not in matched_cur_ids]

    base_by_file_fp: dict[str, list[dict[str, Any]]] = {}
    for f in unmatched_base:
        base_by_file_fp.setdefault(fingerprint_no_line(f), []).append(f)

    still_unmatched_cur: list[dict[str, Any]] = []
    for cur in unmatched_cur:
        pool = base_by_file_fp.get(fingerprint_no_line(cur))
        if pool:
            # Consume the first available match. Preserves determinism
            # since both lists are iterated in original order.
            base = pool.pop(0)
            pairs.append((base, cur))
            matched_base_ids.add(id(base))
        else:
            still_unmatched_cur.append(cur)

    # Anything left in the pools is genuinely resolved.
    resolved: list[dict[str, Any]] = []
    for pool in base_by_file_fp.values():
        resolved.extend(pool)

    introduced = still_unmatched_cur

    # Classify each matched pair as changed or unchanged.
    changed: list[dict[str, Any]] = []
    unchanged_count = 0
    for base, cur in pairs:
        diffs = _diff_tracked_fields(base, cur)
        if diffs:
            changed.append({
                "id": cur.get("id"),
                "fingerprint": fingerprint(cur),
                "changes": diffs,
                # Attach a compact current snapshot for report renderers.
                "algorithm": cur.get("algorithm"),
                "displayName": cur.get("displayName"),
                "filePath": cur.get("filePath")
                or _evidence_dict(cur).get("filePath"),
                "lineNumber": cur.get("lineNumber")
                or _evidence_dict(cur).get("lineNumber"),
            })
        else:
            unchanged_count += 1

    # Deterministic sort so the API response and test assertions match.
    introduced.sort(key=_finding_sort_key)
    resolved.sort(key=_finding_sort_key)
    changed.sort(key=_change_sort_key)

    return DeltaResult(
        introduced=introduced,
        resolved=resolved,
        changed=changed,
        unchanged_count=unchanged_count,
    )


def _diff_tracked_fields(
    base: dict[str, Any], cur: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    """Return ``{field: {"from": base_val, "to": cur_val}}`` for tracked
    fields whose values differ. Absent fields count as ``None`` so a
    field appearing in one snapshot but not the other still surfaces."""
    diffs: dict[str, dict[str, Any]] = {}
    for name in _TRACKED_CHANGE_FIELDS:
        b = base.get(name)
        c = cur.get(name)
        if b != c:
            diffs[name] = {"from": b, "to": c}
    return diffs


def _finding_sort_key(finding: dict[str, Any]) -> tuple[str, ...]:
    ev = _evidence_dict(finding)
    return (
        _s(finding.get("algorithm")),
        _s(finding.get("filePath") or ev.get("filePath")),
        _s(finding.get("parameter")),
        _s(finding.get("id")),
    )


def _change_sort_key(row: dict[str, Any]) -> tuple[str, ...]:
    return (
        _s(row.get("algorithm")),
        _s(row.get("filePath")),
        _s(row.get("id")),
    )


__all__ = [
    "DELTA_SCHEMA_VERSION",
    "DeltaResult",
    "compute_delta",
    "fingerprint",
    "fingerprint_no_line",
]
