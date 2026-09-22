"""Tests for :mod:`app.cli.diff` -- fingerprinting + delta bucketing.

Contract from the SPEC:

1. Fingerprint is stable across runs on identical evidence.
2. Fingerprint changes when file / algorithm / rule / line changes.
3. Line-move alone (no rule change, same file) does NOT surface as
   ``resolved + introduced`` thanks to the file-fallback pass.
4. A field the SPEC tracks (``riskTier``, ``isCurrentlyWeak``, ...)
   moving between the two snapshots surfaces as ``changed``, not
   ``unchanged``.
5. Empty baseline -> every current finding is ``introduced``.
6. Empty current -> every baseline finding is ``resolved``.
"""

from __future__ import annotations

from typing import Any

from app.cli.diff import (
    DELTA_SCHEMA_VERSION,
    compute_delta,
    fingerprint,
    fingerprint_no_line,
)


# ---------------------------------------------------------------------------
# Small builders so each test reads as a single-line intent statement.
# ---------------------------------------------------------------------------

def _f(
    algorithm: str,
    parameter: str | None = None,
    *,
    file_path: str = "src/demo.py",
    line: int = 10,
    rule_id: str = "rule-a",
    tier: str = "overdue",
    weak: bool = False,
    hndl: bool = False,
    quantum: bool = True,
    param_status: str = "resolved",
    needs_verif: bool = False,
    curve: str | None = None,
    fid: str | None = None,
) -> dict[str, Any]:
    """One finding dict matching what the pipeline serialises."""
    return {
        "id": fid or f"F-{algorithm}-{parameter or curve or file_path}",
        "algorithm": algorithm,
        "parameter": parameter,
        "curve": curve,
        "filePath": file_path,
        "lineNumber": line,
        "riskTier": tier,
        "isCurrentlyWeak": weak,
        "isQuantumSensitive": quantum,
        "isHndlExposed": hndl,
        "parameterStatus": param_status,
        "needsVerification": needs_verif,
        "evidence": {
            "filePath": file_path,
            "lineNumber": line,
            "ruleId": rule_id,
            "detectionMethod": "semgrep_api_pattern",
        },
    }


# ---------------------------------------------------------------------------
# Fingerprint stability + separation
# ---------------------------------------------------------------------------

def test_fingerprint_is_stable_across_runs() -> None:
    a = _f("RSA", "2048")
    b = _f("RSA", "2048")  # brand-new dict, same evidence
    assert fingerprint(a) == fingerprint(b)


def test_fingerprint_changes_when_file_changes() -> None:
    a = _f("RSA", "2048", file_path="src/a.py")
    b = _f("RSA", "2048", file_path="src/b.py")
    assert fingerprint(a) != fingerprint(b)


def test_fingerprint_changes_when_algorithm_changes() -> None:
    a = _f("RSA", "2048")
    b = _f("ECDSA", "2048")
    assert fingerprint(a) != fingerprint(b)


def test_fingerprint_changes_when_rule_id_changes() -> None:
    a = _f("RSA", "2048", rule_id="rule-a")
    b = _f("RSA", "2048", rule_id="rule-b")
    assert fingerprint(a) != fingerprint(b)


def test_fingerprint_changes_when_line_number_changes() -> None:
    a = _f("RSA", "2048", line=10)
    b = _f("RSA", "2048", line=99)
    assert fingerprint(a) != fingerprint(b)


def test_fingerprint_no_line_agrees_across_line_move() -> None:
    """The fallback fingerprint MUST collapse a line drift to a match."""
    a = _f("RSA", "2048", line=10)
    b = _f("RSA", "2048", line=99)
    assert fingerprint_no_line(a) == fingerprint_no_line(b)


# ---------------------------------------------------------------------------
# compute_delta -- the four buckets
# ---------------------------------------------------------------------------

def test_empty_baseline_marks_every_current_as_introduced() -> None:
    current = [_f("RSA", "2048"), _f("ECDSA", curve="P-256")]
    d = compute_delta([], current)
    assert len(d.introduced) == 2
    assert d.resolved == []
    assert d.changed == []
    assert d.unchanged_count == 0


def test_empty_current_marks_every_baseline_as_resolved() -> None:
    baseline = [_f("RSA", "2048")]
    d = compute_delta(baseline, [])
    assert d.introduced == []
    assert len(d.resolved) == 1
    assert d.changed == []


def test_matched_findings_with_no_change_are_unchanged() -> None:
    f = _f("RSA", "2048")
    d = compute_delta([f], [f])
    assert d.introduced == []
    assert d.resolved == []
    assert d.changed == []
    assert d.unchanged_count == 1


def test_line_drift_alone_is_not_a_diff() -> None:
    """A whitespace-only edit shifting a match by a few lines MUST NOT
    show up as resolved + introduced. This is what
    ``fingerprint_no_line`` exists for."""
    b = _f("RSA", "2048", line=10)
    h = _f("RSA", "2048", line=99)
    d = compute_delta([b], [h])
    assert d.introduced == []
    assert d.resolved == []
    assert d.unchanged_count == 1


def test_tier_change_lands_in_changed_bucket() -> None:
    b = _f("RSA", "2048", tier="overdue")
    h = _f("RSA", "2048", tier="low-risk")
    d = compute_delta([b], [h])
    assert d.introduced == []
    assert d.resolved == []
    assert len(d.changed) == 1
    row = d.changed[0]
    assert row["changes"]["riskTier"] == {"from": "overdue", "to": "low-risk"}


def test_weak_flag_change_lands_in_changed_bucket() -> None:
    """A finding that flipped from ``isCurrentlyWeak: false`` to true
    is a regression the guardrail needs to catch."""
    b = _f("RSA", "2048", weak=False)
    h = _f("RSA", "2048", weak=True)
    d = compute_delta([b], [h])
    assert len(d.changed) == 1
    assert d.changed[0]["changes"]["isCurrentlyWeak"] == {"from": False, "to": True}


def test_parameter_change_produces_add_plus_remove_not_change() -> None:
    """Same file, same algorithm, different key size -> the old key
    genuinely went away and a new one appeared. Fingerprint mismatch
    is the correct classification."""
    b = _f("RSA", "2048")
    h = _f("RSA", "4096")
    d = compute_delta([b], [h])
    assert len(d.introduced) == 1
    assert len(d.resolved) == 1
    assert d.changed == []


def test_file_rename_is_add_plus_remove() -> None:
    """No line-drift fallback across files -- a rename genuinely IS a
    resolve + introduce pair."""
    b = _f("RSA", "2048", file_path="src/old.py")
    h = _f("RSA", "2048", file_path="src/new.py")
    d = compute_delta([b], [h])
    assert len(d.introduced) == 1
    assert len(d.resolved) == 1


def test_multiple_identical_findings_do_not_collapse() -> None:
    """A file with two indistinguishable findings (same everything)
    must still be counted twice, not merged by the file-fallback."""
    b = [_f("RSA", "2048", line=10), _f("RSA", "2048", line=20)]
    h = [_f("RSA", "2048", line=11), _f("RSA", "2048", line=21)]
    d = compute_delta(b, h)
    # Each line moves slightly. Exact fingerprints all differ, but the
    # file-fallback pairs them up 2:2 -- so both are "unchanged" (same
    # file, same evidence tuple sans line).
    assert d.introduced == []
    assert d.resolved == []
    assert d.unchanged_count == 2


def test_serialisation_shape_matches_schema() -> None:
    """to_dict() envelope has the schema version + counts sub-object."""
    d = compute_delta([], [_f("RSA", "2048")])
    out = d.to_dict()
    assert out["schemaVersion"] == DELTA_SCHEMA_VERSION
    assert out["counts"] == {
        "introduced": 1, "resolved": 0, "changed": 0, "unchanged": 0,
    }
    assert isinstance(out["introduced"], list)


def test_output_lists_sort_deterministically() -> None:
    """Sort key: (algorithm, filePath, parameter, id). Must be stable
    across process restarts so downstream tests / caches work."""
    b = []
    h = [
        _f("RSA", "2048", file_path="src/z.py"),
        _f("RSA", "2048", file_path="src/a.py"),
    ]
    d = compute_delta(b, h)
    paths = [row["filePath"] for row in d.introduced]
    assert paths == sorted(paths)


# ---------------------------------------------------------------------------
# Production-shape compatibility
# ---------------------------------------------------------------------------

def test_fingerprint_reads_evidence_detail_when_evidence_is_a_string() -> None:
    """The live pipeline stores ``evidence`` as a code-snippet string
    and puts the structured metadata under ``evidenceDetail``. The
    fingerprint MUST read ruleId from ``evidenceDetail`` in that
    case -- otherwise every real baseline blows up with
    ``AttributeError: 'str' object has no attribute 'get'``.
    """
    production_shape = {
        "algorithm": "AES",
        "parameter": "256",
        "curve": None,
        "filePath": "field_encryption_aes.py",
        "lineNumber": 33,
        "evidence": "AESGCM.generate_key(bit_length=FIELD_KEY_BITS)",
        "evidenceDetail": {
            "filePath": "field_encryption_aes.py",
            "lineNumber": 33,
            "ruleId": "blindspot-aes-gcm-keygen",
        },
        "riskTier": "low-risk",
    }
    synthetic_shape = _f(
        "AES", "256",
        file_path="field_encryption_aes.py",
        line=33,
        rule_id="blindspot-aes-gcm-keygen",
        tier="low-risk",
    )
    # The two shapes carry the same identity, so their fingerprints agree.
    assert fingerprint(production_shape) == fingerprint(synthetic_shape)


def test_compute_delta_survives_production_shape() -> None:
    """End-to-end guard: a baseline written by ``build_scan_envelope``
    (evidence = string) must not crash :func:`compute_delta`.
    """
    baseline = [
        {
            "algorithm": "RSA",
            "parameter": "2048",
            "curve": None,
            "filePath": "app/legacy.py",
            "lineNumber": 42,
            "evidence": "rsa.generate_private_key(65537, 2048)",
            "evidenceDetail": {
                "filePath": "app/legacy.py",
                "lineNumber": 42,
                "ruleId": "blindspot-rsa-generate",
            },
            "riskTier": "overdue",
        }
    ]
    current = [
        {
            "algorithm": "RSA",
            "parameter": "2048",
            "curve": None,
            "filePath": "app/legacy.py",
            "lineNumber": 42,
            "evidence": "rsa.generate_private_key(65537, 2048)",
            "evidenceDetail": {
                "filePath": "app/legacy.py",
                "lineNumber": 42,
                "ruleId": "blindspot-rsa-generate",
            },
            "riskTier": "overdue",
        }
    ]
    d = compute_delta(baseline, current)
    assert d.introduced == []
    assert d.resolved == []
    assert d.changed == []
    assert d.unchanged_count == 1
