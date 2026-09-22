"""Tests for :mod:`app.cli.policy`.

Contract:

1. Default policy blocks new is_currently_weak, new riskTier=overdue,
   and regressions to overdue. Warns on new HNDL exposure.
2. Warns never contribute to the block count -> exit code stays 0.
3. Dotted keys like ``changes.riskTier.to`` resolve against nested
   change docs.
4. Malformed policy JSON raises PolicyError -> CLI exits 3.
5. Missing --policy path returns the default policy.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from app.cli.diff import compute_delta
from app.cli.policy import (
    DEFAULT_POLICY,
    Policy,
    PolicyError,
    Violation,
    evaluate_policy,
    has_block_violations,
    load_policy,
)


# ---------------------------------------------------------------------------
# Small finding builders
# ---------------------------------------------------------------------------

def _f(**kwargs: Any) -> dict[str, Any]:
    """Minimal finding with the fields the policy inspects."""
    base = {
        "id": kwargs.pop("id", "F1"),
        "algorithm": "RSA",
        "parameter": "2048",
        "curve": None,
        "filePath": "src/demo.py",
        "lineNumber": 10,
        "riskTier": "low-risk",
        "isCurrentlyWeak": False,
        "isQuantumSensitive": True,
        "isHndlExposed": False,
        "parameterStatus": "resolved",
        "needsVerification": False,
        "evidence": {
            "filePath": "src/demo.py",
            "lineNumber": 10,
            "ruleId": "rule-a",
            "detectionMethod": "semgrep_api_pattern",
        },
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def test_load_policy_returns_default_when_path_is_none() -> None:
    assert load_policy(None) is DEFAULT_POLICY


def test_load_policy_parses_valid_file(tmp_path: Path) -> None:
    p = tmp_path / "policy.json"
    p.write_text(json.dumps({
        "schemaVersion": "blindspot.policy.v1",
        "name": "custom",
        "rules": [
            {
                "id": "r1",
                "on": "introduced",
                "match": {"riskTier": "overdue"},
                "action": "block",
            },
        ],
    }), encoding="utf-8")
    policy = load_policy(p)
    assert policy.name == "custom"
    assert len(policy.rules) == 1
    assert policy.rules[0].rule_id == "r1"


def test_load_policy_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(PolicyError):
        load_policy(tmp_path / "nope.json")


def test_load_policy_rejects_bad_json(tmp_path: Path) -> None:
    p = tmp_path / "policy.json"
    p.write_text("{ not-json", encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(p)


def test_load_policy_rejects_unknown_action(tmp_path: Path) -> None:
    p = tmp_path / "policy.json"
    p.write_text(json.dumps({
        "rules": [{
            "id": "r1", "on": "introduced",
            "match": {"riskTier": "overdue"}, "action": "explode",
        }],
    }), encoding="utf-8")
    with pytest.raises(PolicyError, match="action"):
        load_policy(p)


def test_load_policy_rejects_unknown_bucket(tmp_path: Path) -> None:
    p = tmp_path / "policy.json"
    p.write_text(json.dumps({
        "rules": [{
            "id": "r1", "on": "bogus-bucket",
            "match": {"x": 1}, "action": "block",
        }],
    }), encoding="utf-8")
    with pytest.raises(PolicyError, match="on"):
        load_policy(p)


def test_load_policy_rejects_empty_match(tmp_path: Path) -> None:
    p = tmp_path / "policy.json"
    p.write_text(json.dumps({
        "rules": [{
            "id": "r1", "on": "introduced", "match": {}, "action": "block",
        }],
    }), encoding="utf-8")
    with pytest.raises(PolicyError, match="match"):
        load_policy(p)


# ---------------------------------------------------------------------------
# Evaluator -- the default policy
# ---------------------------------------------------------------------------

def test_default_policy_blocks_new_weak_now() -> None:
    delta = compute_delta([], [_f(isCurrentlyWeak=True, algorithm="MD5")])
    violations = evaluate_policy(DEFAULT_POLICY, delta)
    block = [v for v in violations if v.action == "block"]
    assert any(v.rule_id == "no-new-weak-now" for v in block)
    assert has_block_violations(violations)


def test_default_policy_blocks_new_overdue() -> None:
    delta = compute_delta([], [_f(riskTier="overdue")])
    violations = evaluate_policy(DEFAULT_POLICY, delta)
    assert any(v.rule_id == "no-new-overdue" and v.action == "block" for v in violations)


def test_default_policy_blocks_regressions_to_overdue() -> None:
    """A finding present in both scans but promoted to overdue on the
    head side must fire ``no-regressions``."""
    b = _f(riskTier="transitional")
    h = _f(riskTier="overdue")
    delta = compute_delta([b], [h])
    violations = evaluate_policy(DEFAULT_POLICY, delta)
    assert any(v.rule_id == "no-regressions" and v.action == "block" for v in violations)


def test_default_policy_only_warns_on_new_hndl() -> None:
    """A newly HNDL-exposed finding that is NOT also overdue or weak
    should surface as a warn, never blocking the build."""
    finding = _f(isHndlExposed=True, riskTier="low-risk")
    delta = compute_delta([], [finding])
    violations = evaluate_policy(DEFAULT_POLICY, delta)
    hndl = [v for v in violations if v.rule_id == "warn-new-hndl"]
    assert len(hndl) == 1
    assert hndl[0].action == "warn"
    # And the aggregate must NOT report a block.
    assert not has_block_violations(violations)


def test_clean_diff_produces_no_violations() -> None:
    delta = compute_delta([], [])
    assert evaluate_policy(DEFAULT_POLICY, delta) == []


def test_evaluator_ignores_findings_not_in_matching_bucket() -> None:
    """A rule scoped to ``introduced`` must NOT fire on a finding that
    matches by field but sits in the ``resolved`` bucket."""
    # Baseline had it, current does not -> resolved.
    delta = compute_delta([_f(riskTier="overdue")], [])
    violations = evaluate_policy(DEFAULT_POLICY, delta)
    # 'no-new-overdue' is scoped to 'introduced', so it must NOT fire
    # on a resolved finding.
    assert all(v.rule_id != "no-new-overdue" for v in violations)


# ---------------------------------------------------------------------------
# Dotted-key resolution
# ---------------------------------------------------------------------------

def test_dotted_key_resolves_into_change_records() -> None:
    """``changes.riskTier.to`` must reach into the changed doc's
    ``changes`` sub-object correctly."""
    b = _f(riskTier="low-risk")
    h = _f(riskTier="overdue")
    delta = compute_delta([b], [h])
    violations = evaluate_policy(DEFAULT_POLICY, delta)
    reg = [v for v in violations if v.rule_id == "no-regressions"]
    assert len(reg) == 1
    assert reg[0].field == "changes.riskTier.to"
    assert reg[0].value == "overdue"


def test_violation_serialises_to_camel_case_dict() -> None:
    v = Violation(
        rule_id="r1",
        finding_id="F1",
        reason="Because.",
        field="riskTier",
        value="overdue",
        action="block",
    )
    out = v.to_dict()
    for key in ("ruleId", "findingId", "reason", "field", "value", "action"):
        assert key in out
