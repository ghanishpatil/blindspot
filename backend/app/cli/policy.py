"""Policy loader + evaluator for ``blindspot-scan gate``.

Loads a small deterministic policy JSON, evaluates it against a
:class:`~app.cli.diff.DeltaResult`, and produces a list of violations.
The CLI turns any ``block``-severity violation into exit code 2.

Design:

* **Deterministic.** No regex, no arithmetic, no user-supplied Python.
  Every rule is an equality match on a dotted-key path against a
  finding / delta document.
* **Bucket-scoped.** Each rule targets one of ``introduced`` /
  ``resolved`` / ``changed`` / ``all``. That keeps rule intent
  self-documenting.
* **Two severities.** ``block`` (contributes to exit 2) and ``warn``
  (logged for visibility, never blocks). Only ``block`` fires the
  guardrail.

Default policy (embedded in code) matches the SPEC:

  ``no-new-weak-now``   -> block any introduced finding with
                            ``isCurrentlyWeak: true``.
  ``no-new-overdue``    -> block any introduced finding with
                            ``riskTier: overdue``.
  ``no-regressions``    -> block any changed finding whose
                            ``changes.riskTier.to`` equals ``overdue``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from app.cli.diff import DeltaResult


POLICY_SCHEMA_VERSION = "blindspot.policy.v1"

_VALID_BUCKETS: set[str] = {"introduced", "resolved", "changed", "all"}
_VALID_ACTIONS: set[str] = {"block", "warn"}


class PolicyError(ValueError):
    """Raised when a policy file is malformed. Bubbles up to exit 3."""


@dataclass(frozen=True)
class PolicyRule:
    """One equality rule inside a policy document."""

    rule_id: str
    on: str
    match: dict[str, Any]
    action: str


@dataclass(frozen=True)
class Policy:
    """A parsed, validated policy document."""

    name: str
    rules: list[PolicyRule]


@dataclass(frozen=True)
class Violation:
    """One finding-level violation fired by a rule."""

    rule_id: str
    finding_id: str | None
    reason: str
    field: str | None
    value: Any
    action: str  # "block" or "warn"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule_id,
            "findingId": self.finding_id,
            "reason": self.reason,
            "field": self.field,
            "value": self.value,
            "action": self.action,
        }


# ---------------------------------------------------------------------------
# Default policy -- baked in so ``--policy`` is optional.
# ---------------------------------------------------------------------------

DEFAULT_POLICY: Policy = Policy(
    name="blindspot-default",
    rules=[
        PolicyRule(
            rule_id="no-new-weak-now",
            on="introduced",
            match={"isCurrentlyWeak": True},
            action="block",
        ),
        PolicyRule(
            rule_id="no-new-overdue",
            on="introduced",
            match={"riskTier": "overdue"},
            action="block",
        ),
        PolicyRule(
            rule_id="no-regressions",
            on="changed",
            match={"changes.riskTier.to": "overdue"},
            action="block",
        ),
        PolicyRule(
            rule_id="warn-new-hndl",
            on="introduced",
            match={"isHndlExposed": True},
            action="warn",
        ),
    ],
)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_policy(path: Path | str | None) -> Policy:
    """Load a policy from *path*, or return :data:`DEFAULT_POLICY`.

    ``path=None`` returns the default. A missing file, malformed JSON,
    or an unknown ``action`` / ``on`` value raises :class:`PolicyError`
    -- the CLI converts that to exit 3 (bad arguments).

    We validate strictly on load rather than lazily on evaluation so a
    typo in a CI config fails immediately, not later on a real diff.
    """
    if path is None:
        return DEFAULT_POLICY

    path = Path(path).expanduser()
    if not path.is_file():
        raise PolicyError(f"policy file not found: {path}")

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"policy file is not valid JSON: {exc}") from exc

    return _parse_policy(raw)


def _parse_policy(raw: dict[str, Any]) -> Policy:
    """Validate + build a :class:`Policy` from a raw dict."""
    if not isinstance(raw, dict):
        raise PolicyError("policy root must be a JSON object")
    if raw.get("schemaVersion") not in {POLICY_SCHEMA_VERSION, None}:
        raise PolicyError(
            f"unsupported policy schemaVersion: {raw.get('schemaVersion')!r}; "
            f"this CLI understands {POLICY_SCHEMA_VERSION!r}"
        )
    name = raw.get("name") or "unnamed"
    rules_raw = raw.get("rules") or []
    if not isinstance(rules_raw, list):
        raise PolicyError("policy.rules must be a list")

    rules: list[PolicyRule] = []
    for i, item in enumerate(rules_raw):
        if not isinstance(item, dict):
            raise PolicyError(f"policy.rules[{i}] must be an object")
        rule_id = item.get("id")
        on = item.get("on")
        match = item.get("match")
        action = item.get("action")
        if not isinstance(rule_id, str) or not rule_id:
            raise PolicyError(f"policy.rules[{i}].id must be a non-empty string")
        if on not in _VALID_BUCKETS:
            raise PolicyError(
                f"policy.rules[{i}].on must be one of {sorted(_VALID_BUCKETS)}, got {on!r}"
            )
        if not isinstance(match, dict) or not match:
            raise PolicyError(f"policy.rules[{i}].match must be a non-empty object")
        if action not in _VALID_ACTIONS:
            raise PolicyError(
                f"policy.rules[{i}].action must be one of {sorted(_VALID_ACTIONS)}, got {action!r}"
            )
        rules.append(
            PolicyRule(rule_id=rule_id, on=on, match=match, action=action)
        )

    return Policy(name=name, rules=rules)


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------

def evaluate_policy(
    policy: Policy,
    delta: DeltaResult,
) -> list[Violation]:
    """Return every violation the policy fires against *delta*.

    Order is stable: rules iterate in policy order; findings iterate in
    the delta's own sort order (which is already deterministic).
    """
    violations: list[Violation] = []
    buckets_by_name: dict[str, list[dict[str, Any]]] = {
        "introduced": delta.introduced,
        "resolved": delta.resolved,
        "changed": delta.changed,
    }

    for rule in policy.rules:
        docs = _docs_for_bucket(rule.on, buckets_by_name)
        for doc in docs:
            if _matches(doc, rule.match):
                # Pick the first matched (field, value) pair for the
                # reason string -- the exact input that fired the rule.
                first_key = next(iter(rule.match))
                first_val = rule.match[first_key]
                violations.append(
                    Violation(
                        rule_id=rule.rule_id,
                        finding_id=str(doc.get("id")) if doc.get("id") else None,
                        reason=_reason_for(rule, first_key, first_val),
                        field=first_key,
                        value=first_val,
                        action=rule.action,
                    )
                )

    return violations


def _docs_for_bucket(
    on: str, buckets_by_name: dict[str, list[dict[str, Any]]]
) -> Iterable[dict[str, Any]]:
    """Return the finding docs the rule should walk."""
    if on == "all":
        for bucket in buckets_by_name.values():
            yield from bucket
        return
    yield from buckets_by_name.get(on, [])


def _matches(doc: dict[str, Any], match: dict[str, Any]) -> bool:
    """Every dotted-key in *match* must resolve to the specified value."""
    for dotted_key, expected in match.items():
        actual = _resolve_dotted(doc, dotted_key)
        if actual != expected:
            return False
    return True


def _resolve_dotted(doc: dict[str, Any], dotted_key: str) -> Any:
    """Follow ``a.b.c`` into *doc*. Missing intermediates return None."""
    cur: Any = doc
    for part in dotted_key.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _reason_for(rule: PolicyRule, key: str, value: Any) -> str:
    """One-line human reason string attached to each violation.

    Named to match the rule intent -- the CI comment reader should not
    need to open the policy JSON to understand what fired.
    """
    if rule.rule_id == "no-new-weak-now":
        return "New finding is currently weak."
    if rule.rule_id == "no-new-overdue":
        return "New finding is quantum-migration overdue."
    if rule.rule_id == "no-regressions":
        return "Existing finding regressed to overdue."
    if rule.rule_id == "warn-new-hndl":
        return "New finding is HNDL-exposed (harvest-now-decrypt-later)."
    return f"Rule matched: {key}={value!r}"


def has_block_violations(violations: Iterable[Violation]) -> bool:
    """True when at least one violation is ``action == 'block'``."""
    return any(v.action == "block" for v in violations)


# ---------------------------------------------------------------------------
# Public dict <-> Policy conversion (used by the REST API layer)
# ---------------------------------------------------------------------------

def parse_policy_dict(raw: dict[str, Any]) -> Policy:
    """Public wrapper around :func:`_parse_policy` for the API layer.

    Exposes the same strict validation the CLI uses on disk, without
    the file-read step -- the API receives the policy in the request
    body already parsed as JSON. Raises :class:`PolicyError` on any
    schema violation so the endpoint can respond with HTTP 400.
    """
    return _parse_policy(raw)


def policy_to_dict(policy: Policy) -> dict[str, Any]:
    """Serialise a :class:`Policy` back to the on-disk JSON shape.

    Round-trip guarantee: ``parse_policy_dict(policy_to_dict(p)) == p``
    for any valid *p*. This is what the ``GET /api/policy`` endpoint
    returns and what the frontend policy editor round-trips.
    """
    return {
        "schemaVersion": POLICY_SCHEMA_VERSION,
        "name": policy.name,
        "rules": [
            {
                "id": r.rule_id,
                "on": r.on,
                "match": dict(r.match),
                "action": r.action,
            }
            for r in policy.rules
        ],
    }


__all__ = [
    "DEFAULT_POLICY",
    "POLICY_SCHEMA_VERSION",
    "Policy",
    "PolicyError",
    "PolicyRule",
    "Violation",
    "evaluate_policy",
    "has_block_violations",
    "load_policy",
    "parse_policy_dict",
    "policy_to_dict",
]
