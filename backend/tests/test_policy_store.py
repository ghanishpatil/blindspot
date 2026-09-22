"""Tests for :mod:`app.policy.store`.

Contract:

* A fresh store returns :data:`DEFAULT_POLICY`; :meth:`has_override` is False.
* ``save()`` validates, so a malformed dict never touches disk.
* ``save()`` is atomic: partial writes never leave the on-disk file in
  a broken shape (we simulate that indirectly via a schema round-trip).
* ``reset()`` deletes the override and is idempotent.
* Round-trip: ``get() == DEFAULT_POLICY`` after ``save(...)`` + ``reset()``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.cli.policy import DEFAULT_POLICY, PolicyError, policy_to_dict
from app.policy.store import ACTIVE_POLICY_FILENAME, PolicyStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def store(tmp_path: Path) -> PolicyStore:
    """A store rooted at a fresh temp dir per test."""
    return PolicyStore(directory=tmp_path / "policy-store")


def _custom_policy_dict() -> dict:
    """A minimal but valid non-default policy for save/get tests."""
    return {
        "schemaVersion": "blindspot.policy.v1",
        "name": "custom",
        "rules": [
            {
                "id": "no-new-anything",
                "on": "introduced",
                "match": {"isQuantumSensitive": True},
                "action": "block",
            }
        ],
    }


# ---------------------------------------------------------------------------
# get() -- default behaviour
# ---------------------------------------------------------------------------

def test_fresh_store_returns_default_policy(store: PolicyStore) -> None:
    assert store.get() == DEFAULT_POLICY
    assert store.has_override() is False


def test_fresh_store_creates_no_files(store: PolicyStore) -> None:
    """Reading must not silently create the override file."""
    _ = store.get()
    assert not store.path.exists()


# ---------------------------------------------------------------------------
# save() -- validation + persistence
# ---------------------------------------------------------------------------

def test_save_persists_and_round_trips(store: PolicyStore) -> None:
    saved = store.save(_custom_policy_dict())
    assert store.has_override() is True

    reread = store.get()
    assert reread == saved
    assert reread.name == "custom"
    assert len(reread.rules) == 1
    assert reread.rules[0].rule_id == "no-new-anything"


def test_save_writes_canonical_dict_on_disk(store: PolicyStore) -> None:
    """The on-disk file must match ``policy_to_dict(saved)`` byte-shape.
    The API's PUT endpoint promises a round-trip; the store is the
    other half of that contract."""
    saved = store.save(_custom_policy_dict())
    raw = json.loads(store.path.read_text(encoding="utf-8"))
    assert raw == policy_to_dict(saved)


def test_save_rejects_malformed_dict_and_does_not_write(
    store: PolicyStore,
) -> None:
    """A schema failure MUST be visible to the caller *and* leave the
    on-disk state untouched. This is the honesty guardrail: no
    silent partial writes."""
    bad_dict = {
        "schemaVersion": "blindspot.policy.v1",
        "name": "bad",
        "rules": [
            {
                "id": "",  # empty id -> parse_policy_dict rejects.
                "on": "introduced",
                "match": {"isQuantumSensitive": True},
                "action": "block",
            }
        ],
    }
    with pytest.raises(PolicyError):
        store.save(bad_dict)
    assert not store.path.exists()


def test_save_overwrites_previous_override(store: PolicyStore) -> None:
    """Second save must replace the first, not append or leak state."""
    store.save(_custom_policy_dict())
    replacement = _custom_policy_dict()
    replacement["name"] = "custom-v2"
    replacement["rules"][0]["id"] = "no-new-anything-v2"
    saved = store.save(replacement)
    assert saved.name == "custom-v2"
    assert saved.rules[0].rule_id == "no-new-anything-v2"


# ---------------------------------------------------------------------------
# reset() -- lifecycle
# ---------------------------------------------------------------------------

def test_reset_reverts_to_default(store: PolicyStore) -> None:
    store.save(_custom_policy_dict())
    reverted = store.reset()
    assert reverted == DEFAULT_POLICY
    assert store.has_override() is False
    assert not store.path.exists()


def test_reset_is_idempotent(store: PolicyStore) -> None:
    """Resetting a fresh store must not raise -- callers may retry."""
    reverted = store.reset()
    assert reverted == DEFAULT_POLICY
    # Second call also succeeds.
    store.reset()
    assert store.has_override() is False


# ---------------------------------------------------------------------------
# Corruption / safety
# ---------------------------------------------------------------------------

def test_get_raises_policy_error_when_file_is_corrupt(store: PolicyStore) -> None:
    """A hand-edited invalid policy file must NOT be masked as the
    default -- the operator has to see the corruption."""
    store.directory.mkdir(parents=True, exist_ok=True)
    (store.directory / ACTIVE_POLICY_FILENAME).write_text(
        "{not valid json", encoding="utf-8"
    )
    with pytest.raises(PolicyError):
        store.get()


def test_get_raises_policy_error_when_file_violates_schema(
    store: PolicyStore,
) -> None:
    """JSON parses but the schema is wrong -- still visible."""
    store.directory.mkdir(parents=True, exist_ok=True)
    (store.directory / ACTIVE_POLICY_FILENAME).write_text(
        json.dumps({"rules": "not a list"}), encoding="utf-8"
    )
    with pytest.raises(PolicyError):
        store.get()


def test_directory_is_lazily_created(tmp_path: Path) -> None:
    """The store must not require its directory to pre-exist -- the
    scan pipeline creates artefacts on first use, and the policy
    store shares that directory."""
    missing = tmp_path / "does-not-exist-yet"
    assert not missing.exists()
    store = PolicyStore(directory=missing)
    store.save(_custom_policy_dict())
    assert missing.exists()
    assert store.path.is_file()
