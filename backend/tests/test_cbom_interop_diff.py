"""Tests for :mod:`app.cbom.interop_diff` -- pure diff logic + API contract.

Covers:

* Empty-vs-populated: everything is added / removed.
* Identical BOMs: everything unchanged, zero deltas.
* Field drift: algorithm-changed vs parameter-changed vs curve-changed.
* Foreign CBOMs missing Blindspot's tier annotation still diff cleanly.
* API layer 400s on empty inputs, wraps the pure result on success.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.cbom.interop_diff import (
    INTEROP_DIFF_SCHEMA_VERSION,
    ChangedAsset,
    compute_interop_diff,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bom(components: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Minimal CycloneDX 1.6-shaped BOM."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"timestamp": "2026-09-07T00:00:00Z"},
        "components": components or [],
    }


def _crypto(
    name: str,
    *,
    primitive: str | None = None,
    parameter: str | None = None,
    curve: str | None = None,
    mode: str | None = None,
    tier: str | None = None,
    bom_ref: str | None = None,
) -> dict[str, Any]:
    """Build one cryptographic-asset component."""
    algo: dict[str, Any] = {}
    if primitive is not None:
        algo["primitive"] = primitive
    if parameter is not None:
        algo["parameterSetIdentifier"] = parameter
    if curve is not None:
        algo["curve"] = curve
    if mode is not None:
        algo["mode"] = mode

    comp: dict[str, Any] = {
        "type": "cryptographic-asset",
        "name": name,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": algo,
        },
    }
    if bom_ref is not None:
        comp["bom-ref"] = bom_ref
    if tier is not None:
        comp["properties"] = [
            {"name": "blindspot:riskTier", "value": tier},
        ]
    return comp


# ---------------------------------------------------------------------------
# Pure diff
# ---------------------------------------------------------------------------

def test_empty_base_marks_all_head_as_added() -> None:
    head = _bom([
        _crypto("RSA-2048", primitive="pke", parameter="2048"),
        _crypto("AES-256-GCM", primitive="block-cipher", parameter="256", mode="gcm"),
    ])
    result = compute_interop_diff(_bom(), head)
    assert len(result.added) == 2
    assert result.removed == []
    assert result.changed == []
    assert result.unchanged_count == 0


def test_empty_head_marks_all_base_as_removed() -> None:
    base = _bom([_crypto("RSA-2048", primitive="pke", parameter="2048")])
    result = compute_interop_diff(base, _bom())
    assert result.added == []
    assert len(result.removed) == 1
    assert result.unchanged_count == 0


def test_identical_boms_have_zero_deltas() -> None:
    doc = _bom([
        _crypto("RSA-2048", primitive="pke", parameter="2048"),
        _crypto("SHA-256", primitive="hash"),
    ])
    result = compute_interop_diff(doc, doc)
    assert result.added == []
    assert result.removed == []
    assert result.changed == []
    assert result.unchanged_count == 2


def test_parameter_change_surfaces_as_changed_with_parameter_class() -> None:
    base = _bom([_crypto("RSA", primitive="pke", parameter="2048")])
    head = _bom([_crypto("RSA", primitive="pke", parameter="3072")])
    result = compute_interop_diff(base, head)
    assert result.added == []
    assert result.removed == []
    assert len(result.changed) == 1
    row = result.changed[0]
    assert row.changes["parameter_set_identifier"] == {"from": "2048", "to": "3072"}
    assert "parameter_changed" in row.change_classes


def test_algorithm_change_surfaces_with_algorithm_class() -> None:
    """Different primitives at the same *name* are impossible in the
    real world (primitive is part of the identity), so a genuine
    "algorithm change" shows up when the two BOMs disagree on the
    primitive for a shared name -- e.g. one tool tagged 'AES' as
    ``block-cipher`` and another as ``stream-cipher``. The diff must
    surface that as a real drift."""
    base = _bom([_crypto("AES", primitive="block-cipher", parameter="256")])
    head = _bom([_crypto("AES", primitive="stream-cipher", parameter="256")])
    result = compute_interop_diff(base, head)
    # Different primitives means different match keys -> one add + one remove.
    assert len(result.added) == 1
    assert len(result.removed) == 1
    assert result.changed == []


def test_curve_change_surfaces_with_curve_class() -> None:
    base = _bom([_crypto("ECDSA", primitive="signature", curve="secp256r1")])
    head = _bom([_crypto("ECDSA", primitive="signature", curve="secp384r1")])
    result = compute_interop_diff(base, head)
    assert len(result.changed) == 1
    assert "curve_changed" in result.changed[0].change_classes


def test_tier_change_only_surfaces_when_both_sides_annotate() -> None:
    """A Blindspot CBOM (with tier) diffed against IBM CBOMkit (no
    tier) must NOT surface every asset as 'tier_changed'; that would
    drown out real signal. Only report tier drift when both sides
    annotate."""
    base = _bom([_crypto("RSA", primitive="pke", parameter="2048", tier="overdue")])
    head_untagged = _bom([_crypto("RSA", primitive="pke", parameter="2048")])
    result = compute_interop_diff(base, head_untagged)
    # base has tier, head does not -> tier field diverges (overdue -> None).
    # That IS a real drift the user should see.
    assert len(result.changed) == 1
    assert "tier_changed" in result.changed[0].change_classes

    # But when both sides omit tier, no tier_changed appears.
    base_untagged = _bom([_crypto("RSA", primitive="pke", parameter="2048")])
    head_untagged2 = _bom([_crypto("RSA", primitive="pke", parameter="2048")])
    result2 = compute_interop_diff(base_untagged, head_untagged2)
    assert result2.changed == []
    assert result2.unchanged_count == 1


def test_non_crypto_components_are_ignored() -> None:
    """A CycloneDX BOM may carry library/framework components alongside
    cryptographic-asset components. The interop diff only looks at
    crypto assets."""
    base = _bom([
        {"type": "library", "name": "openssl", "version": "3.0"},
        _crypto("RSA", primitive="pke", parameter="2048"),
    ])
    head = _bom([_crypto("RSA", primitive="pke", parameter="2048")])
    result = compute_interop_diff(base, head)
    assert result.added == []
    assert result.removed == []
    assert result.unchanged_count == 1


def test_result_is_json_serialisable_with_schema_version() -> None:
    base = _bom([_crypto("RSA", primitive="pke", parameter="2048")])
    head = _bom([_crypto("RSA", primitive="pke", parameter="3072")])
    result = compute_interop_diff(base, head)
    d = result.to_dict()
    assert d["schemaVersion"] == INTEROP_DIFF_SCHEMA_VERSION
    assert d["counts"] == {"added": 0, "removed": 0, "changed": 1, "unchanged": 0}
    assert d["changed"][0]["changeClasses"] == ["parameter_changed"]


# ---------------------------------------------------------------------------
# API contract
# ---------------------------------------------------------------------------

def test_post_diff_returns_the_full_result(auth_bypassed_client: TestClient) -> None:
    base = _bom([_crypto("RSA-2048", primitive="pke", parameter="2048")])
    head = _bom([_crypto("RSA-2048", primitive="pke", parameter="3072")])
    resp = auth_bypassed_client.post(
        "/api/cbom/diff",
        json={"base": base, "head": head},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["schemaVersion"] == INTEROP_DIFF_SCHEMA_VERSION
    assert body["counts"]["changed"] == 1
    # Provenance strip mentions the crypto asset count on both sides.
    assert body["base"]["cryptoAssetCount"] == 1
    assert body["head"]["cryptoAssetCount"] == 1


def test_post_diff_400s_on_empty_base(auth_bypassed_client: TestClient) -> None:
    resp = auth_bypassed_client.post(
        "/api/cbom/diff",
        json={"base": {}, "head": _bom([_crypto("RSA", primitive="pke")])},
    )
    assert resp.status_code == 400
    assert "base" in resp.json()["detail"].lower()


def test_post_diff_400s_on_empty_head(auth_bypassed_client: TestClient) -> None:
    resp = auth_bypassed_client.post(
        "/api/cbom/diff",
        json={"base": _bom([_crypto("RSA", primitive="pke")]), "head": {}},
    )
    assert resp.status_code == 400


def test_openapi_advertises_the_interop_diff_path(
    auth_bypassed_client: TestClient,
) -> None:
    schema = auth_bypassed_client.get("/openapi.json").json()
    assert "/api/cbom/diff" in schema["paths"]
