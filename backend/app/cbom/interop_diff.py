"""CycloneDX CBOM interop diff.

Compares two CycloneDX 1.6 CBOM documents and reports how their
cryptographic-asset inventories differ. Intended use: diff a Blindspot
CBOM against a CBOM produced by another tool (IBM CBOMkit, sonatype,
Manifest, ...) to demonstrate interoperability.

Design rules:

1. **Pure function, no I/O.** Takes two BOM dicts, returns a dict.
2. **Identity by name + primitive.** Different tools assign different
   ``bom-ref`` values for the same crypto asset, so ``bom-ref`` is
   unreliable as a match key. ``name + primitive`` is the smallest
   stable signature both tools tend to agree on.
3. **Report the change class, not just "different".** A caller looking
   at a diff should know *what kind of* drift they are seeing:
   ``algorithm_changed``, ``parameter_changed``, ``curve_changed``,
   ``tier_changed`` (Blindspot-only annotation).
4. **Never fabricate a match.** If two components share nothing but
   the name, they still match on name; the caller sees the other
   fields diverge and can judge.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable


INTEROP_DIFF_SCHEMA_VERSION = "blindspot.cbom.interop.v1"


# ---------------------------------------------------------------------------
# Component projection
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CryptoAsset:
    """Compact, tool-agnostic projection of one crypto component.

    Only the fields the diff actually keys on. Additional CycloneDX
    fields (evidence, occurrences, properties) are ignored -- diff
    output is the interop signal, not a full component copy.
    """

    bom_ref: str | None
    name: str
    primitive: str | None
    parameter_set_identifier: str | None
    curve: str | None
    mode: str | None
    tier: str | None  # Blindspot-only annotation; may be None on foreign CBOMs.

    @property
    def match_key(self) -> str:
        """Stable, cross-tool identity signature."""
        base = f"{self.name.strip().lower()}|{(self.primitive or '').strip().lower()}"
        return hashlib.sha256(base.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "bomRef": self.bom_ref,
            "name": self.name,
            "primitive": self.primitive,
            "parameterSetIdentifier": self.parameter_set_identifier,
            "curve": self.curve,
            "mode": self.mode,
            "tier": self.tier,
        }


def _extract_crypto_assets(bom: dict[str, Any]) -> list[CryptoAsset]:
    """Return every ``cryptographic-asset`` component in *bom*.

    Tolerant of missing keys: the spec says these fields are optional
    and different tools populate different subsets. We never raise
    on a partial component -- an interop diff on partial data is
    exactly the situation the user wants surfaced, not blocked.
    """
    components = bom.get("components") or []
    if not isinstance(components, list):
        return []

    assets: list[CryptoAsset] = []
    for comp in components:
        if not isinstance(comp, dict):
            continue
        if comp.get("type") != "cryptographic-asset":
            continue
        crypto = comp.get("cryptoProperties") or {}
        if not isinstance(crypto, dict):
            crypto = {}
        algo = crypto.get("algorithmProperties") or {}
        if not isinstance(algo, dict):
            algo = {}

        # Extract Blindspot's optional tier annotation. The upstream
        # tool may not emit this; None is fine.
        tier = _extract_tier(comp)

        assets.append(
            CryptoAsset(
                bom_ref=comp.get("bom-ref") or comp.get("bomRef"),
                name=str(comp.get("name") or ""),
                primitive=_optional_str(algo.get("primitive")),
                parameter_set_identifier=_optional_str(
                    algo.get("parameterSetIdentifier")
                    or algo.get("parameter_set_identifier")
                ),
                curve=_optional_str(algo.get("curve")),
                mode=_optional_str(algo.get("mode")),
                tier=tier,
            )
        )
    return assets


def _extract_tier(component: dict[str, Any]) -> str | None:
    """Look for a Blindspot ``riskTier`` annotation on a component.

    Blindspot records the tier in ``component.properties[]`` as a
    name/value pair (``{"name": "blindspot:riskTier", "value": ...}``);
    older builds may put it directly under
    ``cryptoProperties.riskTier``. Handle both.
    """
    props = component.get("properties") or []
    if isinstance(props, list):
        for p in props:
            if not isinstance(p, dict):
                continue
            name = str(p.get("name") or "").lower()
            if name in {"blindspot:risktier", "risktier", "risk_tier"}:
                val = p.get("value")
                if val is not None:
                    return str(val)
    crypto = component.get("cryptoProperties") or {}
    if isinstance(crypto, dict):
        rt = crypto.get("riskTier") or crypto.get("risk_tier")
        if rt is not None:
            return str(rt)
    return None


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    return s or None


# ---------------------------------------------------------------------------
# Diff result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ChangedAsset:
    """One matched pair whose non-identity fields differ.

    ``changes`` maps each drifted field to ``{"from": base, "to": head}``.
    Meaningful drift only -- fields that agree are not listed.
    """

    base: CryptoAsset
    head: CryptoAsset
    changes: dict[str, dict[str, Any]]

    @property
    def change_classes(self) -> list[str]:
        """High-level buckets any of the drifted fields fall into.

        Kept as a list, not a single value, so a component that drifted
        *both* algorithm and parameter surfaces both -- users looking
        at the interop diff need every signal, not just the strongest.
        """
        classes: list[str] = []
        if "primitive" in self.changes:
            classes.append("algorithm_changed")
        if "parameter_set_identifier" in self.changes:
            classes.append("parameter_changed")
        if "curve" in self.changes:
            classes.append("curve_changed")
        if "mode" in self.changes:
            classes.append("mode_changed")
        if "tier" in self.changes:
            classes.append("tier_changed")
        return classes

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.head.name or self.base.name,
            "base": self.base.to_dict(),
            "head": self.head.to_dict(),
            "changes": self.changes,
            "changeClasses": self.change_classes,
        }


@dataclass(frozen=True)
class InteropDiffResult:
    """Full interop diff, ready to serialise as JSON."""

    added: list[CryptoAsset] = field(default_factory=list)
    removed: list[CryptoAsset] = field(default_factory=list)
    changed: list[ChangedAsset] = field(default_factory=list)
    unchanged_count: int = 0

    def to_dict(
        self,
        *,
        base_meta: dict[str, Any] | None = None,
        head_meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "schemaVersion": INTEROP_DIFF_SCHEMA_VERSION,
            "base": base_meta or {},
            "head": head_meta or {},
            "counts": {
                "added": len(self.added),
                "removed": len(self.removed),
                "changed": len(self.changed),
                "unchanged": self.unchanged_count,
            },
            "added": [a.to_dict() for a in self.added],
            "removed": [a.to_dict() for a in self.removed],
            "changed": [c.to_dict() for c in self.changed],
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_TRACKED_FIELDS: tuple[str, ...] = (
    "primitive",
    "parameter_set_identifier",
    "curve",
    "mode",
    "tier",
)


def compute_interop_diff(
    base_bom: dict[str, Any], head_bom: dict[str, Any]
) -> InteropDiffResult:
    """Diff two CycloneDX 1.6 CBOM documents at the crypto-asset level.

    * ``added``    -- assets present in *head* but not in *base*.
    * ``removed``  -- assets present in *base* but not in *head*.
    * ``changed``  -- matched pairs where at least one tracked field
                       differs (algorithm, parameter, curve, mode, tier).
    * ``unchanged_count`` -- matched pairs with identical tracked fields.

    Matches are resolved by :attr:`CryptoAsset.match_key`
    (``name + primitive`` hashed). Two identical crypto assets on the
    same file will still count separately because the name usually
    encodes enough disambiguation; if that assumption fails, the diff
    surfaces "removed X + added X" pairs which is the correct signal.
    """
    base_assets = _extract_crypto_assets(base_bom)
    head_assets = _extract_crypto_assets(head_bom)

    base_by_key: dict[str, list[CryptoAsset]] = {}
    for a in base_assets:
        base_by_key.setdefault(a.match_key, []).append(a)

    matched: list[tuple[CryptoAsset, CryptoAsset]] = []
    added: list[CryptoAsset] = []

    for cur in head_assets:
        pool = base_by_key.get(cur.match_key)
        if pool:
            base = pool.pop(0)
            matched.append((base, cur))
        else:
            added.append(cur)

    removed: list[CryptoAsset] = []
    for pool in base_by_key.values():
        removed.extend(pool)

    changed: list[ChangedAsset] = []
    unchanged_count = 0
    for base, head in matched:
        diffs = _field_diff(base, head)
        if diffs:
            changed.append(ChangedAsset(base=base, head=head, changes=diffs))
        else:
            unchanged_count += 1

    added.sort(key=_asset_sort_key)
    removed.sort(key=_asset_sort_key)
    changed.sort(key=lambda c: _asset_sort_key(c.head))

    return InteropDiffResult(
        added=added,
        removed=removed,
        changed=changed,
        unchanged_count=unchanged_count,
    )


def _field_diff(base: CryptoAsset, head: CryptoAsset) -> dict[str, dict[str, Any]]:
    diffs: dict[str, dict[str, Any]] = {}
    for name in _TRACKED_FIELDS:
        b = getattr(base, name)
        h = getattr(head, name)
        # A None on one side and a real value on the other is a real
        # drift the operator wants to see. Same-null on both is not.
        if b != h:
            diffs[name] = {"from": b, "to": h}
    return diffs


def _asset_sort_key(a: CryptoAsset) -> tuple[str, str, str, str]:
    return (
        (a.name or "").lower(),
        (a.primitive or ""),
        (a.parameter_set_identifier or ""),
        (a.curve or ""),
    )


def _extract_meta(bom: dict[str, Any]) -> dict[str, Any]:
    """Small provenance strip. Used by the API layer to label each side."""
    meta = bom.get("metadata") or {}
    tools = meta.get("tools") or {}
    tool_components: list[dict[str, Any]] = []
    if isinstance(tools, dict):
        tool_components = tools.get("components") or []
    elif isinstance(tools, list):
        tool_components = tools
    tool_names: list[str] = []
    for t in tool_components:
        if isinstance(t, dict) and t.get("name"):
            tool_names.append(str(t["name"]))

    return {
        "specVersion": bom.get("specVersion") or bom.get("bomFormat"),
        "timestamp": meta.get("timestamp"),
        "componentCount": len(bom.get("components") or []),
        "cryptoAssetCount": sum(
            1
            for c in (bom.get("components") or [])
            if isinstance(c, dict) and c.get("type") == "cryptographic-asset"
        ),
        "tools": tool_names,
    }


__all__ = [
    "INTEROP_DIFF_SCHEMA_VERSION",
    "ChangedAsset",
    "CryptoAsset",
    "InteropDiffResult",
    "compute_interop_diff",
    "_extract_meta",
]
