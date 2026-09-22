"""Pure graph-construction module.

``build_dependency_graph(findings)`` takes a list of serialised
finding dicts (the shape ``findings.json`` on disk uses) and returns
:class:`GraphResult` -- nodes + edges + tier rollups + honest
provenance -- ready to be JSON-serialised as an API response.

No I/O, no filesystem, no scanning. This module is a *view* of the
findings, not a new source of truth.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable


GRAPH_SCHEMA_VERSION = "blindspot.graph.v1"


# Tier ordering, worst-first. Used to bubble the "worst tier at this
# node" for colour coding.
_TIER_RANK: dict[str, int] = {
    "overdue": 3,
    "transitional": 2,
    "low-risk": 1,
    "unknown": 0,
}


def _worse_tier(a: str | None, b: str | None) -> str | None:
    """Return whichever tier has the higher rank. None-tolerant."""
    if a is None:
        return b
    if b is None:
        return a
    return a if _TIER_RANK.get(a, 0) >= _TIER_RANK.get(b, 0) else b


@dataclass(frozen=True)
class GraphNode:
    """One node on the dependency graph."""

    id: str
    kind: str  # "file" | "algorithm"
    label: str
    tier: str | None
    finding_count: int
    blast_radius: int  # only meaningful on file nodes; 0 on algorithm nodes
    # Optional fields carried through for tooltip / drill-down.
    algorithm: str | None = None
    parameter: str | None = None
    curve: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "tier": self.tier,
            "findingCount": self.finding_count,
            "blastRadius": self.blast_radius,
            "algorithm": self.algorithm,
            "parameter": self.parameter,
            "curve": self.curve,
        }


@dataclass(frozen=True)
class GraphEdge:
    """One edge, always from a file node to an algorithm node."""

    source: str  # file node id
    target: str  # algorithm node id
    finding_id: str | None
    tier: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "findingId": self.finding_id,
            "tier": self.tier,
        }


@dataclass(frozen=True)
class GraphResult:
    """Full graph: nodes + edges + summary rollups."""

    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    files_by_tier: dict[str, int] = field(default_factory=dict)
    algorithms_by_tier: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": GRAPH_SCHEMA_VERSION,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "counts": {
                "files": sum(1 for n in self.nodes if n.kind == "file"),
                "algorithms": sum(1 for n in self.nodes if n.kind == "algorithm"),
                "edges": len(self.edges),
                "filesByTier": dict(self.files_by_tier),
                "algorithmsByTier": dict(self.algorithms_by_tier),
            },
        }


# ---------------------------------------------------------------------------
# Node identity helpers
# ---------------------------------------------------------------------------

def _file_id(path: str) -> str:
    """Stable, short id for a file node. SHA-256 of the path so it
    survives odd characters in filenames."""
    return "f:" + hashlib.sha256(path.encode("utf-8")).hexdigest()[:16]


def _algorithm_id(algorithm: str, parameter: str | None, curve: str | None) -> str:
    """Stable id for an algorithm node keyed on the full identity."""
    key = f"{algorithm}|{parameter or ''}|{curve or ''}".encode("utf-8")
    return "a:" + hashlib.sha256(key).hexdigest()[:16]


def _extract_file_path(finding: dict[str, Any]) -> str | None:
    fp = finding.get("filePath") or finding.get("file_path")
    if fp:
        return str(fp)
    detail = finding.get("evidenceDetail")
    if isinstance(detail, dict):
        p = detail.get("filePath") or detail.get("file_path")
        if p:
            return str(p)
    ev = finding.get("evidence")
    if isinstance(ev, dict):
        p = ev.get("filePath") or ev.get("file_path")
        if p:
            return str(p)
    return None


def _algorithm_label(algorithm: str, parameter: str | None, curve: str | None) -> str:
    if parameter:
        return f"{algorithm}-{parameter}"
    if curve:
        return f"{algorithm}/{curve}"
    return algorithm


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_dependency_graph(
    findings: Iterable[dict[str, Any]],
) -> GraphResult:
    """Build the bipartite graph.

    Findings without a resolvable ``filePath`` or ``algorithm`` are
    skipped; every skipped finding is a genuine data gap the operator
    should see in the roadmap panel, but has no rendering meaning on
    the graph.
    """
    findings_list = list(findings)

    # Track worst tier + count per file, per algorithm.
    file_stats: dict[str, dict[str, Any]] = {}
    algo_stats: dict[str, dict[str, Any]] = {}
    edges: list[GraphEdge] = []

    for f in findings_list:
        file_path = _extract_file_path(f)
        algorithm = f.get("algorithm")
        if not file_path or not algorithm:
            continue

        parameter = f.get("parameter")
        curve = f.get("curve")
        tier = f.get("riskTier") or f.get("risk_tier")
        finding_id = f.get("id")

        fid = _file_id(file_path)
        aid = _algorithm_id(str(algorithm), parameter, curve)

        # Bump file stats.
        fs = file_stats.setdefault(
            fid,
            {"path": file_path, "count": 0, "tier": None, "algorithms": set()},
        )
        fs["count"] += 1
        fs["tier"] = _worse_tier(fs["tier"], tier)
        fs["algorithms"].add(aid)

        # Bump algorithm stats.
        as_ = algo_stats.setdefault(
            aid,
            {
                "algorithm": str(algorithm),
                "parameter": parameter,
                "curve": curve,
                "count": 0,
                "tier": None,
            },
        )
        as_["count"] += 1
        as_["tier"] = _worse_tier(as_["tier"], tier)

        edges.append(
            GraphEdge(
                source=fid,
                target=aid,
                finding_id=str(finding_id) if finding_id is not None else None,
                tier=tier,
            )
        )

    # Materialise nodes with stable sort. File blast radius = distinct
    # algorithms it touches (a stronger signal than raw finding count,
    # and matches the "how much of your crypto surface would ripple if
    # this file changed" reading of blast radius).
    file_nodes = [
        GraphNode(
            id=fid,
            kind="file",
            label=fs["path"],
            tier=fs["tier"],
            finding_count=fs["count"],
            blast_radius=len(fs["algorithms"]),
        )
        for fid, fs in sorted(file_stats.items(), key=lambda kv: kv[1]["path"])
    ]

    algorithm_nodes = [
        GraphNode(
            id=aid,
            kind="algorithm",
            label=_algorithm_label(as_["algorithm"], as_["parameter"], as_["curve"]),
            tier=as_["tier"],
            finding_count=as_["count"],
            blast_radius=0,
            algorithm=as_["algorithm"],
            parameter=as_["parameter"],
            curve=as_["curve"],
        )
        for aid, as_ in sorted(
            algo_stats.items(), key=lambda kv: (kv[1]["algorithm"], kv[1]["parameter"] or "")
        )
    ]

    # Deterministic edge order matches the sort order of the nodes,
    # then falls back to finding id -- so identical scans always
    # produce identical graph JSON (matters for caching & tests).
    edges.sort(
        key=lambda e: (e.source, e.target, e.finding_id or "")
    )

    files_by_tier: dict[str, int] = {}
    for n in file_nodes:
        t = n.tier or "unknown"
        files_by_tier[t] = files_by_tier.get(t, 0) + 1

    algorithms_by_tier: dict[str, int] = {}
    for n in algorithm_nodes:
        t = n.tier or "unknown"
        algorithms_by_tier[t] = algorithms_by_tier.get(t, 0) + 1

    return GraphResult(
        nodes=file_nodes + algorithm_nodes,
        edges=edges,
        files_by_tier=files_by_tier,
        algorithms_by_tier=algorithms_by_tier,
    )


__all__ = [
    "GRAPH_SCHEMA_VERSION",
    "GraphEdge",
    "GraphNode",
    "GraphResult",
    "build_dependency_graph",
]
