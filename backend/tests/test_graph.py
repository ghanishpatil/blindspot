"""Tests for :mod:`app.graph.builder` + :mod:`app.api.graph`.

Locks down:

* Bipartite structure: nodes split into kind='file' + kind='algorithm'.
* Edges only ever go file -> algorithm.
* Worst-tier bubbling: a file with one overdue + one low-risk finding
  is tier=overdue.
* Blast radius on a file = distinct algorithm identities it touches.
* Determinism: identical input, byte-identical output.
* API 404 when scan is missing / not owned.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.graph.builder import (
    GRAPH_SCHEMA_VERSION,
    build_dependency_graph,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _finding(
    id_: str,
    *,
    file_path: str,
    algorithm: str,
    parameter: str | None = None,
    curve: str | None = None,
    tier: str = "overdue",
) -> dict[str, Any]:
    return {
        "id": id_,
        "filePath": file_path,
        "algorithm": algorithm,
        "parameter": parameter,
        "curve": curve,
        "riskTier": tier,
    }


def _seed_scan(
    artifacts_dir: Path,
    scan_id: str,
    findings: list[dict[str, Any]],
    project_id: str = "demo",
    owner_id: str | None = "demo-user",
) -> None:
    scan_dir = artifacts_dir / project_id / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    record: dict[str, Any] = {
        "id": scan_id,
        "projectId": project_id,
        "startedAt": "2026-09-01T00:00:00Z",
        "completedAt": "2026-09-01T00:00:05Z",
        "status": "success",
        "summary": {},
    }
    if owner_id is not None:
        record["ownerId"] = owner_id
    (scan_dir / "scan.json").write_text(json.dumps(record), encoding="utf-8")
    (scan_dir / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
    (scan_dir / "cbom.json").write_text("{}", encoding="utf-8")


@pytest.fixture
def artifacts_dir() -> Path:
    get_settings.cache_clear()
    return get_settings().artifacts


# ---------------------------------------------------------------------------
# Pure builder
# ---------------------------------------------------------------------------

def test_empty_findings_yield_empty_graph() -> None:
    g = build_dependency_graph([])
    assert g.nodes == []
    assert g.edges == []


def test_one_finding_yields_one_file_one_algorithm_one_edge() -> None:
    g = build_dependency_graph(
        [_finding("f1", file_path="a.py", algorithm="RSA", parameter="2048")]
    )
    kinds = [n.kind for n in g.nodes]
    assert kinds.count("file") == 1
    assert kinds.count("algorithm") == 1
    assert len(g.edges) == 1
    # Edge goes file -> algorithm.
    src_kind = next(n.kind for n in g.nodes if n.id == g.edges[0].source)
    tgt_kind = next(n.kind for n in g.nodes if n.id == g.edges[0].target)
    assert src_kind == "file"
    assert tgt_kind == "algorithm"


def test_same_algorithm_across_files_shares_one_algorithm_node() -> None:
    g = build_dependency_graph(
        [
            _finding("f1", file_path="a.py", algorithm="RSA", parameter="2048"),
            _finding("f2", file_path="b.py", algorithm="RSA", parameter="2048"),
        ]
    )
    algo_nodes = [n for n in g.nodes if n.kind == "algorithm"]
    file_nodes = [n for n in g.nodes if n.kind == "file"]
    assert len(algo_nodes) == 1
    assert algo_nodes[0].finding_count == 2
    assert len(file_nodes) == 2


def test_worst_tier_bubbles_to_the_node() -> None:
    g = build_dependency_graph(
        [
            _finding("f1", file_path="a.py", algorithm="RSA", parameter="2048", tier="low-risk"),
            _finding("f2", file_path="a.py", algorithm="MD5", tier="overdue"),
        ]
    )
    file_node = next(n for n in g.nodes if n.kind == "file")
    assert file_node.tier == "overdue"


def test_blast_radius_counts_distinct_algorithms_per_file() -> None:
    """A file that touches RSA-1024 + RSA-2048 + MD5 has blast_radius=3.
    Two identical RSA-2048 findings do NOT double-count."""
    g = build_dependency_graph(
        [
            _finding("f1", file_path="a.py", algorithm="RSA", parameter="1024"),
            _finding("f2", file_path="a.py", algorithm="RSA", parameter="2048"),
            _finding("f3", file_path="a.py", algorithm="RSA", parameter="2048"),
            _finding("f4", file_path="a.py", algorithm="MD5"),
        ]
    )
    file_node = next(n for n in g.nodes if n.kind == "file")
    assert file_node.blast_radius == 3
    assert file_node.finding_count == 4


def test_findings_without_file_path_or_algorithm_are_skipped() -> None:
    g = build_dependency_graph(
        [
            {"id": "no-file", "algorithm": "RSA"},
            {"id": "no-algo", "filePath": "x.py"},
            _finding("good", file_path="a.py", algorithm="RSA", parameter="2048"),
        ]
    )
    assert len(g.edges) == 1


def test_evidence_detail_file_path_is_a_valid_fallback() -> None:
    """Production findings carry ``filePath`` at both top level and
    ``evidenceDetail.filePath``. The builder must accept either."""
    g = build_dependency_graph(
        [
            {
                "id": "f1",
                "algorithm": "RSA",
                "parameter": "2048",
                "evidenceDetail": {"filePath": "a.py"},
                "riskTier": "overdue",
            }
        ]
    )
    assert any(n.kind == "file" and n.label == "a.py" for n in g.nodes)


def test_graph_output_is_deterministic() -> None:
    findings = [
        _finding("f1", file_path="b.py", algorithm="RSA", parameter="2048"),
        _finding("f2", file_path="a.py", algorithm="MD5"),
        _finding("f3", file_path="a.py", algorithm="RSA", parameter="2048"),
    ]
    g1 = build_dependency_graph(findings)
    g2 = build_dependency_graph(list(findings))  # fresh iterable
    assert g1.to_dict() == g2.to_dict()


def test_to_dict_carries_schema_version_and_counts() -> None:
    g = build_dependency_graph(
        [
            _finding("f1", file_path="a.py", algorithm="RSA", parameter="2048", tier="overdue"),
            _finding("f2", file_path="b.py", algorithm="MD5", tier="low-risk"),
        ]
    )
    d = g.to_dict()
    assert d["schemaVersion"] == GRAPH_SCHEMA_VERSION
    assert d["counts"]["files"] == 2
    assert d["counts"]["algorithms"] == 2
    assert d["counts"]["edges"] == 2
    assert d["counts"]["filesByTier"]["overdue"] == 1
    assert d["counts"]["filesByTier"]["low-risk"] == 1


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

def test_graph_endpoint_returns_nodes_and_edges(
    auth_bypassed_client: TestClient, artifacts_dir: Path
) -> None:
    _seed_scan(
        artifacts_dir,
        "scan-g",
        [_finding("f1", file_path="a.py", algorithm="RSA", parameter="2048")],
    )
    resp = auth_bypassed_client.get("/api/graph/scan-g")
    assert resp.status_code == 200
    body = resp.json()
    assert body["scanId"] == "scan-g"
    assert body["schemaVersion"] == GRAPH_SCHEMA_VERSION
    assert body["counts"]["files"] == 1
    assert body["counts"]["algorithms"] == 1


def test_graph_endpoint_404s_when_scan_missing(
    auth_bypassed_client: TestClient, artifacts_dir: Path
) -> None:
    resp = auth_bypassed_client.get("/api/graph/does-not-exist")
    assert resp.status_code == 404


def test_openapi_advertises_graph_path(
    auth_bypassed_client: TestClient,
) -> None:
    schema = auth_bypassed_client.get("/openapi.json").json()
    assert "/api/graph/{scan_id}" in schema["paths"]
