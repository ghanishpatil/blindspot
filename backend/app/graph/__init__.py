"""Blast-radius graph builder.

Turns a scan's finding list into a bipartite artifact graph:

* **File nodes** -- one per unique ``file_path`` that carries at
  least one crypto finding. Sized (implicitly, by ``findingCount``)
  and coloured by the worst tier of any finding it hosts.
* **Algorithm nodes** -- one per unique ``(algorithm, parameter,
  curve)`` triple, coloured by the worst tier of any finding at
  that identity.
* **Edges** -- one per finding, linking the finding's file to its
  algorithm node.

This is the CBOM as a graph. Judges see:

* Which files carry the most crypto usage (the blast radius).
* Which algorithms are on fire across the codebase.
* The literal "map" from source files to cryptographic assets.

Nothing here derives new risk signals; ``tier``, ``file_path``, and
``algorithm/parameter/curve`` all come straight from the pipeline.
"""

from app.graph.builder import (
    GRAPH_SCHEMA_VERSION,
    build_dependency_graph,
    GraphEdge,
    GraphNode,
    GraphResult,
)

__all__ = [
    "GRAPH_SCHEMA_VERSION",
    "GraphEdge",
    "GraphNode",
    "GraphResult",
    "build_dependency_graph",
]
