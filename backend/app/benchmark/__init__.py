"""Benchmark harness for measuring scanner precision / recall / F1.

Runs the full :func:`app.pipeline.run_pipeline` against a labelled
dataset of source-code cases and compares each case's expected
findings to what the pipeline actually reported. The output is a
:class:`app.benchmark.metrics.BenchmarkReport` -- confusion matrix
plus per-category rollup -- that the ``/api/benchmark`` endpoints
serialise as JSON.

The bundled dataset lives under :mod:`app.benchmark.data` and is
deliberately small: 12-15 hand-crafted cases spanning weak, transitional,
and strong crypto plus true-negatives (no-crypto files). Enough to
prove the scoring pipeline works end-to-end; the full external corpora
(CryptoAPI-Bench, MASC) are documented as opt-in additions -- see
:file:`app/benchmark/data/README.md`.

Design rules:

* **No fabricated numbers.** Every TP / FP / FN / TN is derived from a
  real ``run_pipeline`` output matched against a manifest entry the
  user can inspect. Metrics are a *report of the pipeline*, never
  independent of it.
* **Pure math in metrics.py.** The scoring functions take dicts / lists
  and return dicts / lists. Fast unit tests, no filesystem.
* **Deterministic case ordering.** ``BenchmarkDataset.cases`` iterates
  in manifest order so reports diff cleanly across runs.
"""

from app.benchmark.dataset import (
    BENCHMARK_SCHEMA_VERSION,
    BenchmarkCase,
    BenchmarkDataset,
    ExpectedFinding,
    load_bundled_dataset,
    load_manifest,
)
from app.benchmark.harness import (
    BenchmarkReport,
    CaseResult,
    run_benchmark,
)
from app.benchmark.metrics import (
    ConfusionMatrix,
    compute_case_confusion,
    compute_dataset_metrics,
)

__all__ = [
    "BENCHMARK_SCHEMA_VERSION",
    "BenchmarkCase",
    "BenchmarkDataset",
    "BenchmarkReport",
    "CaseResult",
    "ConfusionMatrix",
    "ExpectedFinding",
    "compute_case_confusion",
    "compute_dataset_metrics",
    "load_bundled_dataset",
    "load_manifest",
    "run_benchmark",
]
