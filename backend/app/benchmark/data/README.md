# Benchmark dataset -- bundled ground truth

This directory ships a small, hand-labelled crypto-misuse corpus that
Blindspot's benchmark harness (`app.benchmark`) uses to compute
precision / recall / F1 for the scan pipeline.

## Layout

* `manifest.json` -- schema: `blindspot.benchmark.v1`. Every case has
  an `id`, a `file` (relative to this directory), a `category`, a
  `language`, and a list of `expected` findings. `expected: []` means
  the case is a **true-negative**: the scanner should find nothing.
* `cases/*.py`, `cases/*.java`, ... -- the labelled source files.
  These are real crypto call sites, not stubs; the pipeline is expected
  to fire on the weak / transitional cases and stay quiet on the
  strong / no-crypto cases.

## Why bundled + small

Judges (and CI) need to see the benchmark run in seconds, offline, with
no network dependency. 12-15 hand-crafted cases prove the metrics
pipeline works end-to-end. For a deeper evaluation, point the harness
at one of the public corpora below:

## Optional external corpora

Run the benchmark against a downloaded corpus by giving
`load_manifest(path)` a manifest that references the corpus paths:

* [CryptoAPI-Bench](https://github.com/CryptoGuardOSS/CryptoAPI-Bench) --
  ~172 Java cases covering the CryptoGuard misuse taxonomy.
* [MASC](https://github.com/Anti-Malware-Group/MASC) -- mutation-based
  evaluation of static crypto-misuse detectors.

The harness only cares about a valid `manifest.json`; the case files
can live anywhere on disk.

## Honesty guardrail

Every score in the report is derived from a real `run_pipeline` output
matched against a manifest entry an operator can inspect. There are
no synthetic F1 numbers, no baked-in "target scores." When a finding
is missed the report names it under `missed`; when a spurious finding
fires the report names it under `extra`. Fix the pipeline, not the
manifest.
