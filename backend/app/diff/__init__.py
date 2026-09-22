"""Cross-scan diff engine.

The :mod:`app.diff.cbom_diff` module compares two on-disk scan snapshots
and produces a structured, JSON-serialisable diff. Used by
``GET /api/scans/diff`` and the frontend Diff panel.
"""
