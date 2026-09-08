"""Evidence extraction and normalization.

Converts raw scanner output into :class:`app.models.finding.NormalizedFinding`
objects with attached :class:`app.models.finding.Evidence`.

This is the boundary that protects every downstream stage from scanner-specific
formats. Implemented in Phase 5.
"""
