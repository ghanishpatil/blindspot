"""Discovery stage.

Responsibility: find cryptographic artefacts and record where and how they were
found. Nothing here computes risk, tiers, or recommendations — those belong to
later stages so that discovery can be tested and trusted on its own.

Implemented in Phase 4 (semgrep rules + dependency parsing).
"""
