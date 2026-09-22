"""Blindspot CI/CD guardrail CLI.

Exposes ``blindspot-scan`` as an entry-point console script when the
backend is installed with ``pip install -e .`` (see ``pyproject.toml``
``[project.scripts]``).

The CLI is a thin wrapper around the existing pipeline: it runs a real
scan, computes a stable finding-level fingerprint, diffs against a
prior scan, and evaluates a JSON policy. Its whole purpose is to give
CI systems a reliable **exit-code contract** so a PR that introduces
new quantum-vulnerable or currently-weak cryptography fails the build.

Every module here is import-only against ``app.pipeline`` /
``app.scanner`` / ``app.models`` / ``app.recommend``. Nothing about the
runtime pipeline changes when you install the CLI.
"""
