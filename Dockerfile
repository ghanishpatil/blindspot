# syntax=docker/dockerfile:1.7
#
# Dockerfile for the Blindspot CBOM Guardrail GitHub Action.
#
# Build context is the repository root (referenced from
# ``action/action.yml`` as ``image: '../Dockerfile'``). Keeps the CLI's
# source-of-truth (`backend/`) inside the image without pulling from
# PyPI, so a locally-built action always matches the repo's HEAD.
#
# The image installs three things:
#   1. System deps: git (for baseline worktree), bash (entrypoint),
#      ca-certificates (semgrep telemetry off, but pip needs TLS).
#   2. The scan pipeline via ``pip install -e backend`` -- this
#      registers the ``blindspot-scan`` console script from
#      ``backend/pyproject.toml`` `[project.scripts]`.
#   3. Semgrep, needed by ``app.scanner`` at scan time.

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SEMGREP_SEND_METRICS=off

# System deps: git for worktree, bash for entrypoint, gcc/build-essential
# only during build (semgrep wheels are prebuilt for slim, but a few
# transitive deps still compile).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        bash \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/blindspot

# Install backend deps first so image layers cache when only source
# changes. requirements.txt is the pinned canonical set.
COPY backend/requirements.txt /opt/blindspot/backend/requirements.txt
RUN pip install --requirement /opt/blindspot/backend/requirements.txt

# Copy the backend source itself and install it in editable mode so
# the ``blindspot-scan`` console script becomes available on PATH.
COPY backend/pyproject.toml /opt/blindspot/backend/pyproject.toml
COPY backend/app /opt/blindspot/backend/app
RUN pip install --no-deps --editable /opt/blindspot/backend

# The action wrapper.
COPY action/entrypoint.sh /opt/blindspot/entrypoint.sh
RUN chmod +x /opt/blindspot/entrypoint.sh

# Docker actions run with WORKDIR=/github/workspace at runtime.
# GITHUB_OUTPUT is provided by the runner. entrypoint.sh handles both.
ENTRYPOINT ["/opt/blindspot/entrypoint.sh"]
