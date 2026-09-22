#!/usr/bin/env bash
#
# Blindspot CBOM Guardrail — GitHub Action entrypoint.
#
# Reads action inputs from the ``INPUT_*`` environment variables that
# GitHub sets from ``action.yml``'s ``inputs`` block. Runs a baseline
# scan against the configured branch, then a gate scan against the
# checked-out HEAD. Writes counts to ``$GITHUB_OUTPUT`` and exits with
# the CLI's exit code so downstream steps (``if: failure()``, PR
# comments) work off a single source of truth.
#
# Exit code contract, straight from ``blindspot-scan`` (SPEC §3.4):
#   0 -- clean pass (or clean pass with unblocked warns)
#   1 -- runtime error (bad path, git fail, pipeline exception)
#   2 -- policy violation (block-severity finding)
#   3 -- usage error (bad flags, unreadable policy)
#
# ``fail-on-warn`` upgrades a clean-with-warns run (exit 0 + warn
# violations > 0) to exit 2. It never downgrades a genuine block.

set -euo pipefail

# ---------------------------------------------------------------------------
# Inputs (with defaults matching action.yml)
# ---------------------------------------------------------------------------
INPUT_PATH="${INPUT_PATH:-.}"
INPUT_BASELINE_BRANCH="${INPUT_BASELINE_BRANCH:-main}"
INPUT_POLICY="${INPUT_POLICY:-}"
INPUT_FAIL_ON_WARN="${INPUT_FAIL_ON_WARN:-false}"

# Workspace paths. GitHub Actions checks out the repo at
# /github/workspace and sets that as the working directory before
# invoking us; ``pwd`` is that dir.
WORKSPACE="$(pwd)"
BASE_WORKTREE="/tmp/blindspot-base"
BASELINE_JSON="/tmp/blindspot-baseline.json"
DELTA_JSON="/tmp/blindspot-delta.json"

echo "::group::Blindspot guardrail — configuration"
echo "path            = ${INPUT_PATH}"
echo "baseline-branch = ${INPUT_BASELINE_BRANCH}"
echo "policy          = ${INPUT_POLICY:-<built-in default>}"
echo "fail-on-warn    = ${INPUT_FAIL_ON_WARN}"
echo "workspace       = ${WORKSPACE}"
echo "::endgroup::"

# ---------------------------------------------------------------------------
# Baseline: fetch the base branch shallowly, materialise a worktree.
# ---------------------------------------------------------------------------
echo "::group::Fetch baseline branch: ${INPUT_BASELINE_BRANCH}"
# The default $GITHUB_TOKEN is exposed for authenticated fetches when
# actions/checkout was used with persist-credentials: true (the
# default). We do not require it -- unauth fetch works for public
# repos, and private repos rely on the caller's checkout config.
git config --global --add safe.directory "${WORKSPACE}"

# Docker actions run without pre-set git origin creds; use whatever
# origin the checked-out repo has. If the base branch has been fetched
# already (typical actions/checkout with fetch-depth: 0) this is a
# no-op; otherwise fetch shallowly.
if ! git rev-parse --verify "origin/${INPUT_BASELINE_BRANCH}" >/dev/null 2>&1; then
    git fetch --no-tags --prune --depth=1 origin \
        "+refs/heads/${INPUT_BASELINE_BRANCH}:refs/remotes/origin/${INPUT_BASELINE_BRANCH}"
fi

BASELINE_SHA="$(git rev-parse "origin/${INPUT_BASELINE_BRANCH}")"
echo "baseline SHA = ${BASELINE_SHA}"

# Clean any stale worktree from a previous run of the same container.
if [ -d "${BASE_WORKTREE}" ]; then
    git worktree remove --force "${BASE_WORKTREE}" 2>/dev/null || rm -rf "${BASE_WORKTREE}"
fi
git worktree add --detach "${BASE_WORKTREE}" "${BASELINE_SHA}"
echo "::endgroup::"

# ---------------------------------------------------------------------------
# Baseline scan.
# ---------------------------------------------------------------------------
echo "::group::Scan baseline"
if ! blindspot-scan --quiet scan "${BASE_WORKTREE}" \
        --project-id "github-action-baseline" \
        --out "${BASELINE_JSON}"; then
    echo "::error::Baseline scan failed. See logs above."
    exit 1
fi
echo "baseline scan written: ${BASELINE_JSON}"
echo "::endgroup::"

# ---------------------------------------------------------------------------
# Gate scan.
# ---------------------------------------------------------------------------
echo "::group::Gate scan (${INPUT_PATH})"
GATE_ARGS=(
    --baseline "${BASELINE_JSON}"
    --project-id "github-action"
    --out "${DELTA_JSON}"
)
if [ -n "${INPUT_POLICY}" ]; then
    if [ ! -f "${WORKSPACE}/${INPUT_POLICY}" ] && [ ! -f "${INPUT_POLICY}" ]; then
        echo "::error::policy file '${INPUT_POLICY}' not found."
        exit 3
    fi
    if [ -f "${WORKSPACE}/${INPUT_POLICY}" ]; then
        GATE_ARGS+=(--policy "${WORKSPACE}/${INPUT_POLICY}")
    else
        GATE_ARGS+=(--policy "${INPUT_POLICY}")
    fi
fi

# We MUST NOT ``set -e`` this: exit 2 (policy violation) is a
# meaningful signal, not a bash error. Capture it and inspect.
set +e
blindspot-scan --quiet gate "${INPUT_PATH}" "${GATE_ARGS[@]}"
GATE_EXIT=$?
set -e
echo "gate exit code = ${GATE_EXIT}"
echo "::endgroup::"

# ---------------------------------------------------------------------------
# Parse counts and publish outputs.
# ---------------------------------------------------------------------------
INTRODUCED=0
RESOLVED=0
CHANGED=0
VIOLATIONS=0
WARN_VIOLATIONS=0

if [ -f "${DELTA_JSON}" ]; then
    # Prefer python (already in the image) over jq for zero extra deps.
    read -r INTRODUCED RESOLVED CHANGED VIOLATIONS WARN_VIOLATIONS <<EOF_COUNTS
$(python - "${DELTA_JSON}" <<'PY'
import json, sys
path = sys.argv[1]
try:
    with open(path, encoding='utf-8') as fh:
        data = json.load(fh)
except Exception as exc:
    print(f"0 0 0 0 0", end='')
    sys.stderr.write(f"could not parse delta JSON: {exc}\n")
    sys.exit(0)

counts = data.get('counts') or {}
policy = data.get('policy') or {}
violations = policy.get('violations') or []
block = sum(1 for v in violations if v.get('action') == 'block')
warn = sum(1 for v in violations if v.get('action') == 'warn')
print(
    counts.get('introduced', 0),
    counts.get('resolved', 0),
    counts.get('changed', 0),
    block,
    warn,
    end='',
)
PY
)
EOF_COUNTS
fi

echo "::group::Blindspot guardrail — summary"
echo "introduced  = ${INTRODUCED}"
echo "resolved    = ${RESOLVED}"
echo "changed     = ${CHANGED}"
echo "block viols = ${VIOLATIONS}"
echo "warn  viols = ${WARN_VIOLATIONS}"
echo "::endgroup::"

# GITHUB_OUTPUT is a temp file the runner reads after the step.
if [ -n "${GITHUB_OUTPUT:-}" ]; then
    {
        echo "introduced-count=${INTRODUCED}"
        echo "resolved-count=${RESOLVED}"
        echo "changed-count=${CHANGED}"
        echo "violations-count=${VIOLATIONS}"
        echo "warn-violations-count=${WARN_VIOLATIONS}"
        echo "exit-code=${GATE_EXIT}"
    } >>"${GITHUB_OUTPUT}"
fi

# Also expose the delta file for downstream steps that want to upload
# it as an artifact or post-process it.
if [ -f "${DELTA_JSON}" ] && [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "delta-json=${DELTA_JSON}" >>"${GITHUB_OUTPUT}"
fi

# ---------------------------------------------------------------------------
# Exit-code decision.
# ---------------------------------------------------------------------------
# Escalate warn-only runs when the caller opted in.
if [ "${GATE_EXIT}" -eq 0 ] \
   && [ "${INPUT_FAIL_ON_WARN}" = "true" ] \
   && [ "${WARN_VIOLATIONS}" -gt 0 ]; then
    echo "::warning::fail-on-warn=true and ${WARN_VIOLATIONS} warn violation(s) found. Failing the job."
    exit 2
fi

exit "${GATE_EXIT}"
