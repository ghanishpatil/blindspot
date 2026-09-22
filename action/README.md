# Blindspot CBOM Guardrail — GitHub Action

Block pull requests that introduce new quantum-vulnerable or
currently-weak cryptography. Runs the [Blindspot ECDAT](../README.md)
scanner against your baseline branch, diffs the result against the PR
head, and fails the job on policy violations.

The check is additive: a PR that only *resolves* findings or *changes
nothing* passes. A PR that introduces a new `RSA-2048` call, a new
`overdue` finding, or regresses a matched finding into `overdue` is
blocked. Warnings surface HNDL exposure without blocking, unless you
opt into `fail-on-warn: true`.

---

## Quick start

```yaml
# .github/workflows/pqc-guardrail.yml
name: PQC guardrail
on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  # Only needed if you want the action to post PR comments (roadmap).
  pull-requests: write

jobs:
  blindspot:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout PR head
        uses: actions/checkout@v4
        with:
          # Blindspot needs both PR head and the baseline branch, so
          # fetch full history (or at least enough to reach baseline).
          fetch-depth: 0

      - name: Run Blindspot guardrail
        id: blindspot
        uses: blindspot-ecdat/blindspot/action@v1
        with:
          path: "."
          baseline-branch: "main"
          # policy: ".blindspot/policy.json"  # optional
          fail-on-warn: "false"
```

Exit codes are transparent:

* **0** — clean, PR can merge.
* **1** — runtime error (bad path, git fail, pipeline crash). Fix and rerun.
* **2** — policy violation. The job fails; the PR is blocked.
* **3** — usage error (invalid policy file, bad flags). Fix `with:` block.

---

## Inputs

| Name              | Default   | Purpose                                                                              |
| ----------------- | --------- | ------------------------------------------------------------------------------------ |
| `path`            | `.`       | Directory to scan, relative to repo root.                                            |
| `baseline-branch` | `main`    | Branch to diff against. Usually your default branch.                                 |
| `policy`          | *(unset)* | Path to a policy JSON, relative to repo root. Omit to use the built-in default.      |
| `fail-on-warn`    | `false`   | Escalate warn-severity violations to block. Useful once your HNDL posture is clean.  |

## Outputs

| Name                    | Meaning                                                    |
| ----------------------- | ---------------------------------------------------------- |
| `introduced-count`      | Newly introduced findings vs baseline.                     |
| `resolved-count`        | Findings the PR resolves.                                  |
| `changed-count`         | Matched findings whose tracked fields changed.             |
| `violations-count`      | Block-severity violations. Non-zero means PR is blocked.   |
| `warn-violations-count` | Warn-severity violations. Informational.                   |
| `exit-code`             | Raw exit code from `blindspot-scan` (0 / 1 / 2 / 3).       |
| `delta-json`            | Path to the full delta+policy JSON envelope in the runner. |

Read outputs in downstream steps:

```yaml
      - name: Summarise
        if: always()
        run: |
          echo "introduced=${{ steps.blindspot.outputs.introduced-count }}"
          echo "resolved=${{ steps.blindspot.outputs.resolved-count }}"
          echo "violations=${{ steps.blindspot.outputs.violations-count }}"

      - name: Upload delta report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: blindspot-delta
          path: ${{ steps.blindspot.outputs.delta-json }}
```

---

## Custom policies

Drop a file at `.blindspot/policy.json` in your repo and point the
action at it:

```yaml
        with:
          policy: ".blindspot/policy.json"
```

Policy JSON shape (see `backend/app/cli/policy.py::DEFAULT_POLICY` for
the built-in example):

```json
{
  "name": "team-policy",
  "rules": [
    {
      "id": "no-new-weak-now",
      "match": { "in": "introduced", "isCurrentlyWeak": true },
      "action": "block",
      "reason": "PR introduces a currently-weak cryptographic call."
    },
    {
      "id": "no-new-overdue",
      "match": { "in": "introduced", "riskTier": "overdue" },
      "action": "block",
      "reason": "PR introduces a new overdue finding."
    },
    {
      "id": "no-regressions",
      "match": { "in": "changed", "changes.riskTier.to": "overdue" },
      "action": "block",
      "reason": "PR regresses a matched finding into overdue tier."
    },
    {
      "id": "warn-new-hndl",
      "match": { "in": "introduced", "isHndlExposed": true },
      "action": "warn",
      "reason": "PR introduces a new HNDL-exposed finding."
    }
  ]
}
```

Rule fields:

* `match.in` — one of `introduced`, `resolved`, `changed`. The set of
  findings the rule is evaluated against.
* All other keys on `match` are dotted-path equality checks. `changes.riskTier.to`
  reads the tracked-field diff for `changed` findings.
* `action` — `block` (fails the job) or `warn` (informational).
* `reason` — surfaced verbatim in the console output.

---

## Baseline SHA & git provenance

The action runs `git fetch origin <baseline-branch> --depth=1` and
`git worktree add` against the resolved SHA. If your `actions/checkout`
step used `fetch-depth: 0` (recommended), the base is already
available; the action skips the extra fetch. Otherwise the shallow
fetch is enough for scanning.

Every scan envelope carries `target.gitRef` and `target.gitBranch`
when `git rev-parse` succeeds; both are `null` when it doesn't. No
fake SHAs are ever emitted (see [honesty guardrail #3](../SPEC_D1_CICD_GUARDRAIL.md#8-honesty-guardrails)).

---

## Local reproduction

Any behaviour you see in CI reproduces locally:

```bash
# 1. Install the CLI (editable, from the repo root).
pip install -e backend

# 2. Scan the baseline (e.g. main branch checked out at /tmp/base).
blindspot-scan scan /tmp/base --out /tmp/baseline.json

# 3. Gate the PR head against it.
blindspot-scan gate . \
    --baseline /tmp/baseline.json \
    --policy .blindspot/policy.json \
    --out /tmp/delta.json
echo "exit=$?"
```

`blindspot-scan --help` and `blindspot-scan gate --help` document every
flag.

---

## Roadmap

Deferred from the first slice, tracked in
[`SPEC_D1_CICD_GUARDRAIL.md`](../SPEC_D1_CICD_GUARDRAIL.md):

* SARIF v2.1.0 output for GitHub Code Scanning integration.
* Idempotent PR comment (update-in-place instead of stacking).
* GitLab CI / Bitbucket Pipelines wrappers reusing the same CLI.

The CLI itself is stable — the action shells out to it, so anything
that lands in `blindspot-scan` reaches CI users on the next tag.
