# SPEC · D1 — CI/CD Guardrail

**Sprint 1 · Differentiator #4 · From `FULL_PLATFORM_PLAN.md` §2.2**

Turns Blindspot from a scanner into a **continuous posture platform**. Every
push to a repository is re-scanned; the PR is blocked if it introduces new
quantum-vulnerable, weak-now, or overdue cryptography versus the base branch.

This is the single item that most changes how a judge or buyer *reads* the
product: not "scan on demand", but "cannot merge insecure crypto."

---

## 1. Goals

* Ship a **stateless CLI** — `blindspot-scan` — that runs the existing pipeline
  in-process against any local path and emits either a full JSON report or a
  compact JSON *delta* against a previous scan.
* Ship a **GitHub Action wrapper** — `blindspot/scan-action@v1` — that runs the
  CLI on every push / PR and fails the build (or posts a required review) when
  the delta violates a configurable policy.
* Ship a **policy engine** — a small deterministic rule evaluator against
  finding-level fields. Default policy blocks any new `is_currently_weak` or
  new `risk_tier == overdue` finding.

All three pieces are additive. Nothing in `app/pipeline.py`,
`app/api/scan.py`, or any existing scanner changes.

## 2. Non-goals

* No webhook / server-push architecture. This is stateless — the CI runner is
  the compute; there's no Blindspot server involved.
* No GitLab / Bitbucket / Jenkins wrappers on this sprint (all wrap the same
  CLI later; the CLI is the contract).
* No policy DSL. The policy is JSON with a fixed set of fields.
* No CBOM diff on this sprint (that's D2, Sprint 4). The delta here is a
  compact finding-level delta only.
* No latency measurement. The CLI reuses the same pipeline; there is no
  "faster" mode.

## 3. Contract — the CLI

### 3.1 Invocation
```
blindspot-scan scan   <path>                         # full scan → JSON to stdout
blindspot-scan diff   <path> --baseline <file>       # diff against a prior report
blindspot-scan gate   <path> --baseline <file> \     # scan + diff + policy check
                              --policy <file>
```

### 3.2 Arguments
| Arg | Applies to | Purpose |
|---|---|---|
| `<path>` | all | Directory to scan. Must exist, must be a directory, must be inside `--work-root` if set. |
| `--baseline <file>` | `diff`, `gate` | Path to a prior `blindspot-scan scan` output JSON. Missing / unreadable ⇒ treated as empty baseline (all findings are "introduced"). |
| `--policy <file>` | `gate` | Path to a policy JSON (see §5). Missing ⇒ use the built-in default policy. |
| `--project-id <id>` | all | Passed to the pipeline for provenance. Default `ci`. |
| `--out <file>` | `scan`, `diff` | Write JSON here instead of stdout. Stdout stays empty on success (for CI logs). |
| `--format {json,sarif}` | `scan` | Output format. `json` (default) is our native; `sarif` is v2.1.0 for GitHub Code Scanning. |
| `--quiet` | all | Suppress human-readable progress on stderr. |
| `--version` | — | Print the CLI + pipeline version and exit 0. |

### 3.3 Exit codes
| Code | Meaning |
|---|---|
| 0 | Success. For `gate`: no policy violation. |
| 1 | Runtime error (unreadable path, malformed baseline, pipeline exception). |
| 2 | Policy violation (`gate` only). Delta and violation list are still emitted on stdout. |
| 3 | Bad arguments / usage. |

Distinguishing exit 2 from exit 1 is the whole point — CI needs to tell "your
code violates policy" (fix the code) from "the scanner broke" (fix the CI).

### 3.4 stdout / stderr contract
* **stdout** — JSON only, on the success path. Ends with `\n`. Never mixed
  with progress text.
* **stderr** — human-readable progress: `[1/5] running semgrep...`, plus any
  error messages. Suppressed by `--quiet`.
* Machine-parseable JSON on stdout is the CI contract. Never break this.

## 4. Data shapes

### 4.1 Full scan output — `blindspot-scan scan`
```json
{
  "schemaVersion": "blindspot.scan.v1",
  "generatedAt": "2026-09-07T12:34:56Z",
  "cli": { "version": "0.1.0" },
  "pipeline": { "version": "0.9.0" },
  "target": {
    "path": "<abs path>",
    "gitRef": "<sha if detected, else null>",
    "gitBranch": "<branch if detected, else null>"
  },
  "summary": { /* verbatim ScanSummary.serialise() */ },
  "findings": [ /* verbatim Finding.to_firestore_document() per finding */ ]
}
```

`gitRef` / `gitBranch` come from `git rev-parse HEAD` and `git rev-parse
--abbrev-ref HEAD` if the target is a git working tree. Best-effort; null
outside git. Adds *provenance* to the report without inventing anything.

### 4.2 Delta output — `blindspot-scan diff` and inside `gate`
```json
{
  "schemaVersion": "blindspot.delta.v1",
  "generatedAt": "2026-09-07T12:34:56Z",
  "baseline": { "gitRef": "...", "generatedAt": "..." },
  "current":  { "gitRef": "...", "generatedAt": "..." },
  "counts": {
    "introduced": 3,
    "resolved":   1,
    "changed":    0,
    "unchanged": 12
  },
  "introduced": [ /* full Finding docs, new to this scan */ ],
  "resolved":   [ /* full Finding docs, present in baseline, absent now */ ],
  "changed":    [
    {
      "id": "CRYPTO-042",
      "changes": {
        "riskTier":       { "from": "transitional", "to": "overdue" },
        "isCurrentlyWeak":{ "from": false,          "to": true      }
      }
    }
  ],
  "policy": { /* omitted from diff; included on gate */ }
}
```

**Finding identity for diff** is not `Finding.id` (which is regenerated per
scan). It's a stable *fingerprint*:

```
sha256(algorithm + parameter + curve + evidence.file_path + evidence.line_number + evidence.rule_id)
```

Two findings with the same fingerprint are considered the same finding across
runs — algorithm at file X line Y matched by rule Z. Line-number moves are
tolerated by falling back to `(algorithm, parameter, curve, file_path,
rule_id)` when the line-matched pair is empty but a file-matched pair exists.
This tolerance is one hop deep — it never reaches across files.

**Change detection** applies once fingerprints match. A finding is `changed`
(not `unchanged`) when any of these fields differ from baseline:
`riskTier`, `isCurrentlyWeak`, `isQuantumSensitive`, `isHndlExposed`,
`parameter`, `parameterStatus`, `needsVerification`.

### 4.3 Gate output — `blindspot-scan gate` (exit code 2)
As §4.2 plus:
```json
"policy": {
  "name": "block-new-weak-or-overdue",
  "violations": [
    {
      "ruleId": "no-new-weak-now",
      "findingId": "CRYPTO-042",
      "reason": "New finding is currently weak.",
      "field": "isCurrentlyWeak",
      "value": true
    }
  ]
}
```

## 5. Policy JSON format

```json
{
  "schemaVersion": "blindspot.policy.v1",
  "name": "block-new-weak-or-overdue",
  "rules": [
    {
      "id": "no-new-weak-now",
      "on": "introduced",
      "match": { "isCurrentlyWeak": true },
      "action": "block"
    },
    {
      "id": "no-new-overdue",
      "on": "introduced",
      "match": { "riskTier": "overdue" },
      "action": "block"
    },
    {
      "id": "no-regressions",
      "on": "changed",
      "match": { "changes.riskTier.to": "overdue" },
      "action": "block"
    },
    {
      "id": "warn-new-hndl",
      "on": "introduced",
      "match": { "isHndlExposed": true },
      "action": "warn"
    }
  ]
}
```

* **`on`** — which delta bucket to evaluate against: `introduced`, `resolved`,
  `changed`, or `all`.
* **`match`** — a small dotted-key equality DSL (no regex, no arithmetic). Each
  key resolves against the finding document; each value must match exactly.
  Multiple keys are AND-ed.
* **`action`** — `block` (contributes to exit 2), `warn` (logged, does not
  fail the build). Only `block` violations count toward the exit code.

The default (built-in) policy is `no-new-weak-now` + `no-new-overdue` +
`no-regressions`. Users provide `--policy` to override.

## 6. GitHub Action wrapper

### 6.1 `action.yml`
```yaml
name: "Blindspot CBOM Guardrail"
description: "Blocks PRs that introduce new quantum-vulnerable or currently-weak crypto."
inputs:
  path:            { description: "Target path.",           default: "." }
  baseline-branch: { description: "Base branch.",           default: "main" }
  policy:          { description: "Policy file path.",      required: false }
  fail-on-warn:    { description: "Escalate warns to blocks.", default: "false" }
  upload-sarif:    { description: "Upload SARIF to Code Scanning.", default: "true" }
outputs:
  introduced-count: { description: "Number of newly introduced findings." }
  resolved-count:   { description: "Number of resolved findings." }
  changed-count:    { description: "Number of changed findings." }
  violations-count: { description: "Number of block-severity violations." }
runs:
  using: "docker"
  image: "Dockerfile"
```

### 6.2 Action steps (baked into the Docker entrypoint)
1. `git fetch origin <baseline-branch> --depth=1`
2. `git worktree add /tmp/base <sha of baseline-branch>`
3. `blindspot-scan scan /tmp/base --out /tmp/baseline.json`
4. `blindspot-scan gate <path> --baseline /tmp/baseline.json --policy <policy> --out /tmp/delta.json`
5. On exit 2: post a PR comment summarising violations, upload SARIF, fail the job.
6. On exit 0: post an informational comment ("no new quantum-vulnerable
   findings introduced"), upload SARIF, pass the job.

The comment is idempotent — updates in place instead of stacking new comments.

## 7. Where the code lives

| Path | New / touched | Purpose |
|---|---|---|
| `backend/app/cli/__init__.py` | new | Package marker. |
| `backend/app/cli/main.py` | new | `argparse` entrypoint. Registered as `blindspot-scan` in `pyproject.toml`. |
| `backend/app/cli/report.py` | new | Build the full-scan JSON envelope. |
| `backend/app/cli/diff.py` | new | Fingerprinting + delta computation. |
| `backend/app/cli/policy.py` | new | Policy loader + evaluator. |
| `backend/app/cli/git_meta.py` | new | Best-effort `git rev-parse` extraction. |
| `backend/pyproject.toml` | touched | Add `[project.scripts]` entry. |
| `backend/tests/cli/test_*.py` | new | Unit + integration tests. |
| `action/Dockerfile` | new | Slim image with backend + entrypoint. |
| `action/entrypoint.sh` | new | Steps §6.2. |
| `action/action.yml` | new | §6.1. |
| `action/README.md` | new | Usage instructions. |
| `.github/workflows/self-guardrail.yml` | new | Blindspot dogfoods its own action against itself. |

No file in `app/pipeline.py`, `app/api/*`, `app/scanner/*`, `app/models/*`, or
`app/recommend/*` is edited. The CLI imports them read-only.

## 8. Honesty guardrails

Enforced on this sprint per `FULL_PLATFORM_PLAN.md` §5:

1. Every field in the delta comes from an existing pipeline field. **No new
   number is computed here** — this is a differ, not an analyser.
2. The `pipeline.version` in the report envelope is read from
   `app/__version__.py`. Any drift in the pipeline shows up in downstream
   reports as a version bump — never spoofed.
3. `gitRef` / `gitBranch` are optional. If `git rev-parse` fails or the target
   isn't a working tree, both are `null` — never a fake SHA.
4. Fingerprint is a hash of *evidence*, not a semantic guess. If evidence
   changes (file rename), the fingerprint changes and the finding is
   correctly seen as `resolved` + `introduced`. No fuzzy string matching, no
   ML classifier, no invented equivalence.
5. Policy violations show the exact field and value that triggered them. A
   user should never see "policy blocked this" without being able to see
   *why* on the same page.

## 9. Test list

Every test named below must exist and pass before this sprint ships.

### Unit — `tests/cli/test_diff.py`
* `test_fingerprint_stable_across_runs` — same finding twice ⇒ same fingerprint.
* `test_fingerprint_changes_with_file` — same algorithm at a different file ⇒ different fingerprint.
* `test_line_move_still_matches` — file same, line differs by ±20, no rule change ⇒ matched via file-fallback.
* `test_new_finding_is_introduced` — baseline empty ⇒ 1 finding in current ⇒ 1 introduced, 0 resolved.
* `test_missing_baseline_is_empty` — treats missing baseline file as empty baseline; never crashes.
* `test_field_change_marks_changed` — same fingerprint, `isCurrentlyWeak: false→true` ⇒ `changed`, not `unchanged`.
* `test_finding_removed_is_resolved` — present in baseline, absent in current ⇒ resolved.

### Unit — `tests/cli/test_policy.py`
* `test_default_policy_blocks_new_weak_now` — introduced finding with `isCurrentlyWeak: true` ⇒ 1 block violation.
* `test_default_policy_blocks_new_overdue` — introduced finding with `riskTier: overdue` ⇒ 1 block violation.
* `test_default_policy_blocks_regressions` — changed finding whose `riskTier` moved to `overdue` ⇒ 1 block violation.
* `test_warn_action_never_blocks` — a warn violation on `isHndlExposed` ⇒ 0 block violations (still listed).
* `test_dotted_key_resolution` — `changes.riskTier.to` resolves correctly against `changed` docs.
* `test_unknown_action_is_rejected_at_load` — malformed policy JSON ⇒ exit 3 at load time.

### Unit — `tests/cli/test_git_meta.py`
* `test_git_meta_in_working_tree` — returns real SHA and branch.
* `test_git_meta_outside_working_tree` — returns `None` / `None` cleanly.
* `test_git_meta_no_git_binary` — patched `subprocess` failure ⇒ `None` / `None` — never raises.

### Integration — `tests/cli/test_scan_command.py`
* `test_scan_stdout_is_pure_json` — no progress text mixed into stdout.
* `test_scan_exit_zero_on_success` — clean scan against demo repo ⇒ exit 0.
* `test_scan_out_flag_writes_file` — `--out` writes JSON to file, stdout empty.
* `test_scan_produces_stable_fingerprints_twice` — two runs of the same target produce identical fingerprints for the same findings.

### Integration — `tests/cli/test_gate_command.py`
* `test_gate_no_violations_returns_zero` — baseline = current ⇒ exit 0.
* `test_gate_new_weak_returns_two` — baseline with no findings, current with an RSA-1024 ⇒ exit 2, at least one violation on `isCurrentlyWeak`.
* `test_gate_only_warns_returns_zero` — a policy of only warn rules ⇒ exit 0 even if warns fire.

### Regression
* Existing backend suite (283 tests) must remain green.
* Existing frontend suite (18 tests) unchanged.

## 10. Success criteria (verified at sprint end)

* `pip install -e .` inside `backend/` exposes `blindspot-scan` on PATH.
* `blindspot-scan scan .` on this repo emits valid JSON matching the
  `blindspot.scan.v1` schema.
* `blindspot-scan gate` against a synthetic downgrade (add an RSA-1024
  generation to the demo repo, keep baseline clean) exits **2** and prints
  the exact rule + finding that fired.
* The action's `self-guardrail.yml` workflow runs green on this repo and
  produces a PR comment on a test PR.
* All new tests pass. Existing tests unchanged and green.
* `NEXT_ROUND_UPGRADE_PLAN.md` and `FULL_PLATFORM_PLAN.md` are updated: D1
  marked ✅, coverage-table row for Sprint 1 populated.

## 11. Open decisions before coding

Three small things I want your call on before I start:

1. **Package name for the CLI in PyPI-speak.** Options: `blindspot-cli`,
   `blindspot-scan`, `blindspot-cbom`. Same binary name (`blindspot-scan`)
   either way; this is only the pip package. Recommendation: `blindspot-cli`
   — leaves headroom for `blindspot-report`, `blindspot-diff` sub-binaries
   later without a rename.
2. **SARIF on this sprint or Sprint 1.5?** Adding SARIF v2.1.0 output on `scan`
   is small (mapping is 1:1 for our fields) and unlocks GitHub Code
   Scanning's native UI — but it's not strictly required for the guardrail
   itself. Recommendation: include it. It's the CI-story completion piece.
3. **Policy file location convention.** Recommendation: repos put their
   policy at `.blindspot/policy.json`. The action defaults to that path if
   `--policy` isn't given. Consistent with how tools like `renovate` and
   `dependabot` colonise a directory in the repo.

Reply with your calls on these three and I'll start writing the CLI. Or say
"go" and I'll take the recommendations above.
