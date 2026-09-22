# Blindspot ECDAT — Complete Platform Reference

**Enterprise Cryptographic Discovery, Assessment & Transition tool.**

*Every feature. Every module. Every endpoint. Every constant. And — for each
one — exactly **how it works**, step by step.*

Two registers, side by side throughout:

- **Plain English** — what it does, why it matters, what a human sees.
- **Working / Technical** — the actual control flow, the real lookup tables
  with their real values, the exact thresholds, the precise failure modes.

Every number, table, function name, and file path in this document was read
directly out of the source before being written down. Where a documented
capability is *not* actually wired up, this document says so explicitly
(see [Part XI §3 — Known quirks and dead code](#63-known-quirks-dead-code-and-documented-but-unwired-behaviour)).

---

## Table of Contents

**[Part I — Orientation](#part-i--orientation)**
- [1. Executive summary](#1-executive-summary)
- [2. The problem](#2-the-problem-blindspot-solves)
- [3. The five-stage mental model](#3-the-five-stage-mental-model)
- [4. Architecture map](#4-architecture-map)

**[Part II — Core pipeline working](#part-ii--core-pipeline-working)**
- [5. `run_pipeline` end to end](#5-run_pipeline-end-to-end)
- [6. Stage 1 — Discovery fan-out](#6-stage-1--discovery-fan-out)
  - [6.1 Target acquisition — how the scan root comes to exist](#61-target-acquisition--how-the-scan-root-comes-to-exist)
    - [6.1.1 Repository URL ingestion](#611-repository-url-ingestion--appscannerrepositorypy)
    - [6.1.2 Container image ingestion](#612-container-image-ingestion--appscannercontainerpy)
- [7. Stage 2 — CBOM emission](#7-stage-2--cbom-emission)
- [8. Stages 3-5 — Per-finding enrichment](#8-stages-3-5--per-finding-enrichment)
- [9. Summary aggregation](#9-summary-aggregation)
- [10. Caching and fallback mode](#10-caching-and-fallback-mode)

**[Part III — Discovery layer working](#part-iii--discovery-layer-working)**
- [11. Scanner 1 — Source code (semgrep)](#11-scanner-1--source-code-semgrep)
- [12. Scanner 2 — Static crypto artefacts](#12-scanner-2--static-crypto-artefacts)
- [13. Scanner 3 — Dependency manifests](#13-scanner-3--dependency-manifests)
- [14. Scanner 4 — Compiled binaries](#14-scanner-4--compiled-binaries)
- [15. Scanner 5 — Infrastructure / HSM / KMS declarations](#15-scanner-5--infrastructure--hsm--kms-declarations)
- [16. Scanner 6 — Config policy files](#16-scanner-6--config-policy-files)
- [17. Scanner 7 — Live TLS probe](#17-scanner-7--live-tls-probe)
- [18. Scanner 8 — PKCS#11 HSM attestation](#18-scanner-8--pkcs11-hsm-attestation)
- [19. Scanner 9 — AWS KMS attestation](#19-scanner-9--aws-kms-attestation)
- [20. Scanners 10-11 — Azure Key Vault and GCP KMS](#20-scanners-10-11--azure-key-vault-and-gcp-kms)
- [21. Confidence ladder across all scanners](#21-confidence-ladder-across-all-scanners)

**[Part IV — Normalisation working](#part-iv--normalisation-working)**
- [22. The evidence extractor](#22-the-evidence-extractor)
- [23. AST parameter resolution and the module-boundary policy](#23-ast-parameter-resolution-and-the-module-boundary-policy)
- [24. Two-pass mode enrichment](#24-two-pass-mode-enrichment)
- [25. Deliberate skips](#25-deliberate-skips)

**[Part V — Analysis engines working](#part-v--analysis-engines-working)**
- [26. The classifier](#26-the-classifier)
- [27. Current-risk engine](#27-current-risk-engine)
- [28. Quantum-risk engine](#28-quantum-risk-engine)
- [29. Mosca inequality engine](#29-mosca-inequality-engine)
- [30. The HNDL composite](#30-the-hndl-composite)
- [31. Security-level derivation](#31-security-level-derivation)
- [32. The recommender](#32-the-recommender)
- [33. Cost profiles](#33-cost-profiles)
- [34. Latency profiles](#34-latency-profiles)
- [35. Roadmap planner](#35-roadmap-planner)
- [36. Compliance sensitivity engine](#36-compliance-sensitivity-engine)

**[Part VI — Output layer working](#part-vi--output-layer-working)**
- [37. CBOM builder](#37-cbom-builder)
- [38. CBOM validator](#38-cbom-validator)
- [39. Executive report generator](#39-executive-report-generator)
- [40. CSV inventory export](#40-csv-inventory-export)
- [41. PDF rendering](#41-pdf-rendering)

**[Part VII — Tier S features working](#part-vii--tier-s-features-working)**
- [42. S1 — CI/CD guardrail](#42-s1--cicd-guardrail)
- [43. S2 — Cross-scan diff](#43-s2--cross-scan-diff)
- [44. S3 — Policy as code](#44-s3--policy-as-code)
- [45. S4 — Benchmark harness](#45-s4--benchmark-harness)

**[Part VIII — Tier A features working](#part-viii--tier-a-features-working)**
- [46. A1 — Blast-radius graph](#46-a1--blast-radius-graph)
- [47. A2 — Preset sensitivity strip](#47-a2--preset-sensitivity-strip)
- [48. A3 — Wave-plan card](#48-a3--wave-plan-card)
- [49. A4 — Crypto-agility score](#49-a4--crypto-agility-score)
- [50. A5 — CBOM interoperability diff](#50-a5--cbom-interoperability-diff)

**[Part IX — Surfaces](#part-ix--surfaces)**
- [51. REST API — every endpoint](#51-rest-api--every-endpoint)
- [52. CLI — `blindspot-scan`](#52-cli--blindspot-scan)
- [53. GitHub Action](#53-github-action)
- [54. Frontend — pages, panels, components, services](#54-frontend--pages-panels-components-services)

**[Part X — Reference tables](#part-x--reference-tables)**
- [55. Data model](#55-data-model)
- [56. Every enum value](#56-every-enum-value)
- [57. Schema versions](#57-schema-versions)
- [58. Configuration](#58-configuration)
- [59. Testing](#59-testing)
- [60. Deployment](#60-deployment)

**[Part XI — Engineering discipline](#part-xi--engineering-discipline)**
- [61. Honesty guardrails](#61-honesty-guardrails)
- [62. Failure-mode catalogue](#62-failure-mode-catalogue)
- [63. Known quirks, dead code, and documented-but-unwired behaviour](#63-known-quirks-dead-code-and-documented-but-unwired-behaviour)
- [64. Roadmap and deliberate non-goals](#64-roadmap-and-deliberate-non-goals)
- [65. Demo Q&A](#65-demo-qa)

---

# Part I — Orientation

## 1. Executive summary

**Plain English.**
Blindspot walks through a codebase and finds every place cryptography is
used — in source code, in dependency files, inside compiled binaries, in
certificate files, in Terraform, on live TLS endpoints, and in cloud key
vaults. For each one it decides three separate things: is this broken
*today*, will a quantum computer break it *eventually*, and given how long
this data must stay secret, is migration *already overdue*. Then it tells
you what to replace it with, in what order, and produces an auditor-ready
report. It also ships as a CLI and a GitHub Action so bad crypto can be
blocked before it ever merges.

**Working / Technical.**
Python 3.13 + FastAPI backend, React 19 + Vite + TypeScript frontend.
`app/pipeline.py::run_pipeline(target, project_id, owner_id, settings, tls_targets)`
fans out to eleven discovery functions, normalises their output into a single
`NormalizedFinding` contract, emits a CycloneDX 1.6 CBOM, then enriches each
finding through a four-step deterministic chain
(`classify` → `assess_current_risk` → `assess_quantum_risk` → `mosca.assess`)
and attaches a `Recommendation`. Returns `(Scan, list[Finding], cbom_json)`.

Every stage is a pure function of its inputs plus `Settings`. The only
non-determinism in the whole pipeline is `scan_id` (a UUID fragment) and
timestamps.

**Scale, measured.**

| Metric | Value |
|---|---|
| Backend tests | 802 passing |
| Frontend tests | 160 passing |
| Discovery paths | 11 (`semgrep`, static-crypto, deps, binary, infra, config-policy, TLS, PKCS#11, AWS KMS, Azure KV, GCP KMS) |
| Semgrep rule files | 11 YAML files, ~100 rules |
| Languages with source rules | Python, Java, JavaScript, TypeScript, Go, C |
| REST endpoints | 18 under `/api` |
| CLI subcommands | 3 (`scan`, `diff`, `gate`) |
| Bundled benchmark cases | 12 (10 positive, 2 true-negative) |
| Measured benchmark result | precision 1.00, recall 0.80, F1 0.889 |

---

## 2. The problem Blindspot solves

**Plain English.**
Almost every application depends on cryptography it did not choose
deliberately — TLS inherited from a framework, a hash function copied from a
tutorial, an RSA key size hardcoded a decade ago. Most asymmetric
cryptography in production today (RSA, ECDSA, ECDH, Diffie-Hellman) will be
broken outright by a sufficiently large quantum computer. Governments have
published deadlines. Attackers are already recording encrypted traffic to
decrypt later. And almost nobody has an inventory of where their crypto
actually lives.

**Working / Technical.**
The threat model has three distinct axes, and Blindspot scores all three
separately rather than collapsing them into one number:

1. **Present-day weakness** (`is_currently_weak`) — MD5, SHA-1, DES, 3DES.
   Broken now, regardless of quantum. Drives the `REMEDIATE_NOW` strategy.
2. **Quantum vulnerability** (`is_quantum_sensitive`) — Shor-breakable
   primitives. A boolean about the *algorithm*, independent of timing.
3. **Migration urgency** (`risk_tier`) — Mosca's inequality over the
   finding's data lifetime. A judgement about *timing*, independent of
   whether the algorithm is weak today.

And one composite that matters operationally more than any of them:

4. **HNDL exposure** (`is_hndl_exposed`) — confidentiality × quantum-vulnerable
   × overdue. The set of findings where an adversary recording ciphertext
   *today* still profits when a CRQC arrives.

Existing tools cover one axis each: SBOM generators enumerate dependencies
but not usages; Semgrep/CodeQL rules catch weak crypto but score no quantum
timeline; vendor CBOM tools emit an inventory but no migration plan or CI
gate. Blindspot's contribution is combining discovery breadth, deterministic
tri-axis scoring, prescriptive migration targets, and ecosystem integration
in one auditable pipeline.

---

## 3. The five-stage mental model

Every finding travels the same five stages. This chain is what makes the
platform auditable: for any finding on the dashboard you can point at each
stage and see exactly which table or formula produced the value.

```
   ┌──────────┐   ┌──────────────┐   ┌─────────────┐   ┌────────┐   ┌────────────────┐
   │ EVIDENCE │──▶│CLASSIFICATION│──▶│ RISK (×3)   │──▶│ MOSCA  │──▶│ RECOMMENDATION │
   └──────────┘   └──────────────┘   └─────────────┘   └────────┘   └────────────────┘
   what & where    what it's FOR      weak? quantum?    urgency      what to do
   file, line,     artefact type,     _CURRENTLY_WEAK   X + Y > Z    strategy,
   snippet,        security goal,     _SHOR_BREAKS      → tier       target algo,
   confidence,     lifetime (X),      _GROVER_WEAKENS                effort, cost,
   rule id         criticality                                       latency
```

### Stage-by-stage, with the actual mechanism

| Stage | Module | Input | Mechanism | Output |
|---|---|---|---|---|
| **1. Evidence** | `app/scanner/*` + `app/evidence/extractor.py` | Target directory / host / cloud account | 11 scanners; semgrep locates, `ast` resolves | `NormalizedFinding` with `Evidence` |
| **2. Classification** | `app/classifier/classifier.py` | `NormalizedFinding` | 5 lookup tables keyed on `CryptoUsage` | `Classification` (goal, lifetime X, criticality) |
| **3a. Current risk** | `app/risk/mosca.py::assess_current_risk` | `algorithm` string | `_CURRENTLY_WEAK` dict lookup | `CurrentRisk` |
| **3b. Quantum risk** | `app/risk/mosca.py::assess_quantum_risk` | `algorithm` string | `_SHOR_BREAKS` / `_GROVER_WEAKENS` set membership | `QuantumRisk` |
| **4. Mosca** | `app/risk/mosca.py::assess` | X (from stage 2), Y + Z (from config), `quantum_vulnerable` (from 3b) | `margin = (x+y)-z`; tier thresholds | `MoscaAssessment` + `risk_tier` |
| **5. Recommendation** | `app/recommend/recommender.py::recommend` | The whole enriched `Finding` | 3-branch cascade + security-level table | `Recommendation` |

### Why the three risk axes are separate

**Plain English.** MD5 is broken today but a quantum computer barely changes
that. RSA-2048 is perfectly fine today but a quantum computer destroys it.
Collapsing those into one "risk score" would tell you neither thing.

**Working.** The code enforces the separation structurally:

- `assess_current_risk(algorithm)` and `assess_quantum_risk(algorithm)` each
  take only the algorithm string. Neither can see the other's verdict.
- `mosca.assess(...)` takes `quantum_vulnerable` as an explicit keyword
  argument. When `False` it returns early with `applicable=False` — the
  inequality is not silently evaluated against a primitive it does not
  describe.
- `recommend()` checks `is_currently_weak` **before** looking at
  `risk_tier`, so a broken-today finding never gets a "migrate by 2035"
  recommendation.

---

## 4. Architecture map

```
                    ┌───────────────────────────────────────────┐
                    │  React 19 + Vite + TypeScript frontend    │
                    │  14 pages · 14 dashboard panels           │
                    └────────────────────┬──────────────────────┘
                                         │ HTTPS + Firebase ID token
                    ┌────────────────────▼──────────────────────┐
                    │  FastAPI  ·  23 endpoints under /api      │
                    │  app/main.py::create_app()                │
                    └────────────────────┬──────────────────────┘
                                         │
                    ┌────────────────────▼──────────────────────┐
                    │  app/pipeline.py::run_pipeline()          │
                    │  → (Scan, list[Finding], cbom_json)       │
                    └──┬──────┬──────┬──────┬──────┬──────┬─────┘
                       │      │      │      │      │      │
     ┌─────────────────┘      │      │      │      │      └──────────────┐
     ▼                        ▼      ▼      ▼      ▼                     ▼
┌──────────┐        ┌──────────┐ ┌──────┐ ┌────┐ ┌─────────┐    ┌──────────────┐
│ SCANNER  │        │EXTRACTOR │ │CLASS-│ │RISK│ │RECOMMEND│    │    CBOM      │
│ 11 paths │───────▶│ normalize│▶│IFIER │▶│    │▶│         │    │ builder +    │
└──────────┘        └──────────┘ └──────┘ └────┘ └─────────┘    │ validator    │
                                                      │          └──────────────┘
                                                      ▼
                                              ┌──────────────┐
                                              │   ROADMAP    │
                                              │   planner    │
                                              └──────┬───────┘
                                                     ▼
                              ┌──────────────────────────────────────┐
                              │ COMPLIANCE evaluator (re-run Mosca   │
                              │ per Z preset) → REPORT (HTML/PDF/CSV)│
                              └──────────────────────────────────────┘

Deliverable surfaces                Persistence
────────────────────                ───────────
REST API (FastAPI)                  Firebase Auth (ID token verification)
CLI: blindspot-scan {scan,diff,gate} Firestore + Cloud Storage (optional)
GitHub Action (Docker)              Local artefact mirror (ALWAYS written)
                                    Fallback cache (last_scan.json)
```

**Reading the map, plainly.** Data flows strictly left to right. A value is
derived in exactly one place and read downstream. The CBOM is produced from
the *normalised* findings (before risk analysis), while the report is
produced from the *enriched* findings — both describe the same scan, and
neither recomputes the other's numbers.

**The one-directional rule, technically.** No module downstream of
`app/evidence/extractor.py` ever mutates a `NormalizedFinding` field.
`_enrich_finding` constructs a new `Finding` with `**nf.model_dump()` plus
the analysis objects, then attaches the recommendation with
`finding.model_copy(update={"recommendation": rec})`. The report layer's
module docstring states the rule explicitly: *"Nothing is computed here."*

---

# Part II — Core pipeline working

## 5. `run_pipeline` end to end

**File.** `backend/app/pipeline.py`

**Signature.**

```python
def run_pipeline(
    target: Path,
    *,
    project_id: str = "demo",
    owner_id: str | None = None,
    settings: Settings | None = None,
    tls_targets: list[str] | None = None,
) -> tuple[Scan, list[Finding], str]:
```

**Plain English.** One function call does the whole job: find everything,
score everything, produce the inventory, produce the plan. It never saves
anything — the caller decides where results go. If one scanner falls over,
the rest still produce results.

**Working — the exact sequence.**

1. `settings = settings or get_settings()`
2. `scan_id = f"scan-{uuid.uuid4().hex[:12]}"` — 12 hex chars, e.g.
   `scan-d9a047f2cd4c`
3. `started = datetime.now(timezone.utc)`; `t0 = time.monotonic()`
4. **Stage 1** — eleven discovery calls, each independently wrapped
   (§6 below)
5. `normalized = normalize(semgrep_matches, dep_findings, target)`
6. Split: dependency findings are **filtered out** of the analysis set
7. All other scanner outputs are `extend`ed into `source_findings`
8. **Stage 2** — `cbom_json = build_cbom_json(source_findings, project_name=project_id)`
   then `validate_cbom(json.loads(cbom_json))` (warn-only)
9. **Stages 3-5** — per-finding `_enrich_finding(...)` inside a try/except
10. `elapsed = time.monotonic() - t0`; `completed = datetime.now(timezone.utc)`
11. `summary = _build_summary(enriched)`
12. Construct and return `(Scan, enriched, cbom_json)`

**The critical ordering detail.** The CBOM is built at step 8 — *before*
enrichment at step 9. This means the CBOM describes discovered crypto
assets and carries no risk tiers. The risk annotation that the interop diff
looks for (`blindspot:riskTier`) is therefore absent from Blindspot's own
CBOM output as currently wired. Documented honestly in §50 and §63.

---

## 6. Stage 1 — Discovery fan-out

**Plain English.** Eleven different ways of finding cryptography, each in
its own protective wrapper. If semgrep hangs on a hostile file, you still
get your binary findings, your dependency findings, and your cloud KMS
inventory. A partial result beats no result.

**Working — the resilience pattern.** Every scanner call follows the same
shape:

```python
try:
    xxx_findings = scan_xxx(target, settings)
except Exception as exc:  # noqa: BLE001
    logger.warning("Xxx scan failed, continuing without it: %s", exc)
    xxx_findings = []
```

The source scanner additionally records the failure for provenance:

```python
source_scan_error: str | None = None
try:
    semgrep_matches = run_semgrep(target, settings)
except Exception as exc:
    logger.warning("Source scan (semgrep) failed, continuing without it: %s", exc)
    source_scan_error = str(exc)
    semgrep_matches = []
```

**Call order, exactly as coded.**

| # | Call | Gated by | On failure |
|---|---|---|---|
| 1 | `run_semgrep(target, settings)` | — | `[]` + `source_scan_error` set |
| 2 | `parse_dependencies(target)` | — | `[]` |
| 3 | `scan_binaries(target, settings)` | — | `[]` |
| 4 | `scan_infra(target, settings)` | — | `[]` |
| 5 | `scan_static_crypto(target, settings)` | — | `[]` |
| 6 | `scan_config_policy(target, settings)` | — | `[]` |
| 7 | `scan_pkcs11(settings)` | `pkcs11_scan_enabled` | `[]` |
| 8 | `scan_aws_kms(settings)` | `aws_kms_scan_enabled` | `[]` |
| 9 | `scan_azure_kv(settings)` | `azure_kv_scan_enabled` | `[]` |
| 10 | `scan_gcp_kms(settings)` | `gcp_kms_scan_enabled` | `[]` |
| 11 | `scan_tls(host, port, settings)` per target | `tls_scan_enabled` **and** `tls_targets` non-empty | that target skipped, loop continues |

Note that scanners 7-10 take **no target path** — they are
infrastructure-scoped. Running them as pipeline stages rather than separate
endpoints is deliberate: it keeps every attested key on the same
classify/risk/recommend code path as a source finding.

**TLS target parsing.** `_parse_tls_target(spec)` accepts `"host"` or
`"host:port"`, returns `None` for anything containing `://` or `/`, or with
a non-integer / out-of-range port. `None` → the target is logged and
skipped. Default port when unspecified is `443`.

**The dependency-finding filter — the most consequential line in the file.**

```python
source_findings: list[NormalizedFinding] = [
    f for f in normalized
    if f.evidence.detection_method.value != "dependency_manifest"
]
```

**Plain English.** A package listed in `requirements.txt` proves the
*capability* to do RSA, not that any RSA call exists. Scoring it as a real
finding would inflate every count with things that may never execute. So
dependency findings appear in the CBOM and the inventory, but they do **not**
go through classification, risk, or recommendation.

**Working.** Dependency findings are produced by
`extract_from_dependency` and therefore present in `normalized`, but are
excluded from `source_findings` before stage 2. They consequently never
appear in `enriched`, never contribute to `ScanSummary` counters, and never
reach the roadmap.

**What *is* extended into the analysis set.**

```python
source_findings.extend(binary_findings)
source_findings.extend(infra_findings)
source_findings.extend(static_crypto_findings)
source_findings.extend(config_policy_findings)
source_findings.extend(pkcs11_findings)
source_findings.extend(aws_kms_findings)
source_findings.extend(azure_kv_findings)
source_findings.extend(gcp_kms_findings)
source_findings.extend(tls_findings)
```

Nine of the eleven sources flow into full analysis. The pipeline comment
states the design intent: *"the pipeline's whole point is that new discovery
sources plug in at this boundary, not later."*

### 6.1 Target acquisition — how the scan root comes to exist

Everything above assumes `target` is already a directory on disk. It is not
always one to begin with. `POST /api/scan` accepts four different kinds of
target and resolves all of them to a local directory *before* `run_pipeline`
is called. That resolution is the job of two modules that are part of the
scanner package but perform no detection of their own:
`app/scanner/repository.py` and `app/scanner/container.py`.

**Plain English.** You can point Blindspot at a GitHub URL or a Docker image
instead of a folder. It clones or unpacks it into a temporary directory,
scans that directory with the exact same scanners, then deletes it. Because
both of those inputs come from the user, both are treated as hostile.

**Resolution precedence** (`app/api/scan.py`), first match wins, and the
first three only apply when `mode == ScanMode.LIVE`:

| Order | Request field | Resolves via | Guard |
|---|---|---|---|
| 1 | `repositoryUrl` | `clone_repository` | SSRF allowlist |
| 2 | `imageRef` | `prepare_image(image_ref=…)` | CLI pull + safe extract |
| 3 | `imageArchivePath` | `prepare_image(archive_path=…)` | **development only** |
| 4 | `repositoryPath` | used directly | **development only** |
| 5 | (nothing supplied) | `settings.demo_repo` | — |

Both local-filesystem paths (3 and 4) are refused with **400** unless
`BLINDSPOT_ENV` is `development`:

> `"Local path scanning is disabled here. Provide a repositoryUrl instead."`

That is deliberate. Accepting an arbitrary server-side path from an
authenticated HTTP client is an arbitrary-file-read primitive. It is useful
on a laptop and unacceptable in a deployment, so the environment decides.

Clone and extract both run under `asyncio.to_thread` — they are blocking
subprocess work and must not stall the event loop. A single-flight
`_scan_lock` returns **429** rather than stacking concurrent scans, and a
`finally` block calls `_cleanup_temp()` to remove the clone directory, the
image rootfs, and the temporary tarball on every exit path including failure.

#### 6.1.1 Repository URL ingestion — `app/scanner/repository.py`

The module docstring names the risk directly: a user-supplied URL cloned by
the server is an **SSRF-sensitive boundary**.

`validate_repository_url(url, settings)` performs **no network access** and
enforces five rules in order:

1. **HTTPS only.** Any other scheme is refused by name —
   `file://`, `git://`, `ssh://`, and plain `http://` are all rejected.
2. **Host must exist** after parsing.
3. **IP-literal hosts are rejected** via `_is_ip_literal` (`ipaddress.ip_address`).
   This blocks `https://169.254.169.254/...` and every other direct-to-internal
   address trick.
4. **Internal names rejected**: exactly `localhost`, or any host ending
   `.local` or `.internal`.
5. **Allowlist**: the host must equal an allowed host *or* be a subdomain of
   one (`host == allowed or host.endswith("." + allowed)`). Default allowlist
   is `github.com,gitlab.com,bitbucket.org` (`ALLOWED_GIT_HOSTS`, exposed as
   the computed `settings.git_host_allowlist`).

Then a path-sanity check: a bare host root with no `owner/repo` path is
refused.

Note the ordering comment in the source — the IP-literal check sits *outside*
the surrounding `try`, because `RepositoryError` subclasses `ValueError` and
an enclosing `except ValueError` would otherwise swallow the very error it
was raised to surface.

`clone_repository` then shells out to:

```
git clone --depth <git_clone_depth> --single-branch --no-tags <url> <dest>
```

into a fresh `tempfile.mkdtemp(prefix="ecdat-scan-", dir=settings.scan_work)`.
Defaults: `GIT_PATH=git`, `GIT_CLONE_DEPTH=1`,
`REPO_CLONE_TIMEOUT_SECONDS=0`. As with semgrep (§58), **0 means no timeout** —
the source comments that a large public repo on a slow link can legitimately
need many minutes, so an accidental "clone timed out" is impossible under
defaults. Every failure path calls `remove_clone(dest)` before raising, so a
partial clone is never left behind.

**`_classify_git_stderr(stderr, exit_code)`** exists because raw `git clone`
output is dominated by ANSI progress lines. It pattern-matches the
most-specific signatures first and returns one actionable sentence:

| Detected in stderr | Message returned |
|---|---|
| `repository not found`, or `http/2 stream` + `404` | not found / must be public |
| `authentication failed`, `401`, `403`, `access denied` | public repos only |
| `could not resolve host` | DNS failure |
| `connection refused` / `timed out` / `unreachable` | network unreachable |
| `ssl certificate problem`, `server certificate verification failed` | refusing untrusted TLS |
| `unable to access` + `the requested url returned error` | that exact line preserved (so 5xx / 429 survives) |
| (no match) | first `fatal:` line, else `stderr[:500]`, else exit-code message |

The fallbacks matter: the function never returns an empty string, and it
never discards signal — unmatched stderr is truncated, not dropped.

**`remove_clone(path)`** is a hardened `rmtree`. Git writes **read-only**
files under `.git` on Windows, which makes a plain `shutil.rmtree` fail; and
`ignore_errors=True` would silently leak the directory. The `_on_error`
handler chmods `stat.S_IWRITE` and retries, warning only if that also fails.
It is used by the container module too, via direct import.

`cloned_repository(url)` is the context-manager form and is the preferred
entry point — it removes the clone in `finally`, including on exception.

#### 6.1.2 Container image ingestion — `app/scanner/container.py`

**Plain English.** A container image is just a stack of tarballs. Flatten
them into one directory and it contains the same source files, manifests, and
binaries a repository would — so every existing scanner runs against it
unchanged. This module's only job is *"given an image, produce a directory"*.

Two acquisition paths:

- **Archive** — a `docker save` / OCI `docker-archive` tarball already on
  disk. Offline and fully deterministic; the reliable demo path.
- **Reference** — pull `name:tag` using a container CLI on the host.
  Best-effort. With no CLI present it raises a clear error rather than
  pretending.

```python
_KNOWN_CLIS   = ("docker", "podman", "nerdctl")   # preference order
_IMAGE_REF_RE = re.compile(r"^[A-Za-z0-9._:/@-]{1,512}$")
```

`validate_image_ref` checks shape only (registry/host, path, `:tag`,
`@sha256` digest). `_find_container_cli` returns the first of the three found
on `PATH`, or `None`.

`pull_image_to_archive` is deliberately **two steps**, because `docker save`
can only export images already in the local cache:

1. `<cli> image inspect <ref>` — exits 0 iff the image is already local (cheap).
2. If not, `<cli> pull <ref>` (slow, unavoidable).
3. `<cli> save <ref> -o <tar>`, then assert the tarball actually exists.

Each failure names which step failed and includes `stderr[:400]`.
`CONTAINER_CLI_TIMEOUT_SECONDS` defaults to **0 — unlimited**, for the same
reason as the clone timeout, and the timeout error message tells the operator
how to disable it.

**Extraction treats layers as untrusted archives.** `_extract_tar_safely`
walks members one at a time and applies five guards:

| Guard | Behaviour |
|---|---|
| Whiteout markers (`.wh.` prefix) | skipped — layer deletions are irrelevant to scanning |
| Path traversal / zip-slip | `_is_within(dest, target)` via `resolve().relative_to()`; outside members are logged and skipped |
| Symlinks and hardlinks | skipped entirely — they are the escape vector, and a scanner only needs real files |
| Special files (devices, FIFOs) | skipped — not scannable |
| Decompression bombs | `_Budget` charges every member |

```python
max_bytes = int(settings.container_max_extract_mb) * 1024 * 1024
budget    = _Budget(max_bytes=max_bytes, max_files=300_000)
```

`_Budget.charge(size)` accumulates `bytes` and `files` and raises
`ContainerError` when either ceiling is crossed, naming the limit that was
hit. Default `CONTAINER_MAX_EXTRACT_MB=1024` (1 GiB); the file-count cap of
**300,000** is a module constant, not configurable.

Note the guards are **skip-and-continue**, not abort — a single symlink does
not fail the scan — whereas a budget breach **aborts**, because past that
point the archive is no longer plausibly legitimate.

`_layer_paths_from_manifest` reads `manifest.json` and returns
`data[0]["Layers"]` in order, filtered to files that exist. If the manifest
is missing or unreadable it logs a warning and falls back to a **sorted**
`rglob` for `layer.tar`, `*.tar`, or anything under a `blobs` path — sorted
for determinism. Layers are then applied in order so later layers overlay
earlier ones, matching how a container filesystem is actually assembled.

`prepare_image(*, image_ref=None, archive_path=None)`:

- refuses immediately when `CONTAINER_SCAN_ENABLED` is false;
- enforces **exactly one** of the two inputs via `bool(a) == bool(b)`;
- creates `tempfile.mkdtemp(prefix="ecdat-img-root-", dir=settings.scan_work)`;
- on **any** exception, removes the partial rootfs *and* the temp tarball
  before re-raising;
- returns `(root_dir, tmp_tar)` where `tmp_tar` is `None` for the archive path.

`prepared_image_dir(...)` is the context-manager form and cleans up both in
`finally`.

**Configuration** (§58 addendum):

| Variable | Default | Notes |
|---|---|---|
| `CONTAINER_SCAN_ENABLED` | `true` | unlike the cloud scanners, on by default |
| `CONTAINER_MAX_EXTRACT_MB` | `1024` | bomb guard, `ge=1` |
| `CONTAINER_CLI_TIMEOUT_SECONDS` | `0` | 0 = unlimited |
| `GIT_PATH` | `git` | |
| `GIT_CLONE_DEPTH` | `1` | `ge=1` |
| `REPO_CLONE_TIMEOUT_SECONDS` | `0` | 0 = unlimited |
| `ALLOWED_GIT_HOSTS` | `github.com,gitlab.com,bitbucket.org` | computed → `git_host_allowlist` |

Neither module is a scanner in the §11–21 sense: neither returns findings,
and neither appears in the eleven-way fan-out. They are the reason the
fan-out can assume it has a directory.

---

## 7. Stage 2 — CBOM emission

**Plain English.** Turn the list of discovered crypto into a standard
machine-readable inventory (CycloneDX 1.6) that other tools can consume,
then check it actually conforms to the standard.

**Working.**

```python
cbom_json = build_cbom_json(source_findings, project_name=project_id)
cbom_doc = json.loads(cbom_json)
valid, errors = validate_cbom(cbom_doc)
if not valid:
    logger.warning("CBOM validation issues: %s", errors)
```

Validation is **advisory** at this point — a failing CBOM logs a warning and
the pipeline continues. The rationale: losing an entire scan because one
component tripped a schema edge case would be worse than emitting a CBOM
with a logged defect. Full builder and validator mechanics in §37 and §38.

---

## 8. Stages 3-5 — Per-finding enrichment

**File.** `backend/app/pipeline.py::_enrich_finding`

**Plain English.** For each discovered item, work out what it's for, whether
it's broken today, whether quantum breaks it, how urgent migration is, and
what to replace it with. Five decisions, in that order, each feeding the
next.

**Working — the exact code path.**

```python
def _enrich_finding(nf, scan_id, project_id, settings) -> Finding:
    classification = classify(nf)
    current_risk   = assess_current_risk(nf.algorithm)
    quantum_risk   = assess_quantum_risk(nf.algorithm)
    mosca_result   = assess(
        x=classification.data_lifetime_years,
        y=settings.migration_time_years,
        z=settings.quantum_horizon_years,
        z_source=settings.quantum_horizon_source,
        quantum_vulnerable=quantum_risk.is_quantum_vulnerable,
    )
    risk_tier = mosca_result.tier

    finding = Finding(
        **nf.model_dump(),
        scan_id=scan_id,
        project_id=project_id,
        classification=classification,
        current_risk=current_risk,
        quantum_risk=quantum_risk,
        mosca=mosca_result,
        risk_tier=risk_tier,
    )

    rec = recommend(finding)
    finding = finding.model_copy(update={"recommendation": rec})
    return finding
```

**Four facts worth internalising from this function:**

1. **X is per-finding; Y and Z are global.** `x` comes from the classifier's
   per-usage lifetime table. `y` and `z` come from `Settings` and are
   identical for every finding in a scan. That is why switching a Z preset
   re-tiers the whole scan coherently.
2. **`quantum_vulnerable` is always the Shor verdict.** Not a guess, not a
   default — the literal output of `assess_quantum_risk`.
3. **`risk_tier` is a straight copy of `mosca.tier`.** Including the
   `LOW_RISK` that the not-applicable branch assigns. There is no second
   tiering rule anywhere in the codebase.
4. **The recommendation is attached, not injected.** `recommend(finding)`
   receives the fully-enriched finding, so it can read `mosca.equation`
   verbatim into its rationale string.

**Failure isolation.** The call site wraps each finding:

```python
for nf in source_findings:
    try:
        finding = _enrich_finding(nf, scan_id, project_id, settings)
        enriched.append(finding)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to enrich finding %s: %s", nf.id, exc)
```

One malformed finding cannot fail a scan of five thousand.

---

## 9. Summary aggregation

**File.** `backend/app/pipeline.py::_build_summary`

**Plain English.** Count things up for the dashboard cards. Pure counting —
no new judgements.

**Working.** A single pass over `enriched` maintaining ten tallies plus
three `Counter` objects:

```python
for f in findings:
    total += 1
    algo_counter[f.algorithm] += 1
    type_counter[f.artefact_type.value] += 1
    conf_counter[f.evidence.confidence_level.value] += 1

    if f.is_quantum_sensitive:  quantum_sensitive += 1
    if f.is_currently_weak:     current_weak += 1
    if f.is_hndl_exposed:       hndl += 1
    if f.needs_verification:    needs_verif += 1
    if f.parameter_status.value == "unresolved": unresolved += 1
    if   f.risk_tier == RiskTier.OVERDUE:      overdue += 1
    elif f.risk_tier == RiskTier.TRANSITIONAL: transitional += 1
    elif f.risk_tier == RiskTier.LOW_RISK:     low_risk += 1
```

Every boolean read here is a `@computed_field` on `Finding` — so the summary
cannot disagree with the per-finding detail view. The tier counters use
`elif`, so they are mutually exclusive and sum to at most `total`.

Resulting `ScanSummary` fields: `total_findings`, `quantum_sensitive`,
`overdue`, `transitional`, `low_risk`, `current_weak_crypto`,
`hndl_exposed`, `needs_verification`, `unresolved_parameters`,
`by_algorithm`, `by_artefact_type`, `by_confidence`.

---

## 10. Caching and fallback mode

**Plain English.** If a live scan can't run (semgrep missing, demo machine
offline), the platform can serve the last successful scan instead — clearly
labelled as cached, never passed off as fresh.

**Working.**

```python
def save_cache(scan, findings, cbom_json, settings=None) -> None:
    data = {
        "scan": scan.serialise(),
        "findings": [f.serialise() for f in findings],
        "cbom": cbom_json,
    }
    cache_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
```

```python
def load_cached_result(settings=None) -> tuple[Scan, list[Finding], str] | None:
    if not cache_path.is_file():
        return None
    try:
        data = json.loads(cache_path.read_text(encoding="utf-8"))
        scan = Scan.model_validate(data["scan"])
        scan = scan.model_copy(update={"mode": ScanMode.CACHED})   # ← the honesty step
        findings = [Finding.model_validate(f) for f in data["findings"]]
        return scan, findings, data.get("cbom", "{}")
    except Exception as exc:
        logger.warning("Failed to load cached result: %s", exc)
        return None
```

**The honesty step.** `scan.mode` is forcibly rewritten to
`ScanMode.CACHED` on load. The frontend renders that as a visible banner
(`PhaseNotice`), and the executive report prints
`scan.mode.value.upper()` in its cover metadata. A cached scan can never
silently masquerade as live.

Cache location: `settings.fallback_cache`, default
`backend/app/data/cache/last_scan.json`.

---

# Part III — Discovery layer working

Eleven scanners. Each one produces `NormalizedFinding` objects on an
identical contract, so nothing downstream needs to know which scanner found
what. Each stamps a distinct `DetectionMethod` so provenance is never lost,
and each picks a confidence value that honestly reflects how strong its
evidence is.

## 11. Scanner 1 — Source code (semgrep)

**File.** `backend/app/scanner/semgrep.py`
**Entry point.** `run_semgrep(target: Path, settings: Settings | None = None) -> list[dict]`
**Detection method.** `semgrep_api_pattern`

**Plain English.** Runs semgrep with Blindspot's own rule pack over the
target directory. Semgrep tells us *where* a crypto API call is; a separate
step (§22) then figures out *what parameters* it was called with.

### 11.1 How the executable is located

`resolve_semgrep(settings)` tries three strategies in order:

1. `Path(settings.semgrep_path)` — if it points directly at an existing file,
   use it resolved.
2. `shutil.which(configured)` — the activated-venv or system-PATH case.
3. `_interpreter_script_dirs()` — directories that hold console scripts for
   the *running* interpreter:
   - `sysconfig.get_path("scripts")` and `sysconfig.get_path("purelib")`
   - `Path(sys.executable).parent`
   - that parent `+ "/Scripts"` (Windows) and `+ "/bin"` (POSIX)

This third strategy is what makes `uvicorn app.main:app` work when semgrep
was `pip install`ed into the same venv but the venv is not activated.

`require_semgrep(settings)` wraps it and raises `SemgrepNotAvailable` with a
fixable message naming the configured path and the install command.

### 11.2 The rule directory

`RULES_DIR = Path(__file__).resolve().parent / "rules"`. `rules_dir()`
raises `SemgrepNotAvailable` if the directory is missing.

### 11.3 The exact command line

```
<semgrep> scan
    --config <rules_dir>
    --json
    --quiet
    --metrics=off
    --no-git-ignore
    --exclude <pattern>          (repeated, ~40 times)
    <target>
```

- `--metrics=off` — no telemetry leaves the machine. Required for air-gap mode.
- `--no-git-ignore` — a `.gitignore`d vendored library still contains real
  crypto, so we scan it anyway.
- `--quiet` + `--json` — machine-parseable stdout only.

### 11.4 The exclusion list, and why it exists

`_SEMGREP_EXCLUDES` is a ~40-entry tuple. Grouped by intent:

| Group | Patterns |
|---|---|
| Compiled / binary | `*.so *.dll *.dylib *.exe *.sys *.pyd *.a *.lib *.o *.obj *.bundle *.bin` |
| Archives | `*.zip *.tar *.tar.gz *.tgz *.gz *.7z *.rar *.jar *.war *.whl` |
| Media / docs | `*.png *.jpg *.jpeg *.gif *.webp *.pdf *.svg *.mp4 *.mp3 *.ico *.woff *.woff2 *.ttf` |
| IaC (owned by the infra scanner) | `*.tf *.tfvars *.tf.json *.tfstate` |
| Noisy directories | `node_modules .git dist build __pycache__ .venv venv .mypy_cache .pytest_cache .semgrep` |

The source comment explains the binary exclusions specifically: *"On
Windows, real-time antivirus scans of large or ELF-magic files can otherwise
stall the semgrep process indefinitely."* This is a real operational fix, not
a performance nicety. Binaries are handled by scanner 4, IaC by scanner 5 —
excluding them here prevents double-reporting as well.

### 11.5 Subprocess invocation and the encoding fix

```python
proc = subprocess.run(
    cmd,
    capture_output=True,
    text=True,
    encoding="utf-8",
    errors="replace",
    timeout=subprocess_timeout(settings.semgrep_timeout_seconds),
)
```

**The `encoding="utf-8"` is load-bearing.** Without it Python decodes child
output with the OS locale codec — `cp1252` on Windows — which raises on any
non-cp1252 byte (e.g. `0x9d`) appearing in a scanned file's path or code
snippet. `errors="replace"` means one odd byte degrades a single character
rather than failing the whole scan.

**Timeout semantics.** `subprocess_timeout(0)` means *wait indefinitely*.
The source comment states the reasoning: a large polyglot repo can
legitimately keep semgrep busy for many minutes, and a fixed cap would
either kill real scans or mask a genuinely stuck process. On
`TimeoutExpired`, `SemgrepScanError` is raised with a message that names the
env var and tells the operator how to disable the cap.

### 11.6 Output handling

```python
raw = (proc.stdout or "").strip()
if not raw:
    raise SemgrepScanError(
        f"Semgrep produced no output (exit code {proc.returncode}). "
        f"stderr: {(proc.stderr or '')[:500]}"
    )
output = json.loads(raw)         # JSONDecodeError → SemgrepScanError with first 300 chars
```

Exit code is deliberately **not** treated as fatal: semgrep returns 0 on
success even with findings, and 1 on errors, but *partial results plus
errors* is a valid output shape. So stdout is parsed regardless, and
`output["errors"]` entries are logged individually at warning level
(`short_msg` plus first 200 chars of `long_msg`).

Returns `output.get("results", [])`. Logs match count, scanned-file count
(`output["paths"]["scanned"]`), and error count.

### 11.7 The rule pack — 11 files, ~100 rules

**Plain English.** One YAML file per algorithm family or per language. Each
rule carries `metadata.algorithm` so the extractor knows what it found
without re-parsing the pattern.

| File | Rules | Languages | Algorithms stamped |
|---|---|---|---|
| `rsa.yaml` | 3 | python | RSA (keygen, OAEP encrypt, export-key) |
| `ecc.yaml` | 4 | python | ECC, ECDH, ECDSA (sign + verify) |
| `aes.yaml` | 4 | python | AES (GCM keygen/encrypt/decrypt, generic Cipher) |
| `des.yaml` | 2 | python | 3DES, DES |
| `hash.yaml` | 5 | python | MD5 ×2, SHA-1 ×2, SHA-256 |
| `modes.yaml` | 6 | python | *(none — mode-only rules)* |
| `openssl_c.yaml` | 13 | c | RSA, ECC, ECDSA, ECDH, AES, DES, 3DES, MD5, SHA-1 |
| `java_crypto.yaml` | 22 | java | RSA, ECDSA, DSA, Ed25519, DH, AES, DES, 3DES, MD5, SHA-1, SHA-256, ECDH, X25519 |
| `javascript_crypto.yaml` | 31 | javascript, typescript | MD5, SHA-1, SHA-256, AES, DES, 3DES, ChaCha20, RSA, ECDSA, Ed25519, X25519, DSA |
| `go_crypto.yaml` | 19 | go | RSA, ECDSA, Ed25519, ECDH, X25519, DSA, AES, DES, 3DES, MD5, SHA-1, SHA-256 |

**Rule id convention.** Every id is prefixed `blindspot-`, then language
(for non-Python packs), then algorithm, then operation — e.g.
`blindspot-go-ecdsa-sign`, `blindspot-java-rsa-sign-weakhash`,
`blindspot-js-webcrypto-aes`. That convention is functionally significant:
the CBOM builder infers the CycloneDX `cryptoFunction` by substring-matching
the rule id (§37.3).

**`modes.yaml` is special.** Its six rules (`blindspot-mode-cbc`, `-gcm`,
`-ecb`, `-ctr`, `-ecb-pycryptodome`, `-cbc-pycryptodome`) carry **no**
`metadata.algorithm`. They exist purely to enrich algorithm findings with
cipher-mode information, and the extractor skips them as standalone findings
(§25). The JavaScript pack covers three separate ecosystems in one file —
`node:crypto`, WebCrypto (`crypto.subtle`), `node-forge`, and `crypto-js` —
because a single repo often mixes them.

---

## 12. Scanner 2 — Static crypto artefacts

**File.** `backend/app/scanner/static_crypto.py`
**Entry point.** `scan_static_crypto(target: Path, settings: Settings | None = None) -> list[NormalizedFinding]`
**Detection methods.** `static_cert_file`, `static_key_material`, `static_keystore`

**Plain English.** Finds certificates, private keys, and keystores sitting in
the repository as files — and also PEM blocks pasted inline into source or
config files. The file *is* the evidence: the algorithm and key size are read
straight out of the encoded bytes, so there is no guessing involved.

### 12.1 Extension routing

`_classify_path(path)` routes each candidate by suffix:

| Bucket | Extensions | Handling |
|---|---|---|
| Direct certificate | cert extensions (`.pem`, `.crt`, …) | parse with `cryptography.x509` |
| Direct key | `.key` | parse as private/public key |
| Direct DER | `.der` | try cert, then key |
| Keystore | `.p12`, `.pfx`, `.jks`, `.keystore` | existence-only finding |
| Inline PEM | text-y extensions (`_INLINE_PEM_EXTS`) | scan *contents* for `-----BEGIN` blocks |

### 12.2 Confidence values and why each is what it is

| Emitter | Confidence | Reasoning (from source comments) |
|---|---|---|
| `_emit_cert_finding` | **0.92** | "HIGH band — file is the evidence." |
| `_emit_key_finding` | **0.90** | "HIGH band — key bytes decoded, algorithm read." |
| `_emit_keystore_finding` | **0.90** | "File existence is high confidence; the contents are separately marked UNRESOLVED so needs_verification routes them to review." |

**The keystore design is the interesting one.** A `.p12` file is
password-protected, so its contents are genuinely opaque. Rather than guess
or omit it, the scanner emits a high-confidence finding (the file
*definitely* exists and *definitely* holds key material) with
`ParameterStatus.UNRESOLVED`. Downstream, `needs_verification` becomes
`True` and the recommender routes it to `INVESTIGATE`. The tool states what
it knows and what it doesn't.

### 12.3 Encrypted-material handling

Two specific `TypeError` paths — the exception
`cryptography` raises when a key needs a password:

```python
except TypeError:
    # Encrypted — file exists, algorithm is opaque.
    return _emit_keystore_finding(rel_path, "Encrypted-PEM")
```

and for DER:

```python
except TypeError:
    findings.append(_emit_keystore_finding(rel_path, "Encrypted-DER"))
```

Both reuse the keystore emitter, because the epistemic situation is
identical: we know material is present, we cannot read its parameters.

Keystore kind labels are resolved by suffix:
`{".p12": ..., ".pfx": ..., ".jks": "JKS", ".keystore": "JKS"}` with fallback
`"Keystore"`.

### 12.4 Deduplication

Keystore findings dedupe on `f"{rel}|{f.algorithm}|keystore"` so the same
file discovered via two code paths appears once.

### 12.5 Logging

```python
logger.info(
    "Static crypto scan: %d finding(s) across %d file(s) under %s.",
    len(findings), len({f.evidence.file_path for f in findings}), root.name or root,
)
```

`_relative(path, root)` returns `str(path.relative_to(root))`, falling back
to `path.name` on `ValueError` (path outside root).

---

## 13. Scanner 3 — Dependency manifests

**File.** `backend/app/scanner/dependency_parser.py`
**Entry point.** `parse_dependencies(target: Path) -> list[dict]`
**Detection method.** `dependency_manifest`

**Plain English.** Reads `requirements.txt`, `pom.xml`, `package.json`, and
`go.mod` and reports which crypto libraries are on the build path. This tells
you what the code *could* do, not what it *does* — so these findings are
informational only and are deliberately excluded from risk scoring.

### 13.1 The two honesty rules, from the module docstring

1. **"Only packages whose stated purpose is to provide cryptographic
   primitives."** A web framework that transitively depends on OpenSSL does
   not count.
2. **"Confidence is capped at the medium band."** A `pom.xml` entry for
   `bcprov-jdk18on` proves the JAR is on the classpath, not that it is
   invoked. Source scanning (scanner 1) is what proves invocation.

### 13.2 The four catalogues, with every actual confidence value

**Python** (`requirements*.txt`):

| Package | Provides | Confidence |
|---|---|---|
| `cryptography` | RSA, ECDH, ECDSA, AES, 3DES, SHA-1, SHA-256, MD5 | **0.70** |
| `pycryptodome` | RSA, DES, 3DES, AES, MD5, SHA-1, SHA-256 | **0.65** |
| `pycryptodomex` | RSA, DES, 3DES, AES, MD5, SHA-1, SHA-256 | **0.65** |
| `pynacl` | X25519, Ed25519, AES | **0.60** |
| `pyopenssl` | RSA, ECDH, ECDSA, AES, 3DES, SHA-1, SHA-256, MD5 | **0.50** |
| `pyca` | RSA, ECDH, ECDSA, AES, 3DES | **0.50** |
| `paramiko` | RSA, ECDSA, AES, 3DES | **0.45** |

**Java** (`pom.xml`):

| Package | Confidence |
|---|---|
| `org.bouncycastle:bcprov-jdk18on` | **0.65** |
| `org.bouncycastle:bcprov-jdk15on` | **0.65** |
| `org.bouncycastle:bcprov-ext-jdk18on` | **0.60** |
| `org.bouncycastle:bctls-jdk18on` | **0.60** |
| `com.google.crypto.tink:tink` | **0.60** |
| `org.bouncycastle:bcpkix-jdk18on` | **0.55** |
| `org.bouncycastle:bcpg-jdk18on` | **0.55** |
| `org.jasypt:jasypt` | **0.55** |
| `commons-codec:commons-codec` | **0.45** |

**JavaScript** (`package.json`):

| Package | Confidence |
|---|---|
| `node-forge` | **0.65** |
| `crypto-js` | **0.65** |
| `elliptic` | **0.60** |
| `tweetnacl` | **0.60** |
| `jsrsasign` | **0.60** |
| `jose` | **0.55** |
| `sshpk` | **0.50** |
| `jsonwebtoken` | **0.50** |

**Go** (`go.mod`):

| Package | Confidence |
|---|---|
| `golang.org/x/crypto` | **0.60** |
| `github.com/google/tink/go` | **0.60** |
| `github.com/cloudflare/circl` | **0.55** |
| `filippo.io/edwards25519` | **0.55** |
| `github.com/ProtonMail/go-crypto` | **0.55** |
| `github.com/miekg/pkcs11` | **0.40** |

Every value sits in the medium band (0.4–0.7), so `confidence_level`
resolves to `MEDIUM` or `LOW` — never `HIGH`. That is the cap the docstring
promises, enforced by data rather than by an assertion.

`github.com/miekg/pkcs11` at **0.40** is the lowest in any catalogue: PKCS#11
bindings indicate an HSM *surface*, and what algorithms actually live on the
token is a separate question that scanner 8 answers properly.

### 13.3 Per-ecosystem parsing quirks

| Ecosystem | Parser | Line numbers |
|---|---|---|
| pip | line-by-line text scan | real line number |
| Maven | `xml.etree.ElementTree` | **always `1`** — "ElementTree does not preserve source line numbers on 3.10" |
| npm | JSON parse | real line number |
| Go | line-by-line text scan | real line number |

**Go indirect dependencies are included.** The source comment: *"Indirect
dependencies (marked with `// indirect`) are still surfaced because a
transitive crypto library still puts the primitives on the build classpath.
Their confidence is the same as direct — capability signal is capability
signal."*

### 13.4 Directory skipping

`_SKIP_DIRS: frozenset[str]` includes `node_modules`, `.git`, and others.
The rationale in the source: vendored trees contain thousands of manifests
we should not re-parse, and skipping them *"dramatically speeds up scans of
real repositories."* The check is `any(part in _SKIP_DIRS for part in
candidate.relative_to(root).parts[:-1])` — note `[:-1]`, so the filename
itself is never matched against the skip set.

### 13.5 Output shape

`parse_dependencies` returns plain dicts (not `NormalizedFinding`), which
`extract_from_dependency` later expands into **one finding per algorithm in
`provides`**. So a single `cryptography==42.0.0` line produces eight
findings, each carrying the same 0.70 confidence and the same `raw_line`
snippet.

---

## 14. Scanner 4 — Compiled binaries

**File.** `backend/app/scanner/binary.py`
**Entry point.** `scan_binaries(target: Path, settings: Settings | None = None) -> list[NormalizedFinding]`
**Detection method.** `binary_signature`
**Confidence.** **0.55** — deliberately below the 0.6 medium threshold

**Plain English.** Looks inside `.dll`, `.so`, `.exe` and similar files for
the mathematical fingerprints of crypto algorithms — the specific constant
values MD5, SHA-1 and SHA-2 use to initialise their internal state, and the
ASN.1 object identifiers certificates use. Finding these proves a crypto
library is *linked in*; it does not prove any code path calls it. That's
why every binary finding is routed to manual review.

### 14.1 Why 0.55 specifically

From the source comment:

> Deliberately low band (< 0.6) so `needs_verification` flags every binary
> finding for human review. Fingerprint match is a hint, not a proof of use.

0.55 lands below the `ConfidenceLevel.MEDIUM` boundary (0.6), so
`confidence_level` evaluates to `LOW`, which makes `needs_verification`
`True` for **every** binary finding, unconditionally. The honesty property is
achieved through the confidence ladder rather than a special case.

### 14.2 File selection — `_looks_binary(path)`

Two-stage:

```python
_BINARY_EXTS: set[str] = {
    ".exe", ".dll", ".sys", ".pyd",       # PE
    ".so", ".a",                          # ELF / archive
    ".dylib", ".bundle",                  # Mach-O
    ".o", ".obj", ".lib",                 # object / static libs
}
```

If the suffix isn't recognised, sniff the first 8 bytes:

```python
_MAGIC_PREFIXES: tuple[bytes, ...] = (
    b"\x7fELF",           # ELF (Linux / BSD)
    b"MZ",                # DOS/PE (Windows)
    b"\xca\xfe\xba\xbe",  # Mach-O fat / Java class
    b"\xcf\xfa\xed\xfe",  # Mach-O 64-bit little-endian
    b"\xfe\xed\xfa\xcf",  # Mach-O 64-bit big-endian
    b"\xce\xfa\xed\xfe",  # Mach-O 32-bit little-endian
    b"!<arch>",           # Unix archive (.a)
)
```

An `OSError` on open returns `False` — unreadable files are skipped, not
fatal.

### 14.3 Fingerprint construction — the genuinely clever part

**Plain English.** Every hash algorithm starts from a fixed set of magic
numbers. Those numbers appear verbatim in any binary that implements the
algorithm. Blindspot reconstructs the exact byte layout each algorithm uses
on disk and searches for it.

**Working.** Three packers, differing only in byte order — which is itself
algorithm-specific:

```python
def _sha2_h0_bytes(*ints: int) -> bytes:
    """Pack 32-bit words big-endian, the layout SHA-2 constants take on disk."""
    return b"".join(struct.pack(">I", v) for v in ints)

def _md5_h0_bytes(*ints: int) -> bytes:
    """MD5 stores its A/B/C/D state little-endian on disk."""
    return b"".join(struct.pack("<I", v) for v in ints)

def _sha1_h0_bytes(*ints: int) -> bytes:
    """SHA-1 stores its H0..H4 state big-endian on disk."""
    return b"".join(struct.pack(">I", v) for v in ints)
```

SHA-512 uses 64-bit words:

```python
_SHA512_H0 = b"".join(struct.pack(">Q", v) for v in (
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
))
```

Getting the endianness right per algorithm is what makes this work at all —
searching for SHA-1's constants in little-endian order would never match.

### 14.4 ASN.1 OID fingerprints

Signature-algorithm OIDs, DER-encoded, keyed by a tuple carrying the full
domain classification:

```python
("RSA", CryptoPrimitive.SIGNATURE, ArtefactType.SIGNATURE,
 CryptoUsage.DIGITAL_SIGNATURE, "sha256WithRSAEncryption OID"):
    bytes.fromhex("2a864886f70d01010b"),

("ECDSA", CryptoPrimitive.SIGNATURE, ArtefactType.SIGNATURE,
 CryptoUsage.DIGITAL_SIGNATURE, "ecdsa-with-SHA256 OID"): ...
```

The key tuple carries `(algorithm, primitive, artefact_type, usage, label)`
so a match immediately produces a fully-classified finding with no lookup.

### 14.5 Library identification

`_LIBRARY_STRINGS` is a list of `(compiled_bytes_pattern, library, display)`
tuples. **Order matters — the comment says "more specific / branded strings
first":**

```python
(re.compile(rb"OpenSSL\s+(\d+\.\d+(?:\.\d+)?[a-z]?)"), "OpenSSL", "OpenSSL"),
(re.compile(rb"BoringSSL"),                              "BoringSSL", "BoringSSL"),
(re.compile(rb"wolfSSL\s+(\d+\.\d+(?:\.\d+)?)"),         "wolfSSL", "wolfSSL"),
(re.compile(rb"mbed\s*TLS\s+(\d+\.\d+(?:\.\d+)?)"),      "mbedTLS", "mbedTLS"),
(re.compile(rb"libsodium\s+(\d+\.\d+(?:\.\d+)?)"),       "libsodium", "libsodium"),
(re.compile(rb"libcrypto\.so"),                          "OpenSSL", "libcrypto"),
```

The OpenSSL pattern captures a version group including an optional letter
suffix (`1.1.1w`). `libcrypto.so` is listed last and maps back to OpenSSL —
a generic fallback after the branded patterns have had their chance.

### 14.6 Evidence shape

`line_number=None` (a binary has no lines). `file_path` is the repo-relative
path. The code snippet names which fingerprint matched.

---

## 15. Scanner 5 — Infrastructure / HSM / KMS declarations

**File.** `backend/app/scanner/infra.py`
**Entry point.** `scan_infra(target: Path, settings: Settings | None = None) -> list[NormalizedFinding]`
**Detection method.** `infra_declaration`
**Confidence.** **0.72**

**Plain English.** Scans Terraform, CloudFormation, Kubernetes manifests and
SDK code for declarations that a key-management surface exists — an AWS KMS
key, an Azure Key Vault, a CloudHSM cluster, a PKCS#11 module path. It proves
a vault *exists*; it says nothing about which algorithms are inside. Those
findings get routed to "investigate" rather than being scored.

### 15.1 The three deliberate properties, from the docstring

1. `DetectionMethod.INFRA_DECLARATION` — "the provenance is explicit: this is
   a *declared* reference, not a live attestation."
2. `ParameterStatus.UNRESOLVED` — "so the recommender routes them to
   INVESTIGATE."
3. Confidence 0.72 — medium band, above the 0.6 threshold (the declaration
   genuinely exists) but well below attested cloud findings at 0.95.

### 15.2 File selection

`_INFRA_EXTS` includes `.tf`, `.tf.json`, `.yaml`, `.yml` and further
config extensions. Checked as `path.suffix.lower() not in _INFRA_EXTS →
continue`.

### 15.3 The full declaration pattern table

Each entry is a `_Declaration` dataclass carrying
`(regex, algorithm_label, description, artefact_type, cloud, library)`:

**AWS KMS**

| Regex | Label | Artefact type |
|---|---|---|
| `\bresource\s+"aws_kms_key"` | AWS-KMS | `CLOUD_SERVICE` |
| `\bresource\s+"aws_kms_alias"` | AWS-KMS | `CLOUD_SERVICE` |
| `\bAWS::KMS::(Key\|Alias)\b` | AWS-KMS | `CLOUD_SERVICE` |
| `boto3\.client\(\s*['"]kms['"]` | AWS-KMS | `CLOUD_SERVICE` |
| `\bKMSClient\b\|\bAWSKMS\b` | AWS-KMS | `CLOUD_SERVICE` |

**AWS CloudHSM**

| Regex | Label | Artefact type |
|---|---|---|
| `\bresource\s+"aws_cloudhsm_v2_(cluster\|hsm)"` | AWS-CloudHSM | `HARDWARE_MODULE` |
| `\bAWS::CloudHSM::\w+` | AWS-CloudHSM | `HARDWARE_MODULE` |

**GCP KMS**

| Regex | Label |
|---|---|
| `\bresource\s+"google_kms_(crypto_key\|key_ring)"` | GCP-KMS |
| `\bKeyManagementServiceClient\b` | GCP-KMS |

**Azure**

| Regex | Label | Artefact type |
|---|---|---|
| `\bresource\s+"azurerm_key_vault(_key)?"` | Azure-KeyVault | `CLOUD_SERVICE` |
| `\bKeyClient\s*\(\|\bCryptographyClient\s*\(` | Azure-KeyVault | `CLOUD_SERVICE` |
| `\bresource\s+"azurerm_dedicated_hardware_security_module"` | Azure-HSM | `HARDWARE_MODULE` |

**Kubernetes**

| Regex | Label |
|---|---|
| `\bkind:\s*(SealedSecret\|ExternalSecret\|ClusterSecretStore)\b` | K8s-KMS-Backed-Secret |
| `kind:\s*EncryptionConfiguration\|kms:\s*\n\s+name:` | K8s-EncryptionAtRest |

**PKCS#11 / HSM vendors**

| Regex | Label | Vendor |
|---|---|---|
| `\bPKCS11_MODULE_PATH\b\|\bCKA_[A-Z_]+\b` | PKCS11-Module | generic |
| `libsofthsm2?\.so\|softhsm2?\.conf\|SOFTHSM2?_CONF` | PKCS11-SoftHSM | SoftHSM |
| `libykcs11\.so\|yubihsm2?_pkcs11` | PKCS11-YubiHSM | Yubico |
| `libcs_pkcs11_R2\|libcklog2\|SafeNet\|Luna` | PKCS11-Luna | SafeNet/Thales |
| `nfast\|nCipher\|Entrust\s+nShield` | PKCS11-nShield | Entrust |
| `\bPyKCS11\b\|python-pkcs11` | PKCS11-Module | Python bindings |

Note the vendor coverage is by *library filename*, which is the artefact
actually present in a deployment config — `libykcs11.so` appears in a
`softhsm2.conf` or a systemd unit, and that's what gets grepped.

### 15.4 Opportunistic key-spec extraction

```python
_KEY_SPEC_HINT = re.compile(
    r"(?:key_spec|customer_master_key_spec|key_type)\s*=\s*\"([A-Z0-9_]+)\"",
    re.IGNORECASE,
)
```

When a Terraform `aws_kms_key` block declares
`customer_master_key_spec = "RSA_4096"` near the matched resource, the
scanner captures it as a hint. It does not override `ParameterStatus.UNRESOLVED`
— the declaration is still a declaration.

### 15.5 Snippet truncation

`code_snippet=snippet[:200]` — infra files can carry very long lines
(inline JSON policies), and a 200-character cap keeps the evidence
displayable.

---

## 16. Scanner 6 — Config policy files

**File.** `backend/app/scanner/config_policy.py`
**Entry point.** `scan_config_policy(target: Path, settings: Settings | None = None) -> list[NormalizedFinding]`
**Detection method.** `config_policy_declared`
**Default confidence.** **0.70**

**Plain English.** Reads server and application configuration to find the
crypto policy that's actually configured — which TLS versions nginx accepts,
which ciphers Apache offers, what SSH is configured to use, what .NET's
machine key is set to. This is crypto that's real and live but appears in no
source file.

**Working.** Coverage per the module docstring:

| Source | What's parsed |
|---|---|
| OpenSSL `.cnf` | cipher strings, protocol minimums |
| nginx | `ssl_protocols`, `ssl_ciphers` |
| Apache | `SSLProtocol`, `SSLCipherSuite` |
| `sshd_config` | `Ciphers`, `MACs`, `KexAlgorithms`, `HostKeyAlgorithms` |
| .NET `web.config` | `sslProtocols` attributes, `machineKey` |

Builder signature:

```python
def _build_finding(
    ...,
    kind_label: str,
    curve: str | None = None,
    confidence: float = 0.70,
) -> NormalizedFinding:
```

`confidence` is a parameter with a 0.70 default, so individual call sites can
tune per-pattern certainty. Snippet capped at `[:200]` as with the infra
scanner.

Same helper pattern: `_relative(path, root)` with a `path.name` fallback, and
an INFO summary log naming finding count, distinct file count, and root.

---

## 17. Scanner 7 — Live TLS probe

**File.** `backend/app/scanner/tls.py`
**Entry point.** `scan_tls(host: str, port: int = 443, settings: Settings | None = None) -> tuple[dict, list[NormalizedFinding]]`
**Detection method.** `tls_probe`
**Confidence.** **0.95**

**Plain English.** Actually connects to a server, completes the TLS
handshake, and reads the certificate. This is the only scanner that observes
crypto in live use rather than inferring it from a file — hence the highest
confidence in the platform.

### 17.1 The SSRF boundary — the most security-critical code in the scanner layer

**Plain English.** The user supplies the hostname. Without a guard, anyone
could point Blindspot at `169.254.169.254` (the cloud metadata endpoint) or
`10.0.0.5` (an internal service) and use the scanner as a probe into a
private network.

**Working.** Before any connection, the host is resolved and **every**
resolved address is checked:

```python
if (
    ip.is_private
    or ip.is_loopback
    or ip.is_link_local
    or ip.is_reserved
    or ip.is_multicast
    or ip.is_unspecified
):
    → refuse
```

Six separate `ipaddress` predicates. The refusal is on *any* resolved
address, not just the first — so a hostname with mixed public and private A
records is rejected outright. Empty or whitespace-only hosts are refused
before resolution. Failure raises `TlsScanError`.

### 17.2 The handshake

```python
with socket.create_connection((cleaned, port), timeout=settings.tls_scan_timeout_seconds) as sock:
    with context.wrap_socket(sock, server_hostname=cleaned) as ssock:
        cert_der = ssock.getpeercert(binary_form=True)
        protocol = ssock.version() or "unknown"
        cipher   = ssock.cipher()      # (name, protocol, secret_bits)
```

`server_hostname=cleaned` enables SNI, which is required to get the correct
certificate from a virtual-hosted endpoint.
`getpeercert(binary_form=True)` returns raw DER, parsed with
`cryptography.x509` to read `key_type`, `key_bits`, and
`signature_algorithm`.

Failure handling: `except (socket.timeout, ssl.SSLError, OSError) as exc` →
`TlsConnectionError(f"TLS handshake failed for {cleaned}:{port}: {exc}")`.

### 17.3 Evidence for a thing that is not a file

```python
evidence = Evidence(
    file_path=f"{cleaned}:{port}",      # e.g. "example.com:443"
    line_number=None,
    code_snippet=f"{key_type} {key_bits or ''}-bit certificate; sig={sig_alg}; {protocol}",
    detection_method=DetectionMethod.TLS_PROBE,
    confidence=0.95,
)
```

The `file_path` field carries `host:port`. This is the convention every
non-file scanner follows (§21.2) and it is what lets the dashboard, the
inventory table, and the CBOM's `occurrences[].location` all render network
and cloud findings without a special case.

### 17.4 Pipeline integration

Gated by `settings.tls_scan_enabled`. When targets are supplied but the flag
is off:

```python
logger.info("TLS scan disabled by configuration; ignoring %d requested target(s).", len(tls_targets))
```

Per-target failures are caught at two levels in `run_pipeline` —
`TlsScanError` (validation refusal or connection failure) and bare
`Exception` — and both `continue` the loop. The comment cites the
requirement: *"PS Req 2 AC 5 says: an unreachable live target must be
recorded and the scan continues."*

---

## 18. Scanner 8 — PKCS#11 HSM attestation

**File.** `backend/app/scanner/pkcs11_scanner.py`
**Entry point.** `scan_pkcs11(settings: Settings | None = None) -> list[NormalizedFinding]`
**Detection method.** `pkcs11_attested`
**Confidence.** **0.95** — "HIGH band: the module answered with these attributes directly."

**Plain English.** Talks to a real hardware security module through the
PKCS#11 standard and asks it to list its keys. Off by default, because it
touches actual HSM hardware.

**Working — the four-gate short-circuit.** Returns `[]` when *any* of:

1. `not settings.pkcs11_scan_enabled` (default `False`)
2. `_pkcs11 is None` — `python-pkcs11` not installed; logs the install
   command
3. `settings.pkcs11_module_path.strip()` is empty
4. the module path does not point at a file

Each emits a distinct INFO log so the operator knows *which* gate stopped it.

**Evidence shape.**

```python
file_path=f"pkcs11://{module_path}#{token_label or 'default'}"
line_number=None
```

A PKCS#11 URI. Same convention as TLS: an addressable identifier in the
`file_path` slot.

---

## 19. Scanner 9 — AWS KMS attestation

**File.** `backend/app/scanner/aws_kms.py`
**Entry point.** `scan_aws_kms(settings: Settings | None = None, *, ...) -> list[NormalizedFinding]`
**Detection method.** `aws_kms_attested`
**Confidence.** **0.95** — "AWS answered with the algorithm directly."

**Plain English.** Asks AWS to list your KMS keys, then asks about each one:
what algorithm, what key size, what it's used for, and — importantly for
auditors — whether automatic rotation is switched on. Only reads metadata;
never touches key material.

### 19.1 The five discipline rules, from the docstring

1. **Opt-in.** `settings.aws_kms_scan_enabled` defaults to `False`; returns
   `[]` "before any AWS call is attempted."
2. Credentials come from the standard AWS chain only — "Requests never carry
   AWS keys."
3. **Only `DescribeKey` metadata is read** — no `GetKeyPolicy`, no signing or
   encryption operations.
4. Multi-region and pending-deletion keys are surfaced rather than hidden.
5. `boto3` is an optional import; absent → log once, return `[]`.

### 19.2 The rotation-status logic — a worked example of honest tri-state

**Plain English.** Not every KMS key *can* rotate. Asking about the ones
that can't either raises an error or returns something meaningless. So
Blindspot checks whether rotation even applies first, and when it doesn't,
reports "n/a" rather than "disabled".

**Working — `_rotation_supported(metadata) -> bool`** returns `False` for
four cases, each with a stated reason:

| Case | Why |
|---|---|
| Asymmetric keys (RSA, ECC, SM2) | "no rotation, `GetKeyRotationStatus` raises `UnsupportedOperationException`" |
| HMAC keys | "material is fixed, no rotation" |
| `KeyManager == 'AWS'` | "rotated on a schedule the customer does not control" |
| `Origin == 'EXTERNAL'` | customer owns the material |

**`_read_rotation_status(client, metadata) -> bool | None`** — "Never
raises":

```python
if not _rotation_supported(metadata):
    return None
key_id = metadata.get("KeyId")
if not key_id:
    return None
try:
    response = client.get_key_rotation_status(KeyId=key_id)
except (ClientError, BotoCoreError) as exc:
    logger.warning("GetKeyRotationStatus failed for %s: %s", key_id, exc)
    return None
value = response.get("KeyRotationEnabled")
return value if isinstance(value, bool) else None
```

The docstring states the guardrail outright: *"an honest 'we could not
determine this' rather than a fabricated `False`."*

**The tri-state rendering:**

```python
if   rotation_enabled is True:  rotation_str = "enabled"
elif rotation_enabled is False: rotation_str = "disabled"
else:                           rotation_str = "n/a"
```

With the source comment explaining each:

```
True  -> "enabled"   (automatic rotation is on)
False -> "disabled"  (rotation is available but off)
None  -> "n/a"       (asymmetric / HMAC / AWS-managed / external origin
                      -- rotation is not supported)
```

`False` and `None` are semantically different and are rendered differently.
That distinction is the whole point.

### 19.3 Evidence shape

```python
file_path = arn      # the full AWS ARN
line_number = None
code_snippet = (
    f"aws-kms key_id={key_id} spec={key_spec or 'unknown'} "
    f"usage={key_usage or 'unknown'} manager={key_manager} "
    f"state={key_state} origin={origin} rotation={rotation_str}"
)
```

Seven facts in one line, so a reviewer sees algorithm, size, usage,
management, lifecycle state, origin, and rotation together — which the
source comment ties to *"PS Req 2 AC 4 ... ('record the key algorithm, key
size, and rotation configuration')."*

### 19.4 Skipping rather than fabricating

`_resolve_key` returns `NormalizedFinding | None`. From its docstring:
pending-deletion or otherwise incomplete keys return truncated `KeyMetadata`
and *"we would rather skip them than fabricate."*

---

## 20. Scanners 10-11 — Azure Key Vault and GCP KMS

Both follow the AWS scanner's structure deliberately, so all three read the
same way.

### 20.1 Azure Key Vault

**File.** `backend/app/scanner/azure_kv.py`
**Entry point.** `scan_azure_kv(settings=None, *, ...) -> list[NormalizedFinding]`
**Detection method.** `azure_kv_attested` · **Confidence 0.95** — "the vault answered with the JWK directly."

Gates: `azure_kv_scan_enabled` (default `False`) → `AZURE_KV_VAULT_URL` set →
`azure-keyvault-keys` and `azure-identity` importable (install command
logged when absent).

Reads the **JWK** (JSON Web Key) for each key to determine algorithm and
parameters.

**Rotation detection, Azure-specific:** *"A rotation policy is considered
enabled when at least one lifetime action of type `Rotate` exists on the
returned policy. This matches what the Azure portal calls 'Auto rotation'."*
Same tri-state rendering as AWS; `None` when the API declines or errors.

`file_path = str(key_id_url)` — the vault key URL.

### 20.2 GCP KMS

**File.** `backend/app/scanner/gcp_kms.py`
**Entry point.** `scan_gcp_kms(settings=None, *, ...) -> list[NormalizedFinding]`
**Detection method.** `gcp_kms_attested` · **Confidence 0.95**

Gates: `gcp_kms_scan_enabled` (default `False`) → `GCP_KMS_PROJECT` set →
`google-cloud-kms` importable.

`_algorithm_name(version)` extracts the algorithm enum's string name from a
`CryptoKeyVersion`. Iterates key rings → crypto keys → primary version.

**Rotation unsupported when:**

```python
if protection in {"EXTERNAL", "EXTERNAL_VPC"}:  return False
if _algorithm_name(version).startswith("EXTERNAL_"):  return False
```

Externally-protected keys live outside Google's control, so rotation is not
Google's to report.

`file_path = key_name` — the fully-qualified GCP resource name.

---

## 21. Confidence ladder across all scanners

**Plain English.** How sure is the tool? The number is not decorative — it
drives whether a finding gets flagged for human review.

### 21.1 The bands

From `Evidence.confidence_level` in `app/models/finding.py`:

```python
if self.confidence >= 0.85: return ConfidenceLevel.HIGH
if self.confidence >= 0.6:  return ConfidenceLevel.MEDIUM
return ConfidenceLevel.LOW
```

And the consequence, from `Finding.needs_verification`:

```python
if self.parameter_status == ParameterStatus.UNRESOLVED: return True
return self.evidence.confidence_level == ConfidenceLevel.LOW
```

### 21.2 Every confidence value in the platform, ranked

| Value | Source | Band | Reasoning |
|---|---|---|---|
| **0.98** | semgrep + literal int keyword arg | HIGH | `key_size=2048` read directly from the AST |
| **0.95** | semgrep + module-level constant resolved | HIGH | `KEY_SIZE = 2048` in the same file |
| **0.95** | TLS probe | HIGH | observed live on the wire |
| **0.95** | PKCS#11 attested | HIGH | the HSM answered |
| **0.95** | AWS / Azure / GCP KMS attested | HIGH | the cloud API answered |
| **0.92** | static certificate file | HIGH | "the file is the evidence" |
| **0.90** | static key material | HIGH | key bytes decoded |
| **0.90** | static keystore (existence) | HIGH | file exists; contents separately `UNRESOLVED` |
| **0.90** | semgrep default (direct API call) | HIGH | pattern matched a known crypto API |
| **0.88** | semgrep on non-Python source | HIGH | AST skipped, but the semgrep match still stands |
| **0.72** | infra declaration | MEDIUM | declaration is real; contents unknown |
| **0.70** | config policy (default) | MEDIUM | configured policy, not observed traffic |
| **0.70** | dep: `cryptography` | MEDIUM | capability, not use |
| **0.70** | semgrep after `SyntaxError` | MEDIUM | file unparseable; match retained |
| **0.65–0.40** | other dependency packages | MEDIUM / LOW | see §13.2 |
| **0.55** | semgrep, param from an *imported* name | LOW | module-boundary policy (§23) |
| **0.55** | **binary signature** | **LOW** | deliberately sub-0.6 so every binary finding needs review |
| **0.50** | semgrep, param is a non-`Name` expression | LOW | e.g. `key_size=cfg["bits"]` |

**The non-file `file_path` convention.** Five scanners describe things that
are not files, and all five put an addressable identifier in `file_path`:

| Scanner | `file_path` format | Example |
|---|---|---|
| TLS | `host:port` | `example.com:443` |
| PKCS#11 | `pkcs11://<module>#<token>` | `pkcs11:///usr/lib/softhsm.so#demo` |
| AWS KMS | the ARN | `arn:aws:kms:us-east-1:...:key/abc` |
| Azure KV | the key URL | `https://vault.vault.azure.net/keys/k/v` |
| GCP KMS | the resource name | `projects/p/locations/l/keyRings/r/cryptoKeys/k` |

All five set `line_number=None`. Because `file_path` is always populated with
*something addressable*, the inventory table, the CBOM `occurrences[].location`,
and the blast-radius graph all handle network and cloud findings with no
special-casing.

---

# Part IV — Normalisation working

## 22. The evidence extractor

**File.** `backend/app/evidence/extractor.py`
**Entry points.** `normalize(...)`, `extract_from_semgrep_match(...)`, `extract_from_dependency(...)`

**Plain English.** Semgrep tells us *where* a crypto call is but not what
arguments it was called with. This module reads the actual source file,
slices out the matched text, and then parses the file's syntax tree to figure
out the key size or curve. The division of labour is summarised in the
module's own docstring:

> `semgrep LOCATES → we EXTRACT → ast RESOLVES`

**Why this split exists, technically.** Semgrep Community Edition does not
emit metavariable bindings or matched source text — its `lines` field
literally reads `"requires login"`. So the extractor must re-open the file
and work from byte offsets.

### 22.1 Deterministic finding IDs

```python
def _make_finding_id(check_id: str, file_path: str, line: int) -> str:
    raw = f"{check_id}:{file_path}:{line}"
    short_hash = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"CRYPTO-{short_hash}"
```

Produces e.g. `CRYPTO-a3f21c08`. Deterministic across runs and machines,
which is what makes the CBOM's `bom-ref` stable (§37.2) and what makes the
CI delta engine able to match findings between scans.

### 22.2 The algorithm-defaults table

`ALGORITHM_DEFAULTS: dict[str, dict[str, Any]]` — "the ONE place where we
map algorithm names to domain vocabulary." Keyed by the rule's
`metadata.algorithm`, each entry supplies `primitive`, `artefact_type`, and
`usage`. Examples:

| Algorithm | primitive | artefact_type | usage |
|---|---|---|---|
| RSA | `PKE` | `ENCRYPTION` | `KEY_GENERATION` |
| ECDH | `KEY_AGREE` | `KEY_EXCHANGE` | `KEY_ESTABLISHMENT` |
| ECDSA | `SIGNATURE` | `SIGNATURE` | `DIGITAL_SIGNATURE` |
| ECC | `UNKNOWN` | `UNKNOWN` | `KEY_GENERATION` |
| AES | `BLOCK_CIPHER` | `ENCRYPTION` | `DATA_ENCRYPTION` |
| DES / 3DES | `BLOCK_CIPHER` | `ENCRYPTION` | `DATA_ENCRYPTION` |
| MD5 / SHA-1 / SHA-256 / SHA-384 / SHA-512 | `HASH` | `HASH` | `INTEGRITY_HASH` |
| Ed25519 / Ed448 | `SIGNATURE` | `SIGNATURE` | *(EdDSA)* |

The source comment on the EC entries is worth quoting: *"Ed25519 / Ed448 are
EdDSA signatures on Edwards curves. X25519 / X448 are ECDH key agreement on
Montgomery curves. All four are elliptic-curve based and therefore
Shor-breakable."* — the classification encodes the cryptographic reasoning,
not just a label.

**`ECC` is deliberately `UNKNOWN`/`UNKNOWN`.** `ec.generate_private_key()`
could serve ECDH or ECDSA; the extractor refuses to guess and leaves the
dedicated ECDH/ECDSA rules to produce their own findings.

### 22.3 Usage refinement

`_FUNCTION_USAGE: dict[str, CryptoUsage]` overrides the default when the
rule's `crypto_function` metadata is more specific — e.g.
`"encrypt"`/`"decrypt"` → `DATA_ENCRYPTION`, `"digest"` → `INTEGRITY_HASH`.
Resolution order:

```python
usage = _FUNCTION_USAGE.get(crypto_function, defaults.get("usage", CryptoUsage.UNKNOWN))
```

A late special case handles RSA used for encryption rather than key
generation:

```python
if algorithm == "RSA" and crypto_function == "encrypt":
    usage = CryptoUsage.DATA_ENCRYPTION
    artefact_type = ArtefactType.ENCRYPTION
```

This matters downstream: `KEY_GENERATION` carries a 10-year lifetime while
`DATA_ENCRYPTION` carries 5, so the refinement directly changes the Mosca X
value.

### 22.4 Primitive override from rule metadata

```python
if metadata.get("primitive"):
    try:
        primitive = CryptoPrimitive(metadata["primitive"])
    except ValueError:
        pass
```

A rule may state the primitive explicitly; an unrecognised string is
silently ignored rather than crashing the scan.

### 22.5 Source-file resolution

Three attempts, because semgrep's `path` may be absolute or relative:

```python
file_path = Path(file_path_raw)
if not file_path.is_absolute():
    file_path = target_root / file_path
if not file_path.is_file():
    file_path = target_root / Path(file_path_raw).name    # last resort: basename
    if not file_path.is_file():
        logger.warning("Source file not found for evidence: %s", file_path_raw)
        return None
```

Read with `errors="replace"`:

```python
source = file_path.read_text(encoding="utf-8", errors="replace")
```

The comment: *"keeps the scan alive on files with non-UTF-8 bytes, which
occur in large C codebases like OpenSSL."* An `OSError` logs and returns
`None`.

### 22.6 Snippet and context extraction

```python
def _read_evidence_snippet(source, start_offset, end_offset, start_line):
    snippet = source[start_offset:end_offset]
    lines = source.splitlines()
    context_start = max(0, start_line - 3)
    context_end = min(len(lines), start_line + 3)
    return snippet.strip(), lines[context_start:context_end]
```

Snippet comes from **byte offsets** (exact match extent); context comes from
**line numbers** (2 lines either side, clamped to file bounds). The
`CodeEvidence` frontend component renders the snippet highlighted within
the context.

### 22.7 Relative path for evidence

```python
try:
    rel_path = file_path.relative_to(target_root)
except ValueError:
    rel_path = file_path
```

Repo-relative when possible. This is what makes the benchmark harness able
to bucket findings by manifest-declared filename (§45.3), and what makes the
blast-radius graph's file nodes readable.

---

## 23. AST parameter resolution and the module-boundary policy

**Plain English.** Knowing you called `rsa.generate_private_key(...)` isn't
enough — you need the key size. Blindspot parses the file and tries to
resolve it. But it only trusts values it can see in *that file*; a constant
imported from elsewhere is honestly marked unresolved rather than chased
across modules.

### 23.1 Python-only gate

```python
is_python_source = file_path.suffix.lower() in (".py", ".pyi")
try:
    if not is_python_source:
        confidence = 0.88
        raise _SkipASTAnalysis
    tree = ast.parse(source)
    ...
except _SkipASTAnalysis:
    pass
except SyntaxError:
    logger.warning("Could not parse %s for AST extraction.", rel_path)
    confidence = 0.7
```

`_SkipASTAnalysis` is a private sentinel exception used purely for
control flow — the docstring says it's *"Kept as a control-flow exception so
the existing `except SyntaxError:` fallback stays untouched."*

**Why 0.88 for non-Python.** From the inline comment: Java/JS/TS/Go findings
cannot have parameters resolved from a *Python* syntax tree, but *"the
semgrep AST match itself is still strong evidence, so we keep the confidence
at the high band rather than penalising every non-Python finding as if it
were a text match."* Their `parameter_status` stays `NOT_APPLICABLE` and the
rule's own metadata carries the algorithm. A per-language extractor is named
as a later upgrade.

### 23.2 The three AST helpers

```python
def _module_constants(tree) -> dict[str, int]:
    """Integer constants assigned at module level in THIS file."""
```
Walks `tree.body` only (not `ast.walk`) — so it picks up module-level
`KEY_SIZE = 2048` but deliberately not a value assigned inside a function.

```python
def _imported_names(tree) -> dict[str, str]:
    """Names bound by import in this file, mapped to source module."""
```
Handles both `ImportFrom` and `Import`, honouring `asname`.

```python
def _find_call_at_line(tree, line) -> ast.Call | None:
    """Find the ast.Call node closest to the given line number."""
```
Minimises `abs(node.lineno - line)` across all `ast.Call` nodes. *Closest*,
not exact — semgrep's reported line and the AST's `lineno` can differ by one
on multi-line calls.

### 23.3 The module-boundary policy — `_resolve_integer_arg`

**Plain English.** Three outcomes. If the value is a number written right
there, we know it. If it's a constant defined in the same file, we know it. If
it came from an import, we say so and flag it for a human.

**Working.**

```python
def _resolve_integer_arg(name, constants, imports):
    # Imported from elsewhere — not ours to resolve.
    if name in imports:
        return (None, ParameterStatus.UNRESOLVED, 0.55, [name])

    # Defined at module level in this file — sound to resolve.
    if name in constants:
        return (str(constants[name]), ParameterStatus.RESOLVED, 0.95, [])

    # Unknown origin.
    return (None, ParameterStatus.UNRESOLVED, 0.55, [name])
```

The unresolved name is returned in a list which becomes
`NormalizedFinding.unresolved_parameters`, and the classifier's rationale
renders it verbatim (*"Parameter could not be resolved (KEY_SIZE)"*).

### 23.4 Keyword-argument extraction

```python
def _extract_key_size_from_call(call_node, constants, imports, keyword_name="key_size"):
    for kw in call_node.keywords:
        if kw.arg != keyword_name:
            continue
        if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
            return str(kw.value.value), ParameterStatus.RESOLVED, 0.98, []
        if isinstance(kw.value, ast.Name):
            return _resolve_integer_arg(kw.value.id, constants, imports)
        # Anything else (attribute, subscript, call, etc).
        return None, ParameterStatus.UNRESOLVED, 0.5, [keyword_name]
    return None, ParameterStatus.NOT_APPLICABLE, 0.0, []
```

Four outcomes, four confidence values:

| Shape | Example | Status | Confidence |
|---|---|---|---|
| Integer literal | `key_size=2048` | `RESOLVED` | **0.98** |
| Name → module constant | `key_size=KEY_BITS` (defined here) | `RESOLVED` | **0.95** |
| Name → imported | `key_size=KEY_BITS` (imported) | `UNRESOLVED` | **0.55** |
| Any other expression | `key_size=cfg["bits"]` | `UNRESOLVED` | **0.50** |
| Keyword absent | — | `NOT_APPLICABLE` | 0.0 *(ignored)* |

`_extract_bit_length` is a thin wrapper passing `keyword_name="bit_length"`,
for `AESGCM.generate_key(bit_length=N)`.

**Guard at the call site:** the result is only applied when
`status != ParameterStatus.NOT_APPLICABLE`, so a missing keyword leaves the
default 0.9 confidence intact rather than zeroing it.

Applied for exactly two algorithm/function pairs:

```python
if algorithm == "RSA" and crypto_function == "keygen" and call_node: ...
elif algorithm == "AES" and crypto_function == "keygen" and call_node: ...
```

### 23.5 Curve extraction

```python
def _find_curve_in_file(tree) -> str | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in _CURVE_NAMES:
                return _CURVE_NAMES[node.func.attr]
    # Also check module-level assignments like MESH_CURVE = ec.SECP256R1()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in _CURVE_NAMES:
            return _CURVE_NAMES[node.attr]
    return None
```

Two passes: calls first (`ec.SECP256R1()`), then bare attribute references
(`MESH_CURVE = ec.SECP256R1`).

`_CURVE_NAMES` handles both casings the `cryptography` library exposes:

```python
{
    "secp256r1": "secp256r1", "SECP256R1": "secp256r1",
    "secp384r1": "secp384r1", "SECP384R1": "secp384r1",
    "secp521r1": "secp521r1", "SECP521R1": "secp521r1",
    "X25519": "x25519",
    "Ed25519": "ed25519",
}
```

Applied only for `algorithm in ("ECC", "ECDH", "ECDSA")`, and when a curve
is found it is normalised to the NIST short name for the `parameter` field:

```python
curve_to_param = {
    "secp256r1": "P-256",
    "secp384r1": "P-384",
    "secp521r1": "P-521",
    "x25519":    "X25519",
    "ed25519":   "Ed25519",
}
parameter = curve_to_param.get(curve, curve)
parameter_status = ParameterStatus.RESOLVED
```

So an ECDSA finding ends up with `curve="secp256r1"` **and**
`parameter="P-256"` — which is exactly what the security-level classifier
needs, since `_ECC_CURVE_BITS` accepts either spelling (§31.4).

---

## 24. Two-pass mode enrichment

**Plain English.** `AES` and `AES in ECB mode` are very different risks. The
mode is usually written a line or two away from the algorithm, so Blindspot
collects all the modes in a file first, then attaches them to the algorithm
findings in that file.

**Working — inside `normalize()`.**

**Pass 1** — build a file → modes index from the mode-only rules:

```python
modes_by_file: dict[str, set[CipherMode]] = {}
for match in semgrep_matches:
    rule_name = check_id.split(".")[-1] if "." in check_id else check_id
    if rule_name.startswith("blindspot-mode-"):
        mode_str = match.get("extra", {}).get("metadata", {}).get("mode")
        file_path = match.get("path", "")
        if mode_str and mode_str in _MODE_MAP:
            modes_by_file.setdefault(file_path, set()).add(_MODE_MAP[mode_str])
```

`_MODE_MAP: dict[str, CipherMode]` = `cbc`, `gcm`, `ecb`, `ctr`, `cfb`,
`ofb`, `ccm`.

**Pass 2** — extract findings and enrich:

```python
for match in semgrep_matches:
    finding = extract_from_semgrep_match(match, target_root)
    if finding and finding.id not in seen_ids:
        if finding.mode is None:
            file_modes = modes_by_file.get(match.get("path", ""), set())
            if len(file_modes) == 1:
                finding = finding.model_copy(update={"mode": file_modes.pop()})
            elif len(file_modes) > 1:
                priority = [CipherMode.ECB, CipherMode.CBC, CipherMode.GCM,
                            CipherMode.CTR, CipherMode.CFB, CipherMode.OFB]
                for m in priority:
                    if m in file_modes:
                        finding = finding.model_copy(update={"mode": m})
                        break
        findings.append(finding)
        seen_ids.add(finding.id)
```

**The priority order is a security decision.** `ECB > CBC > GCM > CTR > CFB >
OFB` — worst first. From the source comment: *"Multiple modes — pick the most
concerning for the primary finding. ECB > CBC > GCM for weak-mode
prioritization."* A file using both ECB and GCM is reported as ECB, because
that's the mode that needs attention.

The mode is only applied when `finding.mode is None` — a rule that already
declared its own mode (`blindspot-aes-gcm-keygen` via
`metadata.mode`) is never overwritten.

**Dependency findings are appended after,** using the same `seen_ids` set:

```python
for dep in dependency_findings:
    for finding in extract_from_dependency(dep, target_root):
        if finding.id not in seen_ids:
            findings.append(finding)
            seen_ids.add(finding.id)
```

**Final log** splits the two sources:

```python
logger.info(
    "Normalization complete: %d findings (%d from source, %d from dependencies).",
    len(findings),
    sum(1 for f in findings if f.evidence.detection_method != DetectionMethod.DEPENDENCY_MANIFEST),
    sum(1 for f in findings if f.evidence.detection_method == DetectionMethod.DEPENDENCY_MANIFEST),
)
```

---

## 25. Deliberate skips

`extract_from_semgrep_match` returns `None` — dropping the match entirely —
in four cases. Two are deliberate policy, two are data problems.

### 25.1 Mode-only rules

```python
if rule_name.startswith("blindspot-mode-"):
    return None
```

They exist to enrich (§24), not to stand alone. Six rules in `modes.yaml`
never produce findings of their own.

### 25.2 Incidental SHA-256

```python
if algorithm == "SHA-256":
    return None
```

With the reasoning stated in full:

> Skip incidental SHA-256 detections (used inside OAEP, ECDSA, HKDF).
> SHA-256 is not weak and not quantum-relevant. Including it inflates
> findings without adding information for the judge.

**Plain English.** Every RSA-OAEP call internally uses SHA-256. Reporting
each one would triple the finding count with items that are neither weak nor
quantum-vulnerable and for which the recommendation would always be "no
action". The rules still *exist* (`blindspot-sha256-cryptography`,
`blindspot-java-sha256`, `blindspot-go-sha256`, `blindspot-js-cryptojs-sha256`)
so the capability is there — the extractor filters at the boundary.

**Documented consequence.** SHA-256 never appears in `by_algorithm`, never in
the CBOM, never in the inventory. If a future requirement needs full hash
inventory, this is the one line to change.

### 25.3 Source file unreachable

Covered in §22.5 — all three resolution attempts fail → warning + `None`.

### 25.4 Source file unreadable

`OSError` on `read_text` → warning + `None`.

---

# Part V — Analysis engines working

## 26. The classifier

**File.** `backend/app/classifier/classifier.py`
**Entry point.** `classify(finding: NormalizedFinding) -> Classification`

**Plain English.** Works out what the cryptography is *for* — protecting
secrecy, proving authenticity, or checking integrity — and how long whatever
it protects needs to stay protected. That lifetime number is the single most
important input to the whole risk calculation.

**Working.** A pure function. Takes no `Settings`, performs no I/O, has no
state. Five module-level tables and a rationale builder.

### 26.1 The central insight, from the module docstring

> *Confidentiality* cryptography (key establishment, encryption) is dominated
> by data lifetime — harvest-now-decrypt-later means data recorded today can
> be decrypted once a quantum computer exists.
>
> *Authenticity* cryptography (signatures) is judged differently. A
> short-lived session signature carries little quantum urgency; a root CA,
> code-signing, or firmware-signing key anchors trust for years and gets
> special handling.

That asymmetry is why a 15-minute JWT signature and a 20-year root CA — both
signatures — get lifetimes of `0.04` and `20.0` years respectively.

### 26.2 Table 1 — `_USAGE_TO_GOAL`

All 16 `CryptoUsage` members are mapped explicitly.

| Security goal | Usages |
|---|---|
| **CONFIDENTIALITY** | `KEY_ESTABLISHMENT`, `KEY_TRANSPORT`, `DATA_ENCRYPTION`, `DATA_AT_REST_ENCRYPTION`, `TRANSPORT_ENCRYPTION`, `KEY_GENERATION`, `KEY_DERIVATION` |
| **AUTHENTICITY** | `DIGITAL_SIGNATURE`, `SESSION_SIGNATURE`, `CERTIFICATE_SIGNING`, `CODE_SIGNING` |
| **INTEGRITY** | `INTEGRITY_HASH`, `PASSWORD_HASHING`, `MESSAGE_AUTHENTICATION` |
| **UNKNOWN** | `RANDOM_GENERATION`, `UNKNOWN` |

Fallback: `SecurityGoal.UNKNOWN`. Since every member is mapped, the fallback
is only reachable if the enum grows without the table being updated.

**This table gates HNDL.** Only `CONFIDENTIALITY` findings can ever be
HNDL-exposed (§30), so which bucket a usage lands in has direct operational
consequences.

### 26.3 Table 2 — `_USAGE_TO_LIFETIME` (Mosca X, in years)

| Usage | X | Source comment |
|---|---|---|
| `CERTIFICATE_SIGNING` | **20.0** | "Root CAs anchor trust for decades" |
| `DATA_AT_REST_ENCRYPTION` | **15.0** | "Statutory retention" |
| `CODE_SIGNING` | **15.0** | "Signed binaries remain deployed for years" |
| `KEY_GENERATION` | **10.0** | "Keys often outlive the data they protect" |
| `DATA_ENCRYPTION` | **5.0** | |
| `KEY_ESTABLISHMENT` | **5.0** | |
| `KEY_TRANSPORT` | **5.0** | |
| `KEY_DERIVATION` | **5.0** | |
| `PASSWORD_HASHING` | **5.0** | |
| `TRANSPORT_ENCRYPTION` | **3.0** | |
| `DIGITAL_SIGNATURE` | **3.0** | |
| `INTEGRITY_HASH` | **1.0** | |
| `MESSAGE_AUTHENTICATION` | **1.0** | |
| `RANDOM_GENERATION` | **1.0** | |
| `SESSION_SIGNATURE` | **0.04** | "~15 minutes to 1 hour" |
| `UNKNOWN` | **5.0** | |

Fallback: **5.0**.

**Worked consequence.** With defaults `Y=3.0`, `Z=10.0`:

- `CERTIFICATE_SIGNING`: `20.0 + 3.0 = 23.0 > 10.0` → **OVERDUE**
- `KEY_GENERATION`: `10.0 + 3.0 = 13.0 > 10.0` → **OVERDUE**
- `DATA_ENCRYPTION`: `5.0 + 3.0 = 8.0`, not `> 10.0`, but `> 5.0` → **TRANSITIONAL**
- `INTEGRITY_HASH`: `1.0 + 3.0 = 4.0`, not `> 5.0` → **LOW-RISK**
- `SESSION_SIGNATURE`: `0.04 + 3.0 = 3.04` → **LOW-RISK**

This is why the demo repo's RSA key-generation findings land in `overdue`
while a JWT signature does not — and it is derivable by hand from these two
tables plus the two config values.

### 26.4 Table 3 — `_USAGE_TO_CRITICALITY`

| Criticality | Usages |
|---|---|
| **HIGH** | `DATA_AT_REST_ENCRYPTION`, `KEY_GENERATION`, `CERTIFICATE_SIGNING`, `CODE_SIGNING`, `INTEGRITY_HASH`, `PASSWORD_HASHING` |
| **MEDIUM** | `DATA_ENCRYPTION`, `KEY_ESTABLISHMENT`, `KEY_TRANSPORT`, `KEY_DERIVATION`, `TRANSPORT_ENCRYPTION`, `DIGITAL_SIGNATURE`, `MESSAGE_AUTHENTICATION`, `UNKNOWN` |
| **LOW** | `SESSION_SIGNATURE`, `RANDOM_GENERATION` |

Fallback: `MEDIUM`. Feeds `_CRIT_WEIGHT` in the roadmap priority score (§35.2).

### 26.5 Table 4 — `_LONG_LIVED_TRUST_ANCHORS`

```python
_LONG_LIVED_TRUST_ANCHORS: set[CryptoUsage] = {
    CryptoUsage.CERTIFICATE_SIGNING,
    CryptoUsage.CODE_SIGNING,
}
```

Exactly two members. Sets `is_long_lived_trust_anchor`, which switches the
rationale to the trust-anchor phrasing (§26.8).

*Documentation note:* the module docstring mentions "firmware signing" as a
trust anchor, but no `FIRMWARE_SIGNING` member exists in `CryptoUsage` and
none is in this set. See §63.

### 26.6 Table 5 — `_WEAK_ALGORITHMS`

```python
_WEAK_ALGORITHMS: dict[str, Criticality] = {
    "MD5":  Criticality.HIGH,
    "SHA-1": Criticality.HIGH,
    "DES":  Criticality.HIGH,
    "3DES": Criticality.HIGH,
}
```

### 26.7 The escalation rule — monotone upward only

```python
criticality = _USAGE_TO_CRITICALITY.get(usage, Criticality.MEDIUM)
if algorithm in _WEAK_ALGORITHMS:
    weak_crit = _WEAK_ALGORITHMS[algorithm]
    crit_order = {Criticality.LOW: 0, Criticality.MEDIUM: 1, Criticality.HIGH: 2}
    if crit_order.get(weak_crit, 0) > crit_order.get(criticality, 0):
        criticality = weak_crit
```

**Plain English.** A weak algorithm can only raise criticality, never lower
it. If a usage is already HIGH, finding MD5 there doesn't change anything; if
a usage is LOW and the algorithm is MD5, it becomes HIGH.

Matching is **exact, case-sensitive string equality** on `finding.algorithm`.
`"MD5"` matches; `"md5"` would not. This is consistent with every other
algorithm table in the platform.

### 26.8 The rationale builder

`_build_rationale(finding, goal, lifetime, is_trust_anchor) -> str` joins
parts with `" "`:

1. `f"{display} used for {usage_label}."` — `display` is
   `finding.display_name`; `usage_label` is `usage.value.replace("_", " ")`
2. `f"Primary security goal: {goal.value}."`
3. One goal-conditional sentence:

| Goal | Sentence |
|---|---|
| CONFIDENTIALITY | *"Data lifetime of {lifetime} years drives the Mosca X value, since harvest-now-decrypt-later applies to confidentiality."* |
| AUTHENTICITY + trust anchor | *"This is a long-lived trust anchor. The lifetime of the anchored trust ({lifetime} years) dominates, not the lifetime of any single signed message."* |
| AUTHENTICITY, not anchor | *"Short-lived signature ({lifetime} years). Harvest-now-decrypt-later does not apply to authenticity: a signature forged in the future is worthless against a token that has already expired."* |
| INTEGRITY | *"Integrity check with a {lifetime}-year relevance window."* |
| UNKNOWN | *(no third sentence at all)* |

4. Conditionally, when `parameter_status.value == "unresolved"`:
   `f"Parameter could not be resolved ({', '.join(unresolved_parameters)}). Confidence is reduced."`

**Important:** part 4 changes only the *text*. It does not alter criticality,
lifetime, or any numeric field — the confidence reduction happened earlier in
the extractor.

### 26.9 `lifetime_source` — documented vocabulary vs emitted value

```python
# Lifetime source — always policy_default for the demo.
lifetime_source = "policy_default"
```

Hardcoded and unconditional. The model field documents three legal values —
`policy_default | usage_inferred | declared` — but a repo-wide grep confirms
`"policy_default"` is the only value ever assigned anywhere in `app/`. The
other two are reserved vocabulary. See §63.

The docstring is explicit about why the demo repo's declared lifetimes are
not read: *"The metadata file's `declared` values are the TEST ORACLE, not a
runtime input — the classifier must work on any repo, not just the seed."*

### 26.10 What the classifier does *not* do

`artefact_type` is passed through **verbatim** from
`NormalizedFinding.artefact_type`:

```python
return Classification(
    artefact_type=finding.artefact_type,   # ← not derived here
    ...
)
```

The scanner (via `ALGORITHM_DEFAULTS`) owns that decision. The classifier
never overrides it.

---

## 27. Current-risk engine

**File.** `backend/app/risk/mosca.py::assess_current_risk`
**Signature.** `assess_current_risk(algorithm: str) -> CurrentRisk`

**Plain English.** Is this algorithm broken *right now*, ignoring quantum
computers entirely? Four algorithms are. Each answer cites the specific
attack and year.

**Working.** A single dict lookup. `_CURRENTLY_WEAK: dict[str, tuple[Severity, str]]`
— all four entries, with their verbatim reason strings:

| Algorithm | Severity | Reason (verbatim) |
|---|---|---|
| **MD5** | `HIGH` | "MD5 is collision-vulnerable (practical attacks since 2004) and unsuitable for any security purpose." |
| **SHA-1** | `HIGH` | "SHA-1 has practical collision attacks (SHAttered, 2017) and is unsuitable where collision resistance matters." |
| **DES** | `CRITICAL` | "Single DES has a 56-bit key exhaustively searchable in hours. Broken since the late 1990s." |
| **3DES** | `HIGH` | "Triple DES has a 64-bit block size vulnerable to Sweet32 birthday attacks. NIST SP 800-131A Rev.2 disallowed it after 2023." |

```python
if algorithm in _CURRENTLY_WEAK:
    severity, reason = _CURRENTLY_WEAK[algorithm]
    return CurrentRisk(is_currently_weak=True, severity=severity, reason=reason)
return CurrentRisk(
    is_currently_weak=False,
    severity=Severity.NONE,
    reason=f"{algorithm} remains classically sound today.",
)
```

**DES is the only `CRITICAL` in the codebase.** Note the deliberate
asymmetry with the classifier: `_WEAK_ALGORITHMS` marks all four as
`Criticality.HIGH`, so a DES finding carries `Severity.CRITICAL` on
current-risk but `Criticality.HIGH` on classification. Those are two
different scales measuring two different things — cryptographic brokenness
versus business impact.

**Negative case is still explanatory.** An unlisted algorithm gets a real
sentence, not an empty string. `CurrentRisk.references` exists on the model
but is never populated by this function (§63).

---

## 28. Quantum-risk engine

**File.** `backend/app/risk/mosca.py::assess_quantum_risk`
**Signature.** `assess_quantum_risk(algorithm: str) -> QuantumRisk`

**Plain English.** Does a quantum computer break this? For asymmetric crypto
the answer is yes, completely — Shor's algorithm solves the underlying maths.
For symmetric crypto and hashes, Grover's algorithm halves the effective
security but doesn't break them, so AES-256 stays safe. Blindspot records
these as genuinely different outcomes.

**Working.** Three branches, Shor checked first.

### 28.1 `_SHOR_BREAKS` — 11 members

```python
_SHOR_BREAKS: set[str] = {
    "RSA", "ECDH", "ECDSA", "ECC", "DSA", "DH", "ElGamal",
    "Ed25519", "Ed448", "X25519", "X448",
}
```

The source comment justifies the last four explicitly: *"Ed25519 / Ed448 /
X25519 / X448 are elliptic-curve based (Curve25519 / Curve448) and Shor
breaks the discrete-logarithm problem on which they depend, exactly as it
does for the NIST curves. Grouping them with the other Shor-breakable
primitives is the honest classification."*

Result:

```python
QuantumRisk(
    is_quantum_vulnerable=True,
    threat=QuantumThreat.SHOR_BREAKS,
    effective_security_loss="Fully broken by Shor's algorithm.",
    reason=f"{algorithm} is asymmetric cryptography that Shor's algorithm "
           "breaks outright. A cryptographically relevant quantum computer "
           "would defeat it completely.",
)
```

### 28.2 `_GROVER_WEAKENS` — 9 members

```python
_GROVER_WEAKENS: set[str] = {
    "AES", "3DES", "DES", "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512",
    "ChaCha20",
}
```

Result — **and note `is_quantum_vulnerable=False`**:

```python
QuantumRisk(
    is_quantum_vulnerable=False,          # ← deliberate
    threat=QuantumThreat.GROVER_WEAKENS,
    effective_security_loss=f"{algorithm} effective security reduced by half (Grover).",
    reason=f"{algorithm} is symmetric/hash cryptography. Grover's algorithm "
           "halves the effective security level but does not break it outright. "
           "AES-256 reduced to ~128-bit security remains adequate.",
)
```

**This single `False` drives three downstream behaviours:**

1. `mosca.assess(quantum_vulnerable=False)` → early return with
   `applicable=False` (§29.3)
2. `is_hndl_exposed` → `False` for every symmetric/hash finding (§30)
3. `is_quantum_sensitive` → `False`, so symmetric findings don't inflate the
   `quantum_sensitive` counter

The threat is still *recorded* (`GROVER_WEAKENS`) and the halving is still
*explained* — the platform distinguishes "weakened" from "broken" instead of
flattening both into one boolean.

### 28.3 Neither set

```python
QuantumRisk(
    is_quantum_vulnerable=False,
    threat=QuantumThreat.NONE_KNOWN,
    reason=f"No known practical quantum advantage against {algorithm}.",
)
```

`effective_security_loss` is left `None`. `QuantumThreat.UNKNOWN` exists in
the enum and is the model default, but this function never returns it (§63).

---

## 29. Mosca inequality engine

**File.** `backend/app/risk/mosca.py::assess`

```python
def assess(
    x: float,
    y: float,
    z: float,
    *,
    z_source: str | None = None,
    quantum_vulnerable: bool = True,
    settings: Settings | None = None,
) -> MoscaAssessment:
```

**Plain English.** The famous inequality. If your data must stay secret for
X more years, migration takes Y years, and a quantum computer arrives in Z
years, then when `X + Y > Z` you have already lost — you should have started
migrating before now.

### 29.1 The core arithmetic — four lines

```python
settings = settings or get_settings()
if z_source is None:
    z_source = settings.quantum_horizon_source

margin = (x + y) - z
result = margin > 0
equation = f"{x} + {y} > {z}"
```

**`equation` is an f-string of the raw floats — no rounding, no formatting.**
With pipeline defaults a certificate-signing finding renders
`"20.0 + 3.0 > 10.0"`; a session signature renders `"0.04 + 3.0 > 10.0"`.
The UI displays this string verbatim, so what a user reads is literally the
expression that was evaluated. The `MoscaAssessment` docstring states the
rule: *"The UI renders `equation` verbatim, so it is built from the same
numbers used in the comparison rather than being formatted separately."*

**`margin` and `result` are computed before the applicability check**, so
they are always numerically real even on the not-applicable path.

### 29.2 Tier thresholds

```python
if result:                  tier = RiskTier.OVERDUE        # X + Y > Z
elif (x + y) > (z / 2):     tier = RiskTier.TRANSITIONAL   # X + Y > Z/2
else:                       tier = RiskTier.LOW_RISK
```

Both comparisons are **strict** `>`. The transitional band is therefore
`z/2 < x + y <= z`. With default `Z = 10.0` the boundary is `5.0`.

An exact tie (`x + y == z`) yields `result=False` → falls to the
`elif`, and since `z > z/2` for any positive z, lands in `TRANSITIONAL`.

The threshold rationale, from the module docstring: *"The transitional band
uses Z/2 as the threshold: if the sum reaches half the horizon, the finding
is close enough to warrant planning even if not yet overdue."*

### 29.3 The not-applicable short-circuit

```python
if not quantum_vulnerable:
    return MoscaAssessment(
        x=x, y=y, z=z,
        equation=equation,
        result=result,                    # ← still the real computed value
        tier=RiskTier.LOW_RISK,
        margin_years=margin,              # ← still the real computed value
        z_source=z_source,
        applicable=False,
        notes="Mosca does not meaningfully apply: this algorithm is not "
              "vulnerable to Shor's algorithm. Grover at most halves the "
              "effective security level.",
    )
```

**Plain English.** Mosca's inequality is about Shor's algorithm. Applying it
to AES would produce a number that means nothing. So Blindspot computes it,
labels it not-applicable, and explains why — rather than either hiding the
finding or pretending the number is meaningful.

**A subtle and intentional consequence:** on this path `result` can be
`True` (the arithmetic genuinely holds) while `applicable=False` and
`tier=LOW_RISK`. Consumers must read `applicable` before interpreting
`result`. The recommender does exactly that (§32.5), and the frontend's
`MoscaVisualiser` takes `applicable` as a prop.

### 29.4 Notes strings per tier

| Tier | Notes |
|---|---|
| `OVERDUE` | *"Migration is overdue: the data must remain secure for {x} years and migration takes {y} years, but the quantum horizon is only {z} years away."* |
| `TRANSITIONAL` | *"Migration window is approaching: X + Y = {x + y} exceeds half the quantum horizon (Z/2 = {z / 2})."* |
| `LOW_RISK` (applicable) | `None` |
| any (not applicable) | the fixed string in §29.3 |

### 29.5 The model-level integrity invariant

**File.** `backend/app/models/risk.py`

```python
x: float = Field(ge=0)
y: float = Field(ge=0)
z: float = Field(gt=0)          # strictly positive

@model_validator(mode="after")
def _check_internal_consistency(self) -> MoscaAssessment:
    expected_margin = (self.x + self.y) - self.z
    if abs(self.margin_years - expected_margin) > 1e-6:
        raise ValueError(
            f"margin_years {self.margin_years} does not match (X + Y) - Z = {expected_margin}"
        )
    if self.result is not (expected_margin > 0):
        raise ValueError(
            f"result {self.result} contradicts X + Y > Z ({self.x} + {self.y} > {self.z})"
        )
    return self
```

**Plain English.** The object checks its own arithmetic. You cannot construct
a Mosca assessment whose stored margin or verdict disagrees with its own X,
Y, Z — not even by hand-editing a JSON file and loading it back.

**Working.** This is a hard invariant enforced at every construction *and
every deserialisation* (Pydantic runs `model_validator` on
`model_validate` too). Tolerance `1e-6` accommodates float representation.
`z` being `gt=0` means a zero horizon raises at construction rather than
producing a division-by-zero in the `z / 2` threshold.

The docstring names the threat it defends against: *"Guards against a
formatted string or cached tier drifting away from the numbers it claims to
represent."*

### 29.6 Where Y and Z come from

**File.** `backend/app/config.py`

```python
quantum_horizon_years: float = Field(default=10.0, gt=0,
    description="Mosca Z: years until a cryptographically relevant quantum computer.")
quantum_horizon_source: str = Field(
    default="Demo assumption (configurable via QUANTUM_HORIZON_YEARS)",
    description="Provenance string reported with every Mosca calculation.")
migration_time_years: float = Field(default=3.0, gt=0,
    description="Mosca Y: default organisational migration time in years.")
```

**The `quantum_horizon_source` default is itself an honesty guardrail.** Z is
an assumption about the future, and the default provenance string says so in
plain words. It is carried on every single `MoscaAssessment` and rendered in
the UI and the report. The module docstring makes it rule 1: *"Z is an
assumption. It comes from configuration and every result carries its
provenance. No unsupported claim about quantum timelines is hard-coded."*

---

## 30. The HNDL composite

**File.** `backend/app/models/finding.py` — **not** in `app/risk/`

**Plain English.** Harvest Now, Decrypt Later. An attacker records your
encrypted traffic today and stores it until a quantum computer can crack it.
This only matters if three things are all true: the crypto protects secrecy
(recording a signature is pointless), a quantum computer can break it, and
the data is still sensitive when that happens.

**Working.** A Pydantic `@computed_field` on `Finding`:

```python
@computed_field
@property
def is_hndl_exposed(self) -> bool:
    if not (
        self.classification
        and self.classification.security_goal == SecurityGoal.CONFIDENTIALITY
    ):
        return False
    if not (self.quantum_risk and self.quantum_risk.is_quantum_vulnerable):
        return False
    return self.risk_tier == RiskTier.OVERDUE
```

A three-way AND, each guard also null-safe so part-way-through pipeline
state yields `False` rather than raising.

| Guard | Excludes |
|---|---|
| `security_goal == CONFIDENTIALITY` | all `AUTHENTICITY`, `INTEGRITY`, `UNKNOWN` findings |
| `quantum_risk.is_quantum_vulnerable` | every `GROVER_WEAKENS` algorithm (AES, SHA-*, ChaCha20, DES, 3DES, MD5) |
| `risk_tier == OVERDUE` | `TRANSITIONAL` and `LOW_RISK` — exactly `OVERDUE`, nothing adjacent |

The docstring gives the reasoning per clause, including the memorable one for
clause 1: *"recording a signature or MAC to forge later gains nothing."*

**It asserts nothing new.** Every input is already computed. The docstring:
*"Derived purely from fields the pipeline already computes; it asserts
nothing new about the finding."*

**Its six consumers:**

| Consumer | Use |
|---|---|
| `pipeline._build_summary` | `hndl_exposed` counter |
| `report/executive.py` | `_urgent_key` sort position; "Migrate to PQC" target fallback |
| `cli/policy.py` | built-in `warn-new-hndl` rule matching `{"isHndlExposed": True}` |
| `agility/score.py` | the 15-point HNDL-immunity band |
| `FindingDetail.tsx` | the purple `HNDL` badge |
| CSV export | `Is HNDL Exposed` column |

**Sibling computed fields, same file:**

```python
is_quantum_sensitive = bool(self.quantum_risk and self.quantum_risk.is_quantum_vulnerable)
is_currently_weak    = bool(self.current_risk and self.current_risk.is_currently_weak)

needs_verification:
    if self.parameter_status == ParameterStatus.UNRESOLVED: return True
    return self.evidence.confidence_level == ConfidenceLevel.LOW
```

`needs_verification`'s docstring states its purpose as a trust signal: *"the
tool states what it is unsure about instead of presenting every finding with
equal, unearned certainty."*

---

## 31. Security-level derivation

**File.** `backend/app/recommend/security_level.py`
**Entry points.** `classify_security_level(...)`, `pqc_target_for_category(...)`

**Plain English.** RSA-2048 and RSA-4096 should not get the same
post-quantum replacement — one is roughly as strong as AES-128, the other
much stronger. This module works out how strong the *classical* algorithm
actually is, converts that into a NIST security category, and only then picks
a PQC target. The reasoning is recorded as a human-readable sentence that
ends up verbatim in the recommendation.

### 31.1 Signature

```python
def classify_security_level(
    algorithm: str,
    parameter: str | int | None = None,
    curve: str | None = None,
    *,
    high_assurance_mode: bool = False,
) -> SecurityLevel:
```

Returns a frozen dataclass:

```python
@dataclass(frozen=True)
class SecurityLevel:
    category: NistCategory
    classical_bits: int      # approximate; may be zero when unknown
    derivation: str          # one-line human-readable trace
```

`NistCategory` values are the **strings NIST uses**, so no translation is
needed on serialisation: `CAT_1 = "Category 1"`, `CAT_3 = "Category 3"`,
`CAT_5 = "Category 5"`.

### 31.2 Category boundaries

```python
def _bits_to_category(bits: int) -> NistCategory:
    if bits >= 256: return NistCategory.CAT_5
    if bits >= 192: return NistCategory.CAT_3
    return NistCategory.CAT_1
```

### 31.3 RSA / DSA / DH key size → classical bits

Branch guard: `algo_up in {"RSA", "DSA", "DH", "DIFFIE-HELLMAN"}`.

```python
def _rsa_bits(key_size: int) -> int:
    if key_size >= 15360: return 256
    if key_size >= 7680:  return 192
    if key_size > 3072:   return 192    # RSA-4096 lands here
    if key_size >= 3072:  return 128
    if key_size >= 2048:  return 112
    return 80                            # anything < 2048
```

Resulting mapping:

| Key size | Classical bits | Category | PQC target (KEM) |
|---|---|---|---|
| RSA-1024 | 80 | Category 1 | ML-KEM-512 |
| RSA-2048 | 112 | Category 1 | ML-KEM-512 |
| RSA-3072 | 128 | Category 1 | ML-KEM-512 |
| **RSA-4096** | **192** | **Category 3** | **ML-KEM-768** |
| RSA-7680 | 192 | Category 3 | ML-KEM-768 |
| RSA-15360 | 256 | Category 5 | ML-KEM-1024 |

**The RSA-4096 branch is a deliberate engineering choice, stated in the
source comment:**

> RSA-4096 lands here. Between Cat 1 and Cat 3 boundaries; we bump it to Cat 3
> as a defense-in-depth choice so a large-key finding gets a stronger PQC
> target than a small-key one — otherwise RSA-2048 and RSA-4096 collapse into
> the same target and the recommender looks lazy.

And for sub-2048 keys:

> Anything below 2048 is already unsafe today. Still map to Cat 1 PQC target
> — the `REMEDIATE_NOW` path handles the present-day weakness before quantum
> considerations enter.

### 31.4 ECC curve → classical bits

Branch guard: `algo_up in {"ECDSA", "ECDH", "ECC", "ECIES"}`.

```python
_ECC_CURVE_BITS: dict[str, int] = {
    # NIST prime curves
    "P-256": 128, "P-384": 192, "P-521": 256,
    "secp256r1": 128, "secp384r1": 192, "secp521r1": 256,
    # Koblitz / Bitcoin
    "secp256k1": 128,
    # Montgomery / Edwards
    "X25519": 128, "X448": 224,
    "Ed25519": 128, "Ed448": 224,
}
```

Values follow NIST SP 800-57 Part 1 Rev.5 Table 2.

| Curves | Bits | Category |
|---|---|---|
| P-256, secp256r1, secp256k1, X25519, Ed25519 | 128 | Category 1 |
| P-384, secp384r1 | 192 | Category 3 |
| X448, Ed448 | 224 | Category 3 |
| P-521, secp521r1 | 256 | Category 5 |

**`_ecc_bits(parameter, curve)` resolution order.** Tries `parameter` first,
then `curve` — because some scanners put the curve name in the parameter
field (which is exactly what the extractor's `curve_to_param` mapping does,
§23.5). Each candidate is tried exact-match, then case-insensitively:

```python
for name in candidates:
    bits = _ECC_CURVE_BITS.get(name)
    if bits is not None:
        return bits, name
    for known, bits_known in _ECC_CURVE_BITS.items():
        if known.lower() == name.lower():
            return bits_known, known
return None, None
```

So `"p-256"`, `"P-256"`, and `"secp256r1"` all resolve.

### 31.5 Bare-curve algorithms

After the ECC branch, a loop handles curves used *as* algorithm names
(`X25519`, `Ed25519`, `X448`, `Ed448`):

```python
for known_curve, known_bits in _ECC_CURVE_BITS.items():
    if known_curve.upper() == algo_up:
        ...
```

Case-insensitive, so `ed25519` / `ED25519` / `Ed25519` all resolve.

### 31.6 Symmetric

Branch guard: `algo_up in {"AES"}`.

```python
def _symmetric_bits(key_size: int) -> int:
    if key_size >= 256: return 256
    if key_size >= 192: return 192
    if key_size >= 128: return 128
    return 128      # sub-128 still reported as 128 → Cat 1
```

Input is `_parse_int(parameter) or 128`.

`_parse_int` only accepts pure-numeric strings:

```python
if isinstance(value, str):
    stripped = value.strip()
    if stripped.isdigit():
        return int(stripped)
return None
```

The comment explains: *"Some scanners emit '2048 bits' or 'P-256' — we handle
the curve case separately, so only pure numeric strings match here."*

### 31.7 The unknown-input policy — never silently Cat 1

Three paths default to `CAT_3` with `classical_bits=0`:

| Condition | Derivation string |
|---|---|
| RSA/DSA/DH, unparseable parameter | `f"{algo_up} with unresolved key size -> defaulted to NIST Category 3 pending manual review"` |
| ECC-family, unresolvable curve | `f"{algo_up} with unresolved curve -> defaulted to NIST Category 3 pending manual review"` |
| algorithm not in any table | `f"{algo_up or 'unknown algorithm'} not in the classifier table -> defaulted to NIST Category 3 pending manual review"` |

From the docstring: *"We never silently pick Cat 1 for something we could not
classify; that would understate the migration effort."* Choosing the middle
category and saying "pending manual review" is the honest failure mode.

### 31.8 The PQC target table

```python
_TARGETS: dict[tuple[NistCategory, bool], dict[str, object]] = {
    (CAT_1, False): {"target": "ML-KEM-512",  "parameter_set": "ML-KEM-512 (NIST FIPS 203, Category 1)", "references": ["NIST FIPS 203"]},
    (CAT_3, False): {"target": "ML-KEM-768",  "parameter_set": "ML-KEM-768 (NIST FIPS 203, Category 3)", "references": ["NIST FIPS 203"]},
    (CAT_5, False): {"target": "ML-KEM-1024", "parameter_set": "ML-KEM-1024 (NIST FIPS 203, Category 5)", "references": ["NIST FIPS 203"]},
    (CAT_1, True):  {"target": "ML-DSA-44",   "parameter_set": "ML-DSA-44 (NIST FIPS 204, Category 2)",  "references": ["NIST FIPS 204"]},
    (CAT_3, True):  {"target": "ML-DSA-65",   "parameter_set": "ML-DSA-65 (NIST FIPS 204, Category 3)",  "references": ["NIST FIPS 204"]},
    (CAT_5, True):  {"target": "ML-DSA-87",   "parameter_set": "ML-DSA-87 (NIST FIPS 204, Category 5)",  "references": ["NIST FIPS 204"]},
}
```

Keyed by `(category, is_signature)` so a caller who knows only the usage
resolves to one string with no conditional logic.

**The Cat-1 signature row says "Category 2" — and that is correct.** ML-DSA-44
is genuinely NIST Category 2; it is the parameter set every deployment guide
pairs with a Category-1 KEM. The source comment documents this:
*"ML-DSA-44 -> Cat 2 (paired with Cat 1 KEM in every deployment guide)."*

`pqc_target_for_category` does a bare subscript `_TARGETS[(category, is_signature)]`
— a `KeyError` if a category is ever added without a row, which is the right
failure (loud, at development time). It returns the **shared dict object**, so
both recommendation functions defensively copy: `refs = list(target["references"])`.

### 31.9 `HIGH_ASSURANCE_MODE` — the exact override path

**Plain English.** For national-security or very-long-life data, an operator
can force every recommendation to the strongest category. The reason is still
printed, so an auditor can see the operator opted in rather than the tool
deriving it.

**Working.** Every single return path in `classify_security_level` funnels
through one function:

```python
def _apply_override(category, bits, derivation, high_assurance_mode) -> SecurityLevel:
    if high_assurance_mode and category != NistCategory.CAT_5:
        derivation = (
            f"{derivation}; high_assurance_mode overrides to NIST "
            f"{NistCategory.CAT_5.value}"
        )
        category = NistCategory.CAT_5
    return SecurityLevel(category=category, classical_bits=bits, derivation=derivation)
```

Three properties worth noting:

1. **`classical_bits` is NOT rewritten.** The real derived strength is
   preserved; only the *target category* is upgraded. So a report can show
   "RSA-2048 ≈ 112-bit" alongside "target ML-KEM-1024" and the discrepancy is
   explained by the appended clause.
2. **The derivation is appended, not replaced** — the original reasoning
   survives.
3. **It reaches only two call sites.** `_classify` (the only caller of
   `classify_security_level` in the recommender) is invoked exclusively from
   `_recommend_pqc` and `_recommend_hybrid`. `REMEDIATE_NOW`, `INVESTIGATE`,
   and `DEFER` never call it, so the flag has **no effect** on those three
   strategies.

Config declaration:

```python
high_assurance_mode: bool = Field(default=False, description=(
    "Force every PQC recommendation to NIST Category 5. Use for "
    "long-life-secret data classes (national-security, "
    "HNDL-critical, root CAs). Off by default."))
```

### 31.10 Derivation string templates

| Case | Template |
|---|---|
| Symmetric | `f"{display_name} approx {bits}-bit symmetric strength -> NIST {category.value}"` |
| RSA/DSA/DH | `f"{algo_up}-{size} approx {bits}-bit classical strength -> NIST {category.value}"` |
| ECC | `f"{algo_up} on {curve_name} approx {curve_bits}-bit classical strength -> NIST {category.value}"` |
| Bare curve | `f"{known_curve} approx {known_bits}-bit classical strength -> NIST {category.value}"` |

A complete example from the module docstring:
`"RSA-2048 approx 128-bit -> NIST Category 1 -> ML-KEM-512"`.

---

## 32. The recommender

**File.** `backend/app/recommend/recommender.py`
**Entry point.** `recommend(finding: Finding, settings: Settings | None = None) -> Recommendation`

**Plain English.** Given everything we now know about a finding, say what to
do about it. Four possible verdicts, checked in a strict order so the most
urgent thing always wins.

### 32.1 The cascade — first match wins

```python
# ── Priority 1: Present-day weakness → REMEDIATE_NOW ──────────────
if current_risk and current_risk.is_currently_weak:
    ...return early

# ── Priority 2: Unresolved parameter → INVESTIGATE ────────────────
if finding.parameter_status.value == "unresolved":
    ...return early

# ── Priority 3: Tier-based recommendation ─────────────────────────
if risk_tier == RiskTier.OVERDUE:        return _recommend_pqc(finding, settings)
elif risk_tier == RiskTier.TRANSITIONAL: return _recommend_hybrid(finding, settings)
else:                                    return _recommend_defer(finding)
```

**Why this order.** An MD5 finding is broken today; telling the user to
"migrate to ML-DSA-65 by 2035" would be absurd — they need to replace it now.
And a finding whose key size is unknown cannot have a *sized* replacement
chosen, so it must be investigated first. Only once both of those are
excluded does the quantum timeline become the deciding factor.

The final `else` catches both `LOW_RISK` **and** `risk_tier is None`.

### 32.2 Branch 1 — `REMEDIATE_NOW`

```python
target = _REMEDIATION_TARGETS.get(algorithm, {})
replacement = target.get("replacement", "a modern alternative")
rationale = target.get("rationale",
    f"{algorithm} has known present-day weaknesses. "
    "Replace regardless of quantum migration timelines.")

return Recommendation(
    strategy=MigrationStrategy.REMEDIATE_NOW,
    algorithm=replacement,
    parameter_set=None,
    rationale=rationale,
    replaces=algorithm,
    priority=1,
    effort="low" if algorithm in ("MD5", "SHA-1") else "moderate",
    is_quantum_recommendation=False,          # ← key flag
    references=["NIST SP 800-131A Rev.2"],
)
```

`_REMEDIATION_TARGETS` — all four entries verbatim:

| Algorithm | Replacement | Rationale |
|---|---|---|
| MD5 | **SHA-256** | "MD5 is collision-broken. Replace with SHA-256 for integrity checks." |
| SHA-1 | **SHA-256** | "SHA-1 has practical collision attacks. Replace with SHA-256." |
| DES | **AES-256** | "Single DES has a 56-bit key exhaustively searchable in hours. Replace with AES-256." |
| 3DES | **AES-256** | "Triple DES has 64-bit blocks vulnerable to Sweet32. Replace with AES-256." |

Two details:

- **`is_quantum_recommendation=False`** — the only branch that sets this.
  It lets the UI and report distinguish "fix your broken crypto" from
  "prepare for quantum".
- **Effort is hash-aware.** Swapping `hashlib.md5` for `hashlib.sha256` is a
  one-line change (`"low"`); replacing DES with AES-256 means new key
  material and a data migration (`"moderate"`).

### 32.3 Branch 2 — `INVESTIGATE`

```python
return Recommendation(
    strategy=MigrationStrategy.INVESTIGATE,
    algorithm=f"Determine {algorithm} parameters first",
    parameter_set=None,
    rationale=(
        f"{algorithm} was detected but the key size could not be resolved "
        f"({', '.join(finding.unresolved_parameters)}). "
        "A migration target cannot be sized without knowing the current parameter. "
        "Investigate and resolve before selecting a PQC replacement."
    ),
    replaces=algorithm,
    priority=2,
    effort="investigation",
    is_quantum_recommendation=True,
    references=[],
)
```

The `algorithm` field carries an *instruction* rather than an algorithm name,
so the UI's "target" column reads `Determine RSA parameters first`. The
rationale names the exact unresolved parameters, which came all the way from
the AST module-boundary policy (§23.3).

### 32.4 Branch 3a — `PQC`

```python
usage  = finding.usage
is_sig = _is_signature_usage(usage)
level  = _classify(finding, settings)                              # → SecurityLevel
target = pqc_target_for_category(level.category, is_signature=is_sig)

pqc_algo = str(target["target"])
cost     = _build_cost_profile(pqc_algo, finding, is_signature=is_sig, hybrid=False)
latency  = get_latency_profile(pqc_algo)

rationale = (
    f"{finding.display_name} used for {usage_label} is overdue for "
    f"quantum migration (Mosca: {mosca_equation}). "
    f"{level.derivation} -> {pqc_algo}."
)
```

with `usage_label = usage.value.replace("_", " ")` and
`mosca_equation = finding.mosca.equation if finding.mosca else "N/A"`.

**The rationale stitches three provenanced strings together:** the finding's
display name, the *verbatim* Mosca equation, and the *verbatim* security-level
derivation. A complete real example:

> RSA-2048 used for key generation is overdue for quantum migration
> (Mosca: 10.0 + 3.0 > 10.0). RSA-2048 approx 112-bit classical strength ->
> NIST Category 1 -> ML-KEM-512.

Every clause traces to a computation the reader can verify.

`priority=1`, `effort="high"`. `migration_notes`:

```python
[
    f"Verify {pqc_algo} is supported by your deployment targets.",
    "Plan for larger key/ciphertext sizes in protocol buffers and storage.",
]
```

`_is_signature_usage`:

```python
return usage in {
    CryptoUsage.DIGITAL_SIGNATURE,
    CryptoUsage.SESSION_SIGNATURE,
    CryptoUsage.CERTIFICATE_SIGNING,
    CryptoUsage.CODE_SIGNING,
}
```

Everything else — key exchange, encryption, key generation — is treated as a
KEM.

### 32.5 Branch 3b — `HYBRID`

Same category-driven target selection, wrapped in a name that identifies both
shares:

```python
classical   = _classical_hybrid_label(finding)
hybrid_name = f"{classical} + {pqc_component}"
```

```python
def _classical_hybrid_label(finding: Finding) -> str:
    display = finding.display_name or finding.algorithm or "classical"
    if " (" in display:
        display = display.split(" (", 1)[0]     # "ECDSA (secp256r1)" → "ECDSA"
    return display
```

Producing, per the docstring's examples:

| Finding | Hybrid name |
|---|---|
| X25519 | `X25519 + ML-KEM-512` |
| RSA-2048 | `RSA-2048 + ML-KEM-512` |
| ECDSA (secp256r1) | `ECDSA + ML-DSA-44` |

`priority=2`, `effort="moderate"`, `hybrid=True` passed to the cost builder.
`migration_notes`:

```python
[
    "Hybrid mode increases handshake/signature size but provides defense in depth.",
    "Both components must be validated independently.",
]
```

### 32.6 Branch 3c — `DEFER`

Note the signature: `_recommend_defer(finding)` takes **no `settings`** —
it never consults `high_assurance_mode` because there is no PQC target to
upgrade.

```python
mosca_note = ""
if finding.mosca and finding.mosca.applicable:
    mosca_note = f" (Mosca: {finding.mosca.equation}, margin {finding.mosca.margin_years:.1f} years)."
elif finding.mosca and not finding.mosca.applicable:
    mosca_note = " Mosca does not apply to this algorithm."

return Recommendation(
    strategy=MigrationStrategy.DEFER,
    algorithm="No change required at this time",
    rationale=(
        f"{finding.display_name} does not require immediate migration.{mosca_note} "
        "Monitor quantum computing progress and re-evaluate periodically."
    ),
    replaces=None,
    priority=5,
    effort="none",
    is_quantum_recommendation=True,
    references=[],
)
```

**This is where the `applicable` flag earns its keep.** An AES-256 finding
gets *"Mosca does not apply to this algorithm."* rather than a margin figure
that would be arithmetically real but semantically meaningless. `replaces` is
`None` because nothing is being replaced.

### 32.7 Strategy field summary

| Strategy | `priority` | `effort` | `is_quantum_recommendation` | `references` |
|---|---|---|---|---|
| `REMEDIATE_NOW` | 1 | `low` (MD5/SHA-1) / `moderate` | **False** | `["NIST SP 800-131A Rev.2"]` |
| `INVESTIGATE` | 2 | `investigation` | True | `[]` |
| `PQC` | 1 | `high` | True | FIPS 203 or 204 |
| `HYBRID` | 2 | `moderate` | True | FIPS 203 or 204 |
| `DEFER` | 5 | `none` | True | `[]` |

`Recommendation.priority` is constrained `ge=1, le=5`.

---

## 33. Cost profiles

**File.** `backend/app/recommend/recommender.py::_build_cost_profile`

**Plain English.** Post-quantum keys and signatures are much bigger than what
they replace, and that size is the real cost of migrating — more bandwidth per
connection, more storage per record. Blindspot reports the actual published
byte sizes rather than inventing millisecond figures it cannot measure.

**Working.** From the `CostProfile` model docstring:

> We express cost as the concrete artefact sizes standardised in the FIPS
> specs — public key, ciphertext, and signature bytes — versus the classical
> algorithm being replaced. These are **published parameter sizes, not
> measured latency**.

### 33.1 The size tables

`_KEM_SIZES` (NIST FIPS 203):

| Target | public key | ciphertext | secret key |
|---|---|---|---|
| ML-KEM-512 | 800 | 768 | 1632 |
| ML-KEM-768 | 1184 | 1088 | 2400 |
| ML-KEM-1024 | 1568 | 1568 | 3168 |

`_SIG_SIZES` (NIST FIPS 204):

| Target | public key | signature | secret key |
|---|---|---|---|
| ML-DSA-44 | 1312 | 2420 | 2560 |
| ML-DSA-65 | 1952 | 3309 | 4032 |
| ML-DSA-87 | 2592 | 4627 | 4896 |

### 33.2 Classical baselines

```python
_CLASSICAL_KEY_BYTES = {
    "RSA": 256,      # RSA-2048 modulus; scaled below by key size when known
    "ECDH": 65,      # uncompressed P-256 point
    "ECC": 65, "ECDSA": 65,
    "DH": 256,
    "X25519": 32, "X448": 56,
    "Ed25519": 32, "Ed448": 57,
    "DSA": 128,      # DSA-1024 y-value, coarse
}
_CLASSICAL_SIG_BYTES = {
    "RSA": 256,
    "ECDSA": 72,     # DER-encoded P-256 signature (approx)
    "Ed25519": 64, "Ed448": 114,
    "DSA": 64,       # DSA-1024 signature, coarse
}
```

Every value is commented with its provenance, and the coarse ones are
labelled "coarse". RSA and DH scale with the resolved key size:

```python
if algo in ("RSA", "DH") and finding.parameter and finding.parameter.isdigit():
    return max(1, int(finding.parameter) // 8)
```

So RSA-2048 → 256 B, RSA-4096 → 512 B.

### 33.3 The cost band

```python
def _cost_band(largest_bytes: int) -> str:
    if largest_bytes >= 2400: return "high"
    if largest_bytes >= 1000: return "moderate"
    return "low"
```

Input is `max(pk, ct)` for KEMs and `max(sig, pk)` for signatures. Resulting
bands:

| Target | Largest artefact | Band |
|---|---|---|
| ML-KEM-512 | 800 | **low** |
| ML-KEM-768 | 1184 | **moderate** |
| ML-KEM-1024 | 1568 | **moderate** |
| ML-DSA-44 | 2420 | **high** |
| ML-DSA-65 | 3309 | **high** |
| ML-DSA-87 | 4627 | **high** |

Every ML-DSA parameter set is `high` — which is the honest signal:
post-quantum signatures are the expensive part of PQC migration, not the KEMs.

### 33.4 Summary strings

Signature branch:

```python
ratio = f"~{pqc_main / classical_sig:.0f}x" if classical_sig else "substantially larger"
summary = (
    f"{pqc_component} signature is {pqc_main} B"
    + (f" vs ~{classical_sig} B for {finding.display_name}" if classical_sig else "")
    + f" ({ratio}); public key {sizes['pk']} B. "
    + ("Hybrid carries both a classical and a PQC signature. " if hybrid else "")
    + "Size drives bandwidth/storage cost."
)
```

KEM branch uses `~{pk / classical_key:.1f}x` (one decimal, since KEM ratios
are smaller) and closes with *"Larger handshakes mean more bandwidth per
connection."*

Returns `None` when the target isn't in the relevant table — so an unknown
target yields no cost profile rather than a fabricated one.

`CostProfile.basis` default: *"Published FIPS parameter sizes in bytes — not
measured runtime latency."*

---

## 34. Latency profiles

**File.** `backend/app/recommend/latency.py`
**Entry point.** `get_latency_profile(target: str) -> LatencyProfile | None`

**Plain English.** How slow is post-quantum crypto? Blindspot reports
published benchmark numbers from the algorithm authors' own papers, always
labelled with the exact hardware they were measured on, and never presented as
something measured on your system.

### 34.1 The four honesty rules, from the model docstring

1. *"Never presented as this system's measured latency."* The UI renders it as
   "reference latency (source: …)".
2. *"Cycle counts are the primary unit."* Cycles are portable across clock
   rates.
3. *"Relative bands trump precise numbers."* A coarse `low/moderate/high`
   communicates the operational picture without over-promising.
4. *"Signatures split sign vs. verify."* Verification is often 3-5× faster
   than signing; collapsing them loses the most important operational signal.

### 34.2 All six profiles, complete

| Target | keygen | encaps | decaps | sign | verify | classical baseline | handshake extra | band |
|---|---|---|---|---|---|---|---|---|
| ML-KEM-512 | 33 000 | 45 000 | 34 000 | — | — | 112 000 / 112 000 (ECDH P-256) | — | **low** |
| ML-KEM-768 | 52 000 | 68 000 | 54 000 | — | — | 112 000 / 112 000 | 1 100 B | **low** |
| ML-KEM-1024 | 74 000 | 96 000 | 79 000 | — | — | 112 000 / 112 000 | 1 600 B | **moderate** |
| ML-DSA-44 | 130 000 | — | — | 333 000 | 118 000 | sign 100 000 / verify 350 000 (ECDSA P-256) | — | **moderate** |
| ML-DSA-65 | 210 000 | — | — | 530 000 | 179 000 | 100 000 / 350 000 | 3 500 B | **moderate** |
| ML-DSA-87 | 300 000 | — | — | 642 000 | 279 000 | 100 000 / 350 000 | 5 000 B | **high** |

All figures in CPU cycles.

### 34.3 Citation discipline

Four shared constants, so an audit of "did we invent this?" is one string
lookup:

```python
_SKYLAKE_PLATFORM_NOTE = (
    "Intel Skylake i7-6600U @ 2.6 GHz (AVX2 optimised reference implementation "
    "from the algorithm authors) - not measured on the scanned system."
)
_KYBER_R3_SOURCE = (
    "CRYSTALS-Kyber, Round 3 submission to NIST PQC (2020), performance "
    "appendix, AVX2 optimised, Skylake i7-6600U. ML-KEM (FIPS 203) is the "
    "final standardisation of this design."
)
_DILITHIUM_R3_SOURCE = (... Dilithium equivalent ...)
_CLOUDFLARE_HANDSHAKE_SOURCE = (
    "Cloudflare, 'Sizing Up Post-Quantum Signatures' (Oct 2021), TLS 1.3 "
    "ClientHello / ServerHello overhead measurements."
)
```

`_SKYLAKE_PLATFORM_NOTE` is set as `platform_note` on all six profiles and
ends with the explicit disclaimer. The handshake byte figures cite Cloudflare
separately from the cycle counts, because they come from a different
measurement.

Interesting per-profile summaries worth quoting:

- ML-DSA-44: *"verify is comparable to ECDSA P-256 verify; sign is roughly 3x
  slower."*
- ML-DSA-65: *"Signatures are much larger (~3.3 KB) so the dominant TLS cost
  is bandwidth, not CPU."*
- ML-DSA-87: *"Signature size (~4.6 KB) dominates the TLS handshake cost."*

### 34.4 Hybrid-name normalisation

```python
def _normalise_target(target: str) -> str:
    for token in target.replace(",", " ").split():
        upper = token.strip().upper()
        for prefix in ("ML-KEM-", "ML-DSA-"):
            if upper.startswith(prefix):
                return upper.rstrip(")].,;:")
    return target.strip()
```

So `"X25519 + ML-KEM-768"` resolves to `ML-KEM-768`, and `"ML-DSA-65)"`
(trailing punctuation from a parameter-set string) resolves cleanly. The
docstring explains the choice: *"We latency-profile the PQC component because
that is what the reference cycle counts describe. The classical share adds its
own cost, which is already captured in the `classical_*` fields."*

`available_targets()` returns `sorted(_PROFILES.keys())` — exposed for tests
and frontend schema-completeness checks.

**Implementation caveat.** `_PROFILES` returns **shared singleton**
`LatencyProfile` instances — the same object is attached to every
recommendation with that target. Safe today because nothing mutates them, but
worth knowing before adding per-finding latency adjustment.

---

## 35. Roadmap planner

**File.** `backend/app/roadmap/planner.py`
**Entry point.** `build_roadmap(findings: list[Finding], scan_id: str | None = None) -> MigrationRoadmap`

**Plain English.** Turn a flat list of findings into an ordered plan: fix the
broken things first, then the urgent quantum migrations, then the hybrid
transitions, then monitoring — with the highest-impact item at the top of each
wave.

**Working.** *"Deterministic: the same input always yields the same waves and
ordering."* Everything except `generated_at` is a pure function of the input
list.

### 35.1 The five waves, in fixed display order

`_WAVE_DEFS: list[tuple[str, MigrationStrategy, str, str]]`:

| Order | Key | Strategy | Title | Description |
|---|---|---|---|---|
| 1 | `remediate_now` | `REMEDIATE_NOW` | **Immediate Remediation** | "Cryptography that is already broken today. Fix now, independent of the quantum timeline." |
| 2 | `wave_1` | `PQC` | **Wave 1 — Urgent PQC Migration** | "Overdue under Mosca's inequality. Migrate to post-quantum algorithms first." |
| 3 | `wave_2` | `HYBRID` | **Wave 2 — Hybrid Transition** | "Approaching the migration window. Deploy hybrid classical + PQC." |
| 4 | `wave_3` | `DEFER` | **Wave 3 — Monitor & Defer** | "No immediate quantum urgency. Monitor and re-evaluate on schedule." |
| 5 | `investigate` | `INVESTIGATE` | **Needs Investigation** | "Parameters could not be resolved. Manual review is required before planning." |

Titles use an em dash (`—`), not a hyphen — which is why the report needs a
prefix-stripping regex (§39.6).

**Empty waves are still emitted.** The loop iterates `_WAVE_DEFS`, not the
buckets, so a scan with no weak crypto still produces an "Immediate
Remediation" wave with `items=[]` and `item_count=0`. The UI and report render
"No items in this wave." — the absence is shown rather than hidden.

### 35.2 Priority score

```python
_TIER_WEIGHT = {OVERDUE: 3, TRANSITIONAL: 2, LOW_RISK: 1}
_CRIT_WEIGHT = {HIGH: 3,    MEDIUM: 2,      LOW: 1}

def _priority_score(finding, blast_radius) -> int:
    tier_weight = _TIER_WEIGHT.get(finding.risk_tier, 1) if finding.risk_tier else 1
    criticality = finding.classification.criticality if finding.classification else None
    crit_weight = _CRIT_WEIGHT.get(criticality, 2) if criticality else 2
    return tier_weight * 100 + crit_weight * 10 + blast_radius
```

**The ×100 / ×10 / ×1 scaling is a lexicographic sort encoded as one integer.**
Tier always dominates; criticality breaks ties within a tier; blast radius
breaks ties within that. Ranges from 111 (low-risk, low-criticality, one
finding in its file) to 331+ (overdue, high-criticality, many findings in the
file).

Defaults: missing tier → weight 1; missing criticality → weight 2 (medium).

### 35.3 Blast radius

```python
def _blast_radius_by_file(findings) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for finding in findings:
        counts[finding.file_path] += 1
    return counts
```

A plain per-file count — *"change-impact proxy"*. A finding alone in its file
has blast radius 1 (it counts itself). Read at the call site as
`blast.get(finding.file_path, 1)`.

**Note:** this is a *different* metric from the blast-radius graph's
(§46), which counts **distinct algorithm identities** per file. Both are
named "blast radius" and both are legitimate; the roadmap one is a
co-location count, the graph one is a crypto-surface count.

### 35.4 Wave assignment with a recommender-mirroring fallback

```python
def _strategy_of(finding) -> MigrationStrategy:
    if finding.recommendation is not None:
        return finding.recommendation.strategy
    # Fallback when a finding has not been through the recommender.
    if finding.is_currently_weak:                      return REMEDIATE_NOW
    if finding.parameter_status.value == "unresolved":  return INVESTIGATE
    if finding.risk_tier == RiskTier.OVERDUE:           return PQC
    if finding.risk_tier == RiskTier.TRANSITIONAL:      return HYBRID
    return DEFER
```

The fallback mirrors `recommend()`'s precedence exactly, so a roadmap built
from un-enriched findings lands items in the same waves.

### 35.5 Effort and cost band

```python
_COST_BAND = {PQC: "high", HYBRID: "medium", DEFER: "low",
              REMEDIATE_NOW: "low", INVESTIGATE: "unknown"}

_DEFAULT_EFFORT = {PQC: "high", HYBRID: "moderate", DEFER: "none",
                   REMEDIATE_NOW: "low", INVESTIGATE: "investigation"}
```

In `_to_item`:

```python
effort    = rec.effort if rec and rec.effort else _DEFAULT_EFFORT[strategy]
cost_band = _COST_BAND[strategy]      # ← ALWAYS table-driven
```

**Asymmetry worth knowing:** `effort` prefers the recommendation's own value
(so an MD5 finding keeps its `"low"`), but `cost_band` is *always* read from
the table and never from the recommendation. `HYBRID` cost band is
`"medium"` here, whereas `CostProfile.relative_cost` uses
`low | moderate | high` — two different vocabularies on two different
objects. Do not conflate them.

### 35.6 Sorting and assembly

```python
for order, (key, strategy, title, description) in enumerate(_WAVE_DEFS, start=1):
    items = buckets.get(strategy, [])
    items.sort(key=lambda it: (-it.priority_score, it.finding_id))
    waves.append(MigrationWave(key=key, order=order, title=title,
                               description=description, strategy=strategy, items=items))
    summary[key] = len(items)
    total += len(items)
```

`-priority_score` descending, `finding_id` ascending as the deterministic
tiebreak — so two findings with identical scores always appear in the same
order across runs.

---

## 36. Compliance sensitivity engine

**File.** `backend/app/compliance/evaluator.py`
**Entry point.** `evaluate_compliance(findings, scan_id=None, settings=None) -> ComplianceEvaluation`

**Plain English.** The quantum horizon Z is an assumption, and different
regulators assume different dates. This engine re-runs the same Mosca
calculation against every configured deadline and shows which findings change
tier. A finding that's "low-risk" under a 15-year estimate can be "overdue"
under India's 2027 deadline — and that shift is the most persuasive thing in
the product.

**Working.** *"It does not re-scan, re-classify, or invent new inputs"* — it
re-runs `mosca.assess` with a different Z, reusing each finding's stored
`m.x` and `m.y`.

### 36.1 Preset loading

```python
def _load_presets(settings) -> list[CompliancePreset]:
    presets = []
    for raw in settings.z_presets:
        presets.append(CompliancePreset(
            name=str(raw["name"]),
            z=float(raw["z"]),
            ...
        ))
    return presets
```

### 36.2 The seven shipped presets

From `Settings.z_presets`, a `@computed_field` with `current_year = 2026`
hardcoded:

| Name | Z | Target year | Source |
|---|---|---|---|
| Demo default | `quantum_horizon_years` (10.0) | 2036 | the active `quantum_horizon_source` |
| India CII — Category A (sensitive infra) | `max(1, 2027-2026)` = 1 | 2027 | "India MeitY/CII PQC advisory 2027 deadline for Category A systems" |
| India CII — Category B | `max(2, 2028-2026)` = 2 | 2028 | India MeitY/CII 2028 |
| India CII — Category C | `max(3, 2029-2026)` = 3 | 2029 | India MeitY/CII 2029 |
| NIST IR 8547 — 2030 deprecation | `max(4, 2030-2026)` = 4 | 2030 | "NIST IR 8547 recommendation to deprecate classical asymmetric by 2030" |
| NIST IR 8547 — 2035 disallow | `max(9, 2035-2026)` = 9 | 2035 | "NIST IR 8547 recommendation to disallow classical asymmetric by 2035" |
| CRQC mid-range estimate | 15.0 | 2041 | "Mid-range expert survey estimate for fault-tolerant quantum computer" |

The `max(floor, delta)` pattern keeps Z strictly positive even if the
hardcoded `current_year` drifts past a deadline — which matters because
`MoscaAssessment.z` is `Field(gt=0)` and would otherwise raise.

**Preset index 0 is always the baseline.** `baseline_name = presets[0].name if presets else "Demo default"`
— guarded rather than blind-indexed.

### 36.3 Per-finding re-evaluation

```python
def _tier_under(finding, preset, settings) -> ComplianceTier:
    m = finding.mosca
    if <mosca missing / not applicable>:
        return ComplianceTier(x=0.0, y=0.0, z=preset.z, equation="n/a",
                              margin_years=0.0, ...)
    return <mosca.assess(m.x, m.y, preset.z, z_source=preset.source,
                         quantum_vulnerable=quantum_vulnerable, settings=settings)
             mapped into ComplianceTier>
```

It calls the **same** `mosca.assess` function the pipeline used. The preset
tiers are therefore consistent with the baseline tier by construction — there
is no second implementation of the inequality anywhere in the codebase.

Not-applicable findings get an explicit `equation="n/a"` row rather than being
omitted, so the matrix stays rectangular.

### 36.4 Summary and delta

```python
baseline_overdue = sum(
    1 for f in compliance_findings
    if f.tiers_by_preset[baseline_name].tier == RiskTier.OVERDUE.value
) if compliance_findings else 0

summary_by_preset = {p.name: _summarise(compliance_findings, p.name, baseline_overdue) for p in presets}
```

`_summarise` counts `overdue`, `transitional`, `low_risk`, `not_applicable`,
`total`, and `overdue_delta` — *"Change in overdue count versus the baseline
preset."*

The delta is what the frontend renders as the escalation signal: switching
from the CRQC estimate to India CII 2027 shows a positive `overdue_delta`,
meaning more findings become urgent under the stricter deadline.

### 36.5 Output shape

`ComplianceEvaluation` carries `scan_id`, `generated_at`,
`baseline_preset_name`, `total_findings`, `presets`, `findings`
(each a `ComplianceFinding` with `tiers_by_preset: dict[str, ComplianceTier]`),
and `summary_by_preset`. The whole matrix ships in one payload *"so the GUI
can switch presets instantly without another round-trip"* — which is exactly
what the Tier-A2 preset-sensitivity strip relies on (§47).

---

# Part VI — Output layer working

## 37. CBOM builder

**File.** `backend/app/cbom/builder.py`

```python
def _finding_to_component(finding: NormalizedFinding) -> Component
def build_cbom(findings, *, project_name="Blindspot ECDAT Scan") -> dict[str, Any]
def build_cbom_json(findings, *, project_name="Blindspot ECDAT Scan") -> str
```

**Plain English.** Converts findings into CycloneDX 1.6 — the industry
standard inventory format — so other tools can read Blindspot's output and
Blindspot can read theirs.

### 37.1 Component field mapping

Five kwargs, exactly:

| Component field | Source |
|---|---|
| `name` | `finding.display_name` |
| `type` | `ComponentType.CRYPTOGRAPHIC_ASSET` (hardcoded) |
| `bom_ref` | `finding.id` — **verbatim** |
| `description` | `f"{algorithm} detected in {file_path} at line {line_number} (confidence: {confidence:.0%})"` |
| `crypto_properties` | `CryptoProperties(asset_type=ALGORITHM, algorithm_properties=algo_props)` |
| `evidence` | `ComponentEvidence(occurrences=[occurrence])` |

### 37.2 bom-ref determinism

`bom_ref = finding.id` with no hashing or prefixing — because `finding.id` is
*already* a deterministic SHA-256-derived value from
`_make_finding_id` (§22.1). So a `bom-ref` like `CRYPTO-a3f21c08` is stable
across runs and machines, which is what makes CBOM-to-CBOM comparison
meaningful.

### 37.3 The two-stage crypto-function derivation

**Plain English.** CycloneDX wants to know whether this crypto is used for
key generation, encryption, signing, etc. Blindspot works it out from the
semgrep rule name, and falls back to the usage classification.

**Stage A — substring match on the rule id:**

```python
crypto_functions: list[CDXFunction] = []
rule_id = finding.evidence.rule_id or ""
for keyword, cdx_fn in _FUNCTION_MAP.items():
    if keyword in rule_id.lower():
        crypto_functions.append(cdx_fn)
        break
```

`_FUNCTION_MAP` keys **in insertion order** (order matters because of the
`break`): `keygen`, `encrypt`, `decrypt`, `sign`, `verify`, `digest`,
`keyderive`, `generate`, `encapsulate`, `decapsulate`, `tag`, `other`,
`unknown`.

This is why the rule-id naming convention (§11.7) is functionally
significant: `blindspot-rsa-keygen-cryptography` matches `keygen` and yields
`KEYGEN`.

**Known limitation of substring matching:** at most one function is ever
derived, and `sign` precedes `verify` in the dict, so a rule id like
`blindspot-ecdsa-sign-verify` would match `sign` first. In practice the rule
pack names sign and verify as separate rules, so this does not bite — but it
is a real property of the implementation.

**Stage B — infer from usage** (only when stage A produced nothing):

| `finding.usage.value` | CycloneDX function |
|---|---|
| `key_generation` | `KEYGEN` |
| `key_establishment` | `KEYDERIVE` |
| `key_transport` | `ENCRYPT` |
| `data_encryption` | `ENCRYPT` |
| `data_at_rest_encryption` | `ENCRYPT` |
| `transport_encryption` | `ENCRYPT` |
| `digital_signature` | `SIGN` |
| `session_signature` | `SIGN` |
| `certificate_signing` | `SIGN` |
| `code_signing` | `SIGN` |
| `integrity_hash` | `DIGEST` |
| `password_hashing` | `DIGEST` |
| `message_authentication` | `TAG` |
| `key_derivation` | `KEYDERIVE` |

Final fallback: `crypto_functions or [CDXFunction.UNKNOWN]` — the field is
never empty.

### 37.4 Enum translation tables

`_PRIMITIVE_MAP` — 15 entries, 1:1 by name, because the domain enum's string
values *are* the CycloneDX wire strings:

`pke`, `key-agree`, `signature`, `hash`, `block-cipher`, `stream-cipher`,
`ae`, `mac`, `kdf`, `kem`, `drbg`, `xof`, `combiner`, `other`, `unknown`.

Lookup: `_PRIMITIVE_MAP.get(finding.primitive, CDXPrimitive.UNKNOWN)`.

`_MODE_MAP` — 9 entries: `cbc`, `ecb`, `gcm`, `ctr`, `cfb`, `ofb`, `ccm`,
`other`, `unknown`.

```python
cdx_mode = _MODE_MAP.get(finding.mode, CDXMode.UNKNOWN) if finding.mode else None
```

**`None` when the finding has no mode** — so the field is omitted from the
JSON entirely, rather than being emitted as `"unknown"`. `unknown` appears
only when a finding explicitly carries an unmapped mode. That distinction
matters for interop: an absent field and an explicitly-unknown field are
different claims.

### 37.5 Parameter-set fallback

```python
param_set = finding.parameter
if not param_set and finding.curve:
    param_set = finding.curve
```

For an EC finding where the extractor resolved both, the curve therefore
appears **twice** — once as `parameterSetIdentifier` and once as `curve`. Not
a bug; `parameterSetIdentifier` is the generic slot consumers read, `curve`
is the EC-specific one.

### 37.6 Evidence occurrence

```python
occurrence = Occurrence(
    location=finding.evidence.file_path,
    line=finding.evidence.line_number,
    additional_context=finding.evidence.code_snippet[:200] if finding.evidence.code_snippet else None,
)
```

Exactly one occurrence per component; snippet truncated to 200 characters;
`None` rather than `""` when absent. Because `file_path` always carries
something addressable (§21.2), a TLS finding's occurrence location reads
`example.com:443` and an AWS KMS finding's reads the ARN.

### 37.7 Deduplication and error isolation

```python
seen_refs: set[str] = set()
for finding in findings:
    if finding.id in seen_refs:
        continue
    try:
        component = _finding_to_component(finding)
        bom.components.add(component)
        seen_refs.add(finding.id)          # ← added AFTER success
    except Exception as exc:
        logger.warning("Failed to convert finding %s to CBOM component: %s", finding.id, exc)
```

Dedup is by `finding.id` only — two findings with different ids at the same
file and line both become components. `seen_refs.add()` runs *after* a
successful add, so a finding whose conversion raised is not recorded and a
later duplicate id gets retried.

`bom.components` is set-like, so the library also collapses structurally
identical components.

### 37.8 Post-serialisation injection

```python
outputter = JsonV1Dot6(bom)
document = json.loads(outputter.output_as_string())
document.setdefault("metadata", {})
document["metadata"]["timestamp"] = datetime.now(timezone.utc).isoformat()
```

**Only `metadata.timestamp` is injected.** No `properties` array, no tool
metadata, no `metadata.component`. Consequences documented in §63:

- The executive report's CBOM appendix "Tools" table renders "Not declared."
- Blindspot's own CBOM carries **no** `blindspot:riskTier` property, which is
  the annotation the interop diff (§50) looks for.

`build_cbom_json` returns `json.dumps(document, indent=2, ensure_ascii=False)`.

Empty input logs `"No findings to include in the CBOM."` and still returns a
structurally valid component-less document — which the validator then
correctly rejects.

---

## 38. CBOM validator

**File.** `backend/app/cbom/validator.py`
**Entry point.** `validate_cbom(document: dict) -> tuple[bool, list[str]]`

**Plain English.** Checks the CBOM actually conforms to CycloneDX 1.6, using
the official schema. Because *"a CBOM that only 'looks right' is not
interoperable."*

### 38.1 Schema resolution — no repo file, no network

`_get_bundled_schema() -> dict | None`:

1. `importlib.resources.files("cyclonedx.schema._res").joinpath("bom-1.6.schema.json")`
2. same package, `"bom-1.6.SNAPSHOT.schema.json"`
3. Fallback: walk `cyclonedx.schema.__path__` and return the first
   `rglob("*1.6*schema*.json")` hit

Each candidate wrapped in `except (ModuleNotFoundError, FileNotFoundError, TypeError): continue`.
Any other exception → `logger.debug(...)` → `None`.

The schema comes from the **installed `cyclonedx-python-lib`**. No schema file
lives in the repo and nothing is fetched over the network — which is what makes
validation work in air-gap mode.

`CDX_1_6_SCHEMA_URL = "http://cyclonedx.org/schema/bom-1.6.schema.json"` is
declared as a `$schema` reference constant but is **never used** in validation
(§63).

### 38.2 Three tiers, one error channel

**There is no warning channel in the return value.** Every finding is appended
to `errors`, and `is_valid = len(errors) == 0`. "Warnings" exist only as log
lines.

**Tier 1 — structural, always runs:**

| Check | Error message |
|---|---|
| not a dict | early `return False, ["Document is not a JSON object."]` |
| `bomFormat != "CycloneDX"` | `f"bomFormat must be 'CycloneDX', got {bom_format!r}."` |
| `specVersion not in ("1.6","1.5","1.4")` | `f"specVersion {spec_version!r} is not a supported CycloneDX version."` |
| `components` not a list | `"'components' must be an array."` (and `components` reset to `[]`) |
| `components` empty | `"CBOM contains no components."` |

**Tier 2 — JSON Schema:**

```python
schema = _get_bundled_schema()
if schema:
    try:
        jsonschema.validate(instance=document, schema=schema)
        logger.info("CBOM passed JSON Schema validation (CycloneDX 1.6).")
    except jsonschema.ValidationError as exc:
        path = " -> ".join(str(p) for p in exc.absolute_path) if exc.absolute_path else "root"
        errors.append(f"Schema validation error at {path}: {exc.message}")
    except jsonschema.SchemaError as exc:
        errors.append(f"Schema itself is invalid: {exc.message}")
else:
    logger.info("Bundled CycloneDX schema not found; running structural checks only.")
```

Two design decisions: a **missing schema is a soft skip** (INFO log, not an
error) so the tool still works if the library layout changes; and it uses
`validate` not `iter_errors`, so only the **first** schema violation is
reported.

**Tier 3 — crypto-specific, per component,** prefix `f"components[{i}]"`:

| Check | Message |
|---|---|
| `type != "cryptographic-asset"` | `f"{prefix}: type must be 'cryptographic-asset', got {...!r}."` |
| missing `bom-ref` | `f"{prefix}: missing bom-ref."` |
| missing `name` | `f"{prefix}: missing name."` |
| missing `cryptoProperties` | `f"{prefix} ({name}): missing cryptoProperties."` then **`continue`** |
| missing `assetType` | `f"{prefix} ({name}): missing assetType."` |
| `assetType == "algorithm"` without `algorithmProperties` | `f"{prefix} ({name}): algorithm asset has no algorithmProperties."` |
| `assetType == "algorithm"` without `primitive` | `f"{prefix} ({name}): missing primitive in algorithmProperties."` |

Accepts both spellings: `comp.get("cryptoProperties") or comp.get("crypto-properties", {})`.

Final log: `"CBOM validation passed: %d components, 0 errors."` or
`"CBOM validation found %d errors."`

---

## 39. Executive report generator

**File.** `backend/app/report/executive.py` (~1 770 lines)

```python
def build_executive_html(*, scan, findings, roadmap=None, compliance=None,
                         cbom=None, app_version="0.1.0", now=None) -> str
def build_executive_pdf(*, html, timeout_seconds=60) -> bytes
def build_asset_csv(*, scan, findings) -> str
def cbom_from_json_string(cbom_json: str | None) -> dict | None
class ReportGenerationError(RuntimeError)
```

**Plain English.** Produces a branded, self-contained document a non-engineer
can read — cover page, one-page executive summary, then the full detail. Works
as HTML in a browser or PDF for archiving.

### 39.1 The prime directive

From the module docstring:

> **Nothing is computed here.** Every number, every rationale, every risk tier
> is read verbatim from `Scan` / `Finding` / `MigrationRoadmap` /
> `ComplianceEvaluation` produced by the rest of the pipeline. The report is a
> *presentation* layer, not a second opinion.

Enforced in practice: the only arithmetic in the entire 1 770-line module is
`_pct` (§39.5) and two bar-width calculations.

Two supporting rules: *"Pure Python string templating"* — no template engine,
and every value passed through `html.escape` so a pathological file path
cannot inject markup. And *"PDF rendering is optional... We never invent a
PDF."*

### 39.2 Section order and identity

`build_executive_html` joins eight renderers:

| # | Renderer | `id` | Heading | Classes |
|---|---|---|---|---|
| — | `_render_header` | — | `<h1>Post-Quantum Cryptographic Posture</h1>` | `header.cover` |
| 1 | `_render_executive_summary` | `summary` | `1. Executive Summary` | `section` |
| 2 | `_render_posture_summary` | `posture` | `2. Detailed Posture Breakdown` | `section pagebreak` |
| 3 | `_render_asset_inventory` | `inventory` | `3. Cryptographic Asset Inventory` | `section pagebreak` |
| 4 | `_render_roadmap` | `roadmap` | `4. Wave-by-Wave Migration Plan` | `section pagebreak` |
| 5 | `_render_compliance` | `compliance` | `5. Compliance Sensitivity` | `section pagebreak` |
| A | `_render_cbom_appendix` | `cbom` | `A. Appendix — CycloneDX CBOM` | `section pagebreak` |
| — | `_render_footer` | — | — | `footer` (in-flow) |

**Graceful degradation.** Each renderer has a missing-data branch that emits
an unnumbered heading and drops the `pagebreak` class — e.g. `_render_roadmap`
with no roadmap emits `<h2>Wave-by-wave migration plan</h2>` plus a note
pointing at `GET /api/roadmap`. A scan without a roadmap still produces a
valid report. (The `posture` degraded branch also loses its `id` anchor —
§63.)

Everything is wrapped in `<div class="container">` with `<style>{_CSS}</style>`
inline. Self-contained: no external CSS, JS, or images — *"suitable for
archiving, emailing, or printing to PDF outside the demo environment."*

### 39.3 Cover header

`dl.cover-meta`, a four-column grid with eight pairs: Project, Scan
Identifier, Scan Started, Scan Completed, Report Generated, Tool Version,
Total Findings, Scan Mode.

`Scan Mode` renders `scan.mode.value.upper()` behind a `hasattr` guard — this
is where a cached scan visibly declares itself `CACHED` (§10).

`_iso(value)` formats dates: `"-"` for `None`; strings get `T`→space and the
`.`-suffix stripped; datetimes → `%Y-%m-%d %H:%M UTC` after
`astimezone(timezone.utc)`.

### 39.4 The verdict banner

Strict priority, first match wins:

```python
if overdue > 0 or weak > 0:   # class "overdue"
elif transitional > 0:        # class "transitional"
else:                         # class "clear"
```

| Branch | Title | Summary |
|---|---|---|
| overdue | **"Migration is overdue"** | *"{overdue} finding(s) exceed the Mosca threshold and {weak} use(s) algorithms that are already broken today. Immediate action is required."* |
| transitional | **"Migration window is open"** | *"{transitional} finding(s) sit in the transitional window under the active quantum horizon. Plan hybrid transitions now to stay ahead of the schedule."* |
| clear | **"No urgent quantum migration required"** | *"No findings exceed the Mosca threshold under the active quantum horizon. Continue monitoring the cryptographic surface as it evolves."* |

Background colour from `--danger-soft` / `--warn-soft` / `--ok-soft`.

**It reads `scan.summary`,** so a scan with `summary=None` renders the "clear"
branch (all counters default to 0). Worth knowing when debugging an
unexpectedly green report.

### 39.5 KPIs — the only formula in the module

```python
def _pct(numerator: int, denominator: int) -> str:
    if denominator <= 0:
        return "0%"
    return f"{(numerator / denominator) * 100:.0f}%"
```

The 6-KPI grid (3 columns × 2 rows):

| Label | Value | Share | Tone |
|---|---|---|---|
| Total Findings | `total` | "across every discovery source" | — |
| Overdue (Mosca) | `summary.overdue` | `_pct(overdue, total)` + " of total" | `danger` |
| HNDL Exposed | `summary.hndl_exposed` | `_pct(hndl, total)` | `danger` |
| Quantum-Vulnerable | `summary.quantum_sensitive` | `_pct(qsens, total)` | `warn` |
| Currently Weak | `summary.current_weak_crypto` | `_pct(weak, total)` | `danger` if non-zero else "" |
| Needs Review | `summary.needs_verification` | `_pct(needs_verif, total)` | `warn` |

### 39.6 Sort keys

**Top-5 urgent** (`_TIER_WEIGHT = {"overdue": 0, "transitional": 1, "low-risk": 2}`):

```python
def _urgent_key(f: Finding) -> tuple:
    tier = f.risk_tier.value if f.risk_tier else "zzz"
    weak_first = 0 if f.is_currently_weak else 1      # broken today first
    tier_ord   = _TIER_WEIGHT.get(tier, 99)
    hndl_ord   = 0 if f.is_hndl_exposed else 1        # HNDL before non-HNDL in-tier
    return (weak_first, tier_ord, hndl_ord, f.algorithm, f.evidence.file_path)
```

The `"zzz"` sentinel for a missing tier sorts to the `99` default. The comment
explains `weak_first`: *"they are broken today, tier is irrelevant."*

Per row, a reason tag by first match: `" · currently weak"` → `" · HNDL"` →
`" · overdue"`. And a target pill resolved down a four-step fallback chain:
`recommendation.algorithm` → `recommendation.strategy` → `"Replace"` if
currently weak → `"Migrate to PQC"` if HNDL-exposed or overdue → omitted.

**Inventory** (`_TIER_ORDER = {"overdue": 0, "transitional": 1, "low-risk": 2}`):

```python
def _sort_key(f: Finding) -> tuple:
    tier = f.risk_tier.value if f.risk_tier else "zzz"
    return (_TIER_ORDER.get(tier, 99), f.algorithm, f.evidence.file_path, f.evidence.line_number or 0)
```

**Algorithm mini-chart:** `sorted(summary.by_algorithm.items(), key=lambda kv: (-kv[1], kv[0]))`
— count descending, name ascending. `top_algos = algo_totals[:8]`,
`max_count = max((c for _, c in top_algos), default=1)`,
`width = int(round((count / max_count) * 100))`. Falls back to aggregating
from `findings` directly when `summary.by_algorithm` is absent (older cached
scans).

**Breakdown tables** in section 2 use the same `(-count, name)` key,
untruncated.

### 39.7 Section 3 — the full inventory

Twelve columns: Finding ID, Algorithm, Parameter / Version, Mode, Curve,
Usage, Artefact type, Library, Location, Detection, Conf., Risk tier.

**Nothing is truncated.** From the docstring: *"If a scan produces 5 000
findings the table has 5 000 rows — the whole point is to be complete."*
Caption: `f"{len(ordered)} finding{'s'} — all shown, none truncated"`.

Cell derivations worth noting:

```python
parameter = f.parameter or ("-" if f.parameter_status.value == "not_applicable" else "unresolved")
mode = f.mode.value.upper() if f.mode else "-"
confidence_pct = f"{f.evidence.confidence * 100:.0f}%"
```

So a missing parameter reads `-` when genuinely not applicable but
`unresolved` when it *should* have been resolvable — the distinction survives
all the way to the printed table.

Tone maps: tier → `{overdue: danger, transitional: warn, low-risk: ok}` default
`muted`; confidence level → `{high: ok, medium: warn, low: danger}` default
`muted`.

### 39.8 `_library_version` — four narrow extractors

Only runs for `detection_method == "dependency_manifest"`. Four patterns,
tried in order:

| Ecosystem | Trigger | Extraction |
|---|---|---|
| pip | `"=="` in snippet | `split("==", 1)[1].split(";", 1)[0].strip()` |
| npm | `'":'` present **and** `snippet.count('"') >= 4` | `split(":", 1)[1]` stripped of `,` and `"` |
| Go | `" v"` present **and** `library.startswith(("golang.org","github.com","filippo.io"))` | first token starting with `v` |
| Maven | `":"` present **and** `"<dependency>"` present | last colon-separated segment |

The docstring explains the design: *"A few narrow, well-shaped patterns rather
than one greedy regex — keeps false-positive extraction impossible."*

### 39.9 Section 4 — roadmap rendering

```python
_WAVE_PREFIX = re.compile(r"^\s*wave\s+\d+\s*[—\-:·]\s*", re.IGNORECASE)
clean_title = _WAVE_PREFIX.sub("", wave.title).strip() or wave.title
```

Because the planner's titles already read `"Wave 1 — Urgent PQC Migration"`
and the report renders its own `f"Wave {wave.order}: "` prefix, the regex
strips the duplicate. The comment names the bug it prevents: *"the 'Wave 2:
Wave 1 — Urgent PQC Migration' duplication."* Falls back to the raw title if
stripping empties it. The character class handles em dash, hyphen, colon, and
middot.

Header carries `<span class="pill">{wave.strategy.value}</span>` and
`f"{wave.item_count} item{'s' if wave.item_count != 1 else ''}"`. Item columns:
Finding, Target, Tier, Effort, Cost, Location. All items, no truncation
(`# PS: display all cryptographic assets`).

### 39.10 Section 5 — compliance

Header cells per preset: `preset.name` plus `f"Z={preset.z}"`. Body iterates
`comp.presets` in order (no sorting) and `continue`s when
`summary_by_preset.get(preset.name)` is `None`.

Columns: Preset, Overdue (danger), Transitional (warn), Low-risk (ok), N/A
(muted), `Δ overdue`, Source.

```python
delta_class = "danger" if overdue_delta > 0 else ("ok" if overdue_delta < 0 else "muted")
```

Rendered `f"+{delta}"` when positive. A stricter deadline producing more
overdue findings shows a red `+N` — the escalation signal.

### 39.11 Appendix A — CBOM

Reads `metadata`, `components`, `specVersion`, `serialNumber`,
`metadata.timestamp`. Tools read with a shape guard:

```python
tools.get("components", []) if isinstance(tools, dict) else tools or []
```

Empty → `"Not declared."` — which is what Blindspot's own CBOM currently
produces (§37.8).

Component table: bom-ref, Name, Asset type, Primitive, Parameter set, Mode
(`.upper()`), Curve. Every component, unsorted, untruncated
(`overflow = ""  # nothing is truncated any more`). Non-dict entries skipped
via `if not isinstance(c, dict): continue`.

### 39.12 Footer

```
Blindspot ECDAT v{app_version} · generated {_iso(generated_at)}.

Every value in this report is a straight aggregation of the scan's findings.
No runtime latency was measured on the reporting host and no risk score was
recomputed outside the pipeline.

"You cannot migrate cryptography you cannot find."
```

The middle paragraph is the honesty statement, printed on every report.

### 39.13 Print CSS

```css
@page {
  size: A4;
  margin: 18mm 16mm 22mm 16mm;
  @bottom-left  { content: "Blindspot ECDAT  ·  Cryptographic Assets Report"; ... }
  @bottom-right { content: "Page " counter(page) " of " counter(pages); ... }
}
@page :first { @bottom-left { content: ""; } }
```

`@media print` block: `body { font-size: 10.5pt }`, `.container { max-width: none; padding: 0 }`,
box-shadows removed, `a { color: inherit; text-decoration: none }`,
**`thead { display: table-header-group }`** (so long inventory tables repeat
their header on every page), and `tr, td, th { page-break-inside: avoid }`.

Design tokens in `:root`: `--danger #B91C1C`, `--warn #B45309`, `--ok #15803D`,
`--accent #1E40AF`, plus greys. `--fg #111827` on `--bg #FFFFFF` — near-black
on white, print-first.

*Caveat:* the `@bottom-left` / `@bottom-right` margin boxes are CSS Paged
Media features and the PDF path passes `--print-to-pdf-no-header`. Whether
headless Chrome honours them in the generated PDF was not verified by
execution.

---

## 40. CSV inventory export

**File.** `backend/app/report/executive.py::build_asset_csv`

**Plain English.** The same inventory as a spreadsheet, so a compliance team
can filter and pivot it in Excel.

**Working.** RFC 4180 via the stdlib — *"so we do not maintain a hand-rolled
escaper"*:

```python
writer = csv.writer(buf, dialect="excel", lineterminator="\r\n")
```

Thirty fixed columns in a stable order, Title Case with spaces for
spreadsheet readability:

`Scan Id`, `Finding Id`, `Algorithm`, `Display Name`, `Parameter`,
`Parameter Status`, `Mode`, `Curve`, `Primitive`, `Usage`, `Artefact Type`,
`Library`, `Library Version`, `File Path`, `Line Number`, `Detection Method`,
`Confidence`, `Confidence Level`, `Risk Tier`, `Is Quantum Vulnerable`,
`Is Currently Weak`, `Is HNDL Exposed`, `Needs Verification`,
`Data Lifetime Years`, `Criticality`, `Mosca Equation`, `Mosca Applicable`,
`Recommendation Strategy`, `Recommendation Algorithm`,
`Recommendation Rationale`.

Value formatting: booleans as `"true"`/`"false"` strings; confidence as
`f"{confidence:.2f}"`; lifetime as `f"{years:g}"` (so `15.0` prints `15`);
`None` as `""`. The comment states the contract: *"any external tool (Excel,
LibreOffice, GRC importers, python-pandas) that consumes this file will see
the same schema across releases."*

Notably the CSV carries `Mosca Equation` and `Mosca Applicable` side by side —
so a spreadsheet user can filter out non-applicable rows before averaging
anything.

---

## 41. PDF rendering

**File.** `backend/app/report/executive.py::build_executive_pdf`

**Plain English.** Renders the HTML to PDF using whatever Chrome-family
browser is on the machine. If there isn't one, it says so clearly rather than
producing something broken.

### 41.1 Browser discovery

```python
_CHROME_CANDIDATES = ("chrome", "google-chrome", "chromium",
                      "chromium-browser", "msedge", "microsoft-edge")
```

Tried via `shutil.which`, then four hardcoded Windows install paths that are
not on `PATH` by default:

```
C:\Program Files\Google\Chrome\Application\chrome.exe
C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
C:\Program Files\Microsoft\Edge\Application\msedge.exe
```

Edge is included because it ships with Windows — so the PDF path usually works
on a Windows demo machine with no extra install.

### 41.2 The command

```
<chrome> --headless=new --disable-gpu --no-sandbox --no-first-run
         --no-default-browser-check --hide-scrollbars
         --virtual-time-budget=5000
         --print-to-pdf=<pdf_path> --print-to-pdf-no-header
         <html_path.as_uri()>
```

Written into `tempfile.TemporaryDirectory(prefix="blindspot-report-")` as
`report.html`, output to `report.pdf`. Flags chosen to *"keep the run
deterministic and quiet: no network, no first-run animations, no sandboxes
that require supplemental user setup."* `--virtual-time-budget=5000` gives the
page 5 s of virtual time to settle.

Subprocess: `capture_output=True, text=True, timeout=timeout_seconds,
encoding="utf-8", errors="replace"`.

### 41.3 Three failure modes, all explicit

| Condition | `ReportGenerationError` message |
|---|---|
| No binary found | *"No Chrome, Chromium, or Edge binary was found on PATH. PDF rendering is optional; call the HTML endpoint instead, or install a Chromium-family browser."* |
| `TimeoutExpired` | *"Headless Chrome timed out after {timeout_seconds}s while rendering the report to PDF."* |
| `returncode != 0` or no output file | *"Headless Chrome exited with code {returncode}. stderr: {stderr[:400]}"* |

No silent fallback. The builder raises; the API layer converts it to **503
Service Unavailable** with the message passed through verbatim (§51). The
docstring: *"The caller is expected to fall back to serving the HTML variant
with an honest explanation rather than inventing a PDF."*

### 41.4 HTML and PDF are the same document

`GET /api/report` calls `build_executive_html` **once** and, for
`format=pdf`, feeds that exact string to Chrome. The PDF is therefore
byte-for-byte the same document, rendered — never a separate layout that could
drift.

---

# Part VII — Tier S features working

## 42. S1 — CI/CD guardrail

**Plain English.** A GitHub Action that runs on every pull request, scans the
proposed change, compares it against `main`, and fails the build if new
quantum-vulnerable or currently-weak crypto was introduced. Shift-left: bad
crypto never reaches the default branch.

### 42.1 CLI packaging

Registered in `backend/pyproject.toml`:

```toml
[project.scripts]
blindspot-scan = "app.cli.main:main"
```

Installed with `pip install -e backend`. Verified working:
`blindspot-scan --version` → `blindspot-scan 0.1.0 (pipeline 0.1.0)`.

### 42.2 The scan envelope — `app/cli/report.py`

```python
def build_scan_envelope(target, *, project_id="ci", settings=None, now=None) -> dict
```

Schema `blindspot.scan.v1`. Fields:

| Field | Source |
|---|---|
| `schemaVersion` | `"blindspot.scan.v1"` |
| `generatedAt` | UTC ISO-8601 |
| `cli.version` | `CLI_VERSION` (tracks `app.__version__`) |
| `pipeline.version` | `app.__version__` |
| `target.path` | absolute path |
| `target.gitRef` / `target.gitBranch` | from `git_head_meta()`, or `null` |
| `summary` | verbatim `Scan.summary` serialised |
| `findings` | `Finding.to_firestore_document()` dicts |

The docstring: *"Every field on the envelope comes from an existing pipeline
value. Nothing here computes; this module is a shape adapter."*

### 42.3 Git provenance — `app/cli/git_meta.py`

`git_head_meta()` shells out to `git rev-parse` with a 5-second timeout and
returns `{"gitRef": ..., "gitBranch": ...}` — or **both `None`** when git is
absent, the directory isn't a working tree, or the call fails. Never a
plausible-looking fabricated SHA.

### 42.4 The delta engine — `app/cli/diff.py`

**Plain English.** Works out what changed between two scans by fingerprinting
each finding. A finding that merely moved down a few lines is recognised as the
same finding, not as one removed and one added.

**Fingerprint.** SHA-256 over six fields joined with `\x1f` (ASCII unit
separator, so no field boundary can collide with an in-value character):

```python
parts = [algorithm, parameter, curve, filePath, lineNumber, ruleId]
payload = "\x1f".join(parts).encode("utf-8")
return hashlib.sha256(payload).hexdigest()
```

`fingerprint_no_line(...)` is the same tuple **minus `lineNumber`**.

**Shape tolerance — a real bug that was caught and fixed.** The live pipeline
emits `evidence` as a *code-snippet string* with structured metadata under
`evidenceDetail`, while synthetic test fixtures pass `evidence` as a dict.
`_evidence_dict(finding)` accepts either:

```python
def _evidence_dict(finding) -> dict:
    detail = finding.get("evidenceDetail")
    if isinstance(detail, dict):
        return detail
    evidence = finding.get("evidence")
    if isinstance(evidence, dict):
        return evidence
    return {}
```

Without this, every real baseline raised
`AttributeError: 'str' object has no attribute 'get'`. Two regression tests
lock the behaviour.

**Two-pass matching.**

1. **Exact fingerprint pass** — index both sides by `fingerprint()`, pair
   equal hashes.
2. **File-fallback pass** — for leftovers, index by `fingerprint_no_line()`
   and pair at file level, consuming from a pool with `pool.pop(0)`.

The fallback is *one hop deep and never crosses files*. A file with multiple
identical findings does not collapse — 2 baseline and 2 current findings pair
2:2 rather than deduplicating to 1.

**Change detection is field-list driven:**

```python
_TRACKED_CHANGE_FIELDS = (
    "riskTier", "isCurrentlyWeak", "isQuantumSensitive", "isHndlExposed",
    "parameter", "parameterStatus", "needsVerification",
)
```

Deep-equality was rejected because `id` and `createdAt` would spuriously flag
every finding as changed.

Output `blindspot.delta.v1` with `counts`, `introduced`, `resolved`,
`changed`. All lists deterministically sorted.

### 42.5 The policy engine — `app/cli/policy.py`

Schema `blindspot.policy.v1`. Rule shape:

```json
{"id": "...", "on": "introduced|resolved|changed|all",
 "match": {"dotted.key": value}, "action": "block|warn"}
```

**Strict validation at load**, not lazily at evaluation — *"so a typo in a CI
config fails immediately, not later on a real diff."* Every violation raises
`PolicyError` naming the offending index and field.

**The built-in default policy — four rules:**

| Rule id | `on` | `match` | `action` |
|---|---|---|---|
| `no-new-weak-now` | `introduced` | `{"isCurrentlyWeak": True}` | **block** |
| `no-new-overdue` | `introduced` | `{"riskTier": "overdue"}` | **block** |
| `no-regressions` | `changed` | `{"changes.riskTier.to": "overdue"}` | **block** |
| `warn-new-hndl` | `introduced` | `{"isHndlExposed": True}` | warn |

**Dotted-path resolution** is what makes `no-regressions` work:

```python
def _resolve_dotted(doc, dotted_key):
    cur = doc
    for part in dotted_key.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur
```

So `changes.riskTier.to` walks into the delta's change record. No regex, no
arithmetic, no user-supplied Python — deliberate, for auditability.

Each `Violation` carries `ruleId`, `findingId`, `reason`, `field`, `value`,
`action`. `_reason_for` maps the four built-in rules to human sentences
(*"New finding is currently weak."*, *"Existing finding regressed to
overdue."*, …) and falls back to `f"Rule matched: {key}={value!r}"`.

`has_block_violations(violations)` → `any(v.action == "block" ...)`.

### 42.6 Exit codes — the CI contract

```python
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_POLICY_VIOLATION = 2
EXIT_USAGE = 3
```

Argparse's own error code is 2, which would collide with "policy violation" —
so `main()` intercepts and remaps:

```python
try:
    args = parser.parse_args(argv)
except SystemExit as exc:
    code = exc.code if isinstance(exc.code, int) else EXIT_USAGE
    if code in (0, None):
        return EXIT_OK          # --help / --version
    return EXIT_USAGE           # parse error → 3, not 2
```

**stdout/stderr split.** JSON only on stdout; all progress, warnings, and the
`gate FAILED` banner on stderr. `--quiet` suppresses progress but never
touches stdout. The docstring: *"This split is the whole CI contract — do NOT
mix them."*

**Baseline handling:** a *missing* baseline file is treated as an empty
baseline (everything is "introduced") with a stderr note; an *unreadable or
malformed* one is `EXIT_ERROR`. The distinction is deliberate — the first is a
legitimate first run, the second is a problem the operator must see.

### 42.7 Verified end-to-end

| Command | Result |
|---|---|
| `blindspot-scan --quiet scan ../demo-repo --out baseline.json` | exit **0**, 18 findings |
| `blindspot-scan --quiet gate ../demo-repo --baseline baseline.json` | exit **0**, 18 unchanged, 0 violations |
| same gate against an *empty* baseline | exit **2**, `gate FAILED: 11 block violation(s), 5 warn violation(s)` |

---

## 43. S2 — Cross-scan diff

**Plain English.** Pick any two past scans and see exactly what changed:
which findings appeared, which were fixed, which changed risk tier. A negative
overdue delta means the migration is progressing; a positive one means
something regressed.

**Files.** `backend/app/diff/cbom_diff.py` (pure), `backend/app/api/scans_diff.py` (endpoint),
`frontend/src/components/DiffPanel.tsx`.

### 43.1 Match key — different from the CLI's

```
(algorithm, parameter, curve, filePath)
```

**No line number.** The design note: *"line drift is NOT a diff."* The CLI
delta engine (§42.4) *does* include line number with a fallback pass, because
CI cares about precise introduction points; the dashboard diff cares about
whether an asset exists at all. Two deliberate, separately-justified choices.

### 43.2 Signed deltas

`summaryDelta` is computed `head − base`. So:

- **negative overdue delta** → fewer overdue findings → migration progressed
- **positive overdue delta** → new quantum-vulnerable crypto entered

The frontend colours each chip accordingly, with `invertColour` on the
counters where "fewer is better" (overdue, transitional, HNDL, weak-now).

### 43.3 Router registration order — a real bug avoided

```python
# scans_diff MUST be included BEFORE scans -- the scans router carries a
# ``/scans/{scan_id}`` catch-all that would otherwise greedily match
# ``/scans/diff`` and 404 as "no scan with id 'diff'".
api_router.include_router(scans_diff.router)
api_router.include_router(scans.router)
```

### 43.4 Owner scoping without existence leaks

`_load_visible_scan(scan_id, user, settings)` returns `None` for three
different situations — file missing, file unreadable, caller doesn't own it —
and the endpoint maps **every** `None` to 404. The docstring: *"We
deliberately do NOT distinguish those cases in the return value — so an
attacker cannot probe for scan ids that belong to another user."*

`base == head` → 400 with *"Base and head scan ids must be different."*

### 43.5 Frontend UX contract

`DiffPanel` renders three buckets (Changed / Added / Removed). Each bucket:

- scrolls inside a bounded region (`max-h-[320px] overflow-auto`) so a
  300-row Added list cannot push the other buckets off the page
- has a **sticky column header** while scrolling
- **auto-collapses above 25 rows** (`AUTO_COLLAPSE_THRESHOLD`), keeping the
  count badge visible
- header is a toggle button with `aria-expanded`; empty buckets render a
  *disabled* button with no `aria-expanded` so keyboard users aren't
  offered an empty region

---

## 44. S3 — Policy as code

**Plain English.** Every organisation has a different idea of what should
block a pull request. This lets you edit that policy as JSON in the dashboard,
test it against two past scans before committing to it, and use the exact same
policy file in CI.

**Files.** `backend/app/policy/store.py`, `backend/app/api/policy.py`,
`frontend/src/components/PolicyEditor.tsx`. Schema and evaluator are shared
with the CLI (`app/cli/policy.py`).

### 44.1 Shared schema — one source of truth

`app/cli/policy.py` gained two public wrappers so the API layer reuses the
CLI's validator rather than reimplementing it:

```python
def parse_policy_dict(raw: dict) -> Policy      # public wrapper over _parse_policy
def policy_to_dict(policy: Policy) -> dict      # round-trip guaranteed
```

Round-trip guarantee: `parse_policy_dict(policy_to_dict(p)) == p` for any
valid `p`. That is what makes `blindspot-scan gate` and the dashboard produce
byte-identical verdicts.

### 44.2 Atomic persistence

```python
tmp = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8",
                                  dir=str(self.directory),
                                  prefix=".policy-", suffix=".tmp", delete=False)
tmp.write(payload)
tmp.flush()
os.fsync(tmp.fileno())
tmp.close()
os.replace(tmp.name, self.path)
```

**Four properties:**

1. `dir=str(self.directory)` — the temp file is on the *same filesystem*, so
   `os.replace` is an atomic rename rather than a cross-device copy that
   could tear.
2. `os.fsync` before rename — data is on disk before the pointer swaps.
3. Validation happens **before** the write: `parse_policy_dict(raw)` raises
   `PolicyError` first, so a malformed policy never touches disk.
4. Cleanup on any exception via `os.unlink(tmp.name)` in a nested
   `try/except OSError: pass`.

In-process writes are serialised by a `threading.Lock`; cross-process safety
comes from the atomic rename.

### 44.3 Corrupt-file behaviour

```python
def get(self) -> Policy:
    if not self.path.is_file():
        return DEFAULT_POLICY
    try:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"active policy file is unreadable: {self.path}: {exc}")
    return parse_policy_dict(raw)
```

A hand-edited invalid policy raises rather than silently falling back to the
default — the API turns it into **500** with the reason. Masking a corrupt
policy as "using defaults" would be the dangerous behaviour, because CI would
then enforce rules the operator did not write.

`has_override()` distinguishes "user customised" from "using built-in
default" without changing what `get()` returns — surfaced as `isDefault` in
the API envelope.

`reset()` is idempotent: `except FileNotFoundError: pass`.

### 44.4 Test isolation

`get_default_store()` caches a module-level singleton rooted at
`settings.artifacts`. Since each test gets a fresh `tmp_path`, the singleton
would leak the first test's path into every subsequent test — so
`conftest.py` calls `_reset_default_store_for_tests()` in both the setup and
teardown halves of the `isolated_env` fixture.

### 44.5 Simulation endpoint

`POST /api/policy/simulate` with `{base, head, policy?}`:

- `policy` present → validate and evaluate it
- `policy` omitted → evaluate the currently active policy

It uses the **CLI's** `compute_delta`, so *"the answer here matches
`blindspot-scan gate` byte-for-byte."* Returns `policyName`, `counts`,
`violations`, `blockCount`, `warnCount`, and `wouldBlock` (`blockCount > 0`).
Nothing is persisted.

---

## 45. S4 — Benchmark harness

**Plain English.** How accurate is the scanner? Blindspot ships 12
hand-labelled crypto cases and measures its own precision, recall, and F1
against them — then shows the number on the dashboard, including the cases it
misses.

**Files.** `backend/app/benchmark/{dataset,metrics,harness}.py`,
`backend/app/benchmark/data/`, `backend/app/api/benchmark.py`.

### 45.1 Manifest schema — `blindspot.benchmark.v1`

```json
{
  "id": "weak-rsa-1024",
  "file": "cases/weak_rsa_1024.py",
  "category": "weak-crypto/rsa",
  "language": "python",
  "expected": [
    {"algorithm": "RSA", "parameter": "1024",
     "expectedTier": "overdue",
     "notes": "NIST SP 800-131A rev 3 disallows 1024-bit RSA for signing since 2013."}
  ]
}
```

`expected: []` means a **true-negative** case — the scanner must find nothing.

Validation is strict and rejects **unknown keys** (`_VALID_CASE_KEYS`,
`_VALID_EXPECTED_KEYS`) so a typo like `"Category"` fails loudly rather than
being silently ignored. Duplicate case ids are refused. Every error names the
offending index or case id.

### 45.2 Matching — `ExpectedFinding.matches`

```python
algo_a = (self.algorithm or "").strip().upper()
algo_b = str(finding.get("algorithm") or "").strip().upper()
if algo_a != algo_b: return False
if self.parameter is not None and str(self.parameter).strip() != str(finding.get("parameter") or "").strip():
    return False
if self.curve is not None and <same for curve, case-insensitive>:
    return False
return True
```

Algorithm match is **case-insensitive** here (unlike the risk tables).
Parameter and curve are only checked when the expectation names them — so an
expectation of just `{"algorithm": "MD5"}` matches regardless of parameter.

### 45.3 Scoring — `compute_case_confusion`

Greedy but deterministic pairing:

1. For each expected slot in manifest order, walk the still-unmatched
   reported findings in pipeline order and pair the first that matches.
2. Unmatched expectations → `missed` (FN). Unmatched reports → `extra` (FP).
3. A case with no expectations **and** no reports → one TN.

```python
if case.is_true_negative and fp == 0:
    tn = 1
else:
    tn = 0
```

**Multiple identical findings are not collapsed.** Two expected RSA-2048 and
three reported → 2 TP + 1 FP, not 1 TP + 1 FP.

### 45.4 Metrics

```python
precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
f1        = 2*p*r / (p + r) if (p + r) > 0 else 0.0
accuracy  = (tp + tn) / total if total > 0 else 0.0
```

Zero denominators return `0.0` rather than raising — *"an evaluator that
reports 'no findings expected AND none produced' should not crash on
`ZeroDivisionError`."* Values are returned **unrounded**; rounding is a
rendering concern.

### 45.5 One scan, not N

```python
findings = scan_fn(dataset.root, settings)
buckets  = _bucket_findings_by_file(findings)
```

The harness scans the dataset **directory once** and buckets findings by
relative `filePath`, rather than invoking the pipeline per case. Path
normalisation handles Windows:

```python
norm = str(path).replace("\\", "/")
```

and case lookup does the same — so a manifest entry `cases/weak_rsa_1024.py`
matches a finding at `cases\weak_rsa_1024.py`.

Falls back to `evidenceDetail.filePath` when the top-level field is null.

### 45.6 Missing files are refused, not scored

```python
missing = dataset.missing_files()
if missing:
    raise BenchmarkError(
        "benchmark dataset is incomplete; the following case files "
        f"are missing on disk: {[c.file for c in missing]}"
    )
```

**Plain English.** If a case file is missing, scoring it as a true negative
would silently inflate accuracy. So the harness refuses to run.

### 45.7 Dependency injection for fast tests

```python
ScanFn = Callable[[Path, Settings], list[dict[str, Any]]]

def run_benchmark(dataset, *, settings=None, scan_fn=None, now=None) -> BenchmarkReport
```

Real callers get `_default_scanner` (which calls `run_pipeline`). Tests inject
a fake, so the 7 harness tests run in milliseconds without needing semgrep.

### 45.8 The measured result

Running the real harness against the bundled dataset:

```
overall: {'tp': 8, 'fp': 0, 'fn': 2, 'tn': 2,
          'precision': 1.0, 'recall': 0.8,
          'f1': 0.888888888888889, 'accuracy': 0.8333333333333334}
```

Per category:

| Category | TP | FP | FN | TN | F1 |
|---|---|---|---|---|---|
| `weak-crypto/rsa` | 1 | 0 | 0 | 0 | 1.00 |
| `weak-crypto/hash` | 2 | 0 | 0 | 0 | 1.00 |
| `weak-crypto/mode` | 1 | 0 | 0 | 0 | 1.00 |
| `weak-crypto/symmetric` | 1 | 0 | **1** | 0 | 0.67 |
| `quantum-overdue/rsa` | 1 | 0 | 0 | 0 | 1.00 |
| `quantum-overdue/ec` | 1 | 0 | 0 | 0 | 1.00 |
| `quantum-overdue/keyexchange` | 0 | 0 | **1** | 0 | 0.00 |
| `acceptable/symmetric` | 1 | 0 | 0 | 0 | 1.00 |
| `negative` | 0 | 0 | 0 | **2** | 0.00 † |

† The harness emits `f1: 0.0` for the `negative` category because F1 is
undefined when `tp = fp = fn = 0`. Read it as "not applicable", not as a
failure: both negative cases were correctly reported clean (`tn = 2`).

**Precision 1.00 — zero false positives.** Every finding the scanner reported
was genuinely expected.

**Recall 0.80 — two real misses**, and the report names them:

1. **3DES via pycryptodome** (`DES3.new(...)`) — the Python rule pack covers
   `DES` via pycryptodome but this specific 3DES construction is not matched.
2. **DH-2048 via `cryptography.hazmat`** (`dh.generate_parameters(...)`) — no
   Python rule covers finite-field Diffie-Hellman key generation (the Java
   pack has `blindspot-java-dh-keygen`, Python does not).

Both are genuine rule-coverage gaps, named by case id in the report's
`missed` array, and both are fixable by adding two rules. The benchmark is
the mechanism that makes the gap visible rather than invisible.

### 45.9 API concurrency

```python
acquired = _run_lock.acquire(blocking=False)
if not acquired:
    raise HTTPException(409, "A benchmark run is already in progress.")
try:
    ...
finally:
    _run_lock.release()
```

Non-blocking acquire → **409 Conflict** rather than queueing, because the
pipeline is expensive and a queued duplicate serves nobody. Result cached to
`settings.artifacts/benchmark-latest.json`; `GET /latest` returns it or 404.
---

# Part VIII — Tier A features working

Tier S (Part VII) made the platform *credible*: a policy you can edit, a
benchmark you can re-run, a diff you can gate on. Tier A makes it
*persuasive*. Each of the five features below answers a question a reviewer
asks out loud during a demo, and each one answers it with data the pipeline
already produced rather than a new source of truth.

That constraint matters. Every Tier A feature is a **projection**, not a
computation. None of them re-derives risk. If the roadmap and the blast-radius
graph ever disagree, that is a bug in the projection, not a difference of
opinion between two engines.

---

## 46. A1 — Blast-radius graph

### Plain English

A findings table tells you *what* is broken. It does not tell you *how
tangled* it is. Twenty findings spread across twenty files is a very
different migration from twenty findings that all trace back to one crypto
helper.

The blast-radius graph draws that shape. Files sit on an outer ring,
algorithms on an inner ring, and a line connects a file to every algorithm it
touches. A file with many lines is load-bearing — change it and a lot moves.
An algorithm with a fat node is systemic — it is not one mistake, it is a
habit.

Click any node and everything unrelated fades out. That is the whole
interaction: one click to answer "if I fix this, what else do I touch?"

### Technical

**Builder**: `backend/app/graph/builder.py`

```python
GRAPH_SCHEMA_VERSION = "blindspot.graph.v1"

def build_dependency_graph(findings) -> DependencyGraph
```

The graph is **bipartite**: two disjoint node sets (files, algorithms) with
edges only ever crossing between them. Never file→file, never
algorithm→algorithm. That is a deliberate modelling choice — Blindspot does
not claim to know the import graph (see §64, non-goals), so it does not draw
one.

**Node identity is content-hashed, not positional:**

```python
def _file_id(path)                 -> "f:" + sha256(path)[:16]
def _algorithm_id(algo, param, curve) -> "a:" + sha256(...)[:16]
```

Two findings on the same file produce the same node id because the id is
derived from the path, not from iteration order. That makes the graph stable
across scans — a node keeps its identity as long as the file keeps its path,
which is what makes frontend animations and selection state survive a refresh.

**Tier aggregation — worst wins:**

```python
_TIER_RANK = {"overdue": 3, "transitional": 2, "low-risk": 1, "unknown": 0}

def _worse_tier(a, b):  # bubbles the worse of the two upward
```

A file node's tier is the **worst** tier among its findings, not the average
and not the most common. A file with nineteen low-risk findings and one
overdue finding renders red. The reasoning: you cannot partially migrate a
file. If one call site in it is overdue, the file is on the critical path.

**The blast-radius number — read this carefully:**

```
file node:      blastRadius = len(distinct algorithm ids touched)
algorithm node: blast_radius = 0
```

This is **not the same number** as the roadmap's `blast_radius`. The roadmap
counts *findings per file* (§35). The graph counts *distinct algorithms per
file*. Both are legitimate and both are honest, but they answer different
questions:

| Metric | Source | Question it answers |
|---|---|---|
| Roadmap `blast_radius` | `_blast_radius_by_file` — finding count | "How much work is in this file?" |
| Graph `blastRadius` | distinct algorithm ids | "How many different crypto decisions does this file entangle?" |

A file with eight RSA call sites and nothing else scores 8 in the roadmap and
1 in the graph. That is correct in both places. It is flagged again in §63
because it is the single most likely thing for a reviewer to read as a
contradiction.

Algorithm nodes carry `blast_radius = 0` rather than a file count. The
builder deliberately does not make the number mean two things depending on
which ring you are looking at; algorithm nodes expose `findingCount` instead.

**Skip rules.** A finding is dropped from the graph if it has no `filePath`
**or** no `algorithm`. An edge needs both endpoints to exist; a half-edge is
not drawable and inventing a placeholder node would be fabrication. Dropped
findings still appear in the findings table — the graph is a projection, not
a filter on truth.

**Path extraction** uses `_extract_file_path`, which tries `filePath` first,
then falls back through `evidenceDetail` → `evidence`. Scanner output shapes
vary (§11–21), and the graph would rather find the path in an odd place than
silently omit a node.

**Determinism.** Everything is sorted before emission:

- files by `path`
- algorithms by `(algorithm, parameter)`
- edges by `(source, target, finding_id)`

Same findings in, byte-identical JSON out. Required for the 12 backend tests
to assert on exact output, and required for the frontend's stagger animation
to be reproducible.

**Endpoint**: `GET /api/graph/{scan_id}` — `backend/app/api/graph.py`.
Owner-scoped: a scan belonging to another user returns **404, not 403**, so
the endpoint does not confirm the existence of scans you cannot read.

### Frontend mechanics

`frontend/src/components/DependencyGraph.tsx`

```ts
VIEWBOX = 760;  CENTER = 380
OUTER_RADIUS = 305        // file ring
INNER_RADIUS = 140        // algorithm ring
FILE_LABEL_OFFSET = 20
```

Node radii scale by **square root**, not linearly, and both are clamped:

```ts
_fileRadius      = min(20, max(5,  5  + √blastRadius  * 4))
_algorithmRadius = min(28, max(14, 14 + √findingCount * 3))
```

Square root because area, not radius, is what the eye reads as magnitude —
linear scaling makes a 10× count look 10× wider and therefore ~100× heavier.
Clamping because one pathological file should not consume the canvas.

**Colour** — `_tierColor`:

| Tier | Hex |
|---|---|
| `overdue` | `#EF4444` |
| `transitional` | `#F59E0B` |
| `low-risk` | `#10B981` |
| (default / unknown) | `#94A3B8` |

**Animation** — four CSS keyframe sets:

| Keyframe | Duration / easing | Notes |
|---|---|---|
| `graph-node-in` | 520ms `cubic-bezier(0.2, 0.9, 0.3, 1.2)` | delay = `index * 25ms` stagger |
| `graph-edge-in` | 900ms, delay 320ms | animates `stroke-dashoffset` so edges draw themselves |
| `graph-ring-in` | — | guide rings fade in first |
| `graph-pulse` | 1.6s, `infinite` | applied only to the selected node |

The overshoot in the node easing (`1.2` final control point) is what makes
nodes settle rather than stop. Edges start at 320ms so the rings and nodes
exist before lines connect them — otherwise the first frame is a knot.

**Focus interaction.** On select:

- unrelated nodes drop to `opacity: 0.35`
- off-focus edges drop to alpha `0.06`
- hover halo renders at `fillOpacity` 0.25 (selected) / 0.18 (hover)

Dimming rather than hiding. A hidden node changes the layout; a dimmed node
keeps the shape of the problem visible while you read one part of it.

**Chrome.** An in-SVG `Legend` (all four tiers, always all four, even if the
scan has no low-risk findings — a legend that changes shape per scan teaches
the reader nothing), a `HoverTooltip`, and a centre hub reading
`BLAST RADIUS` over `N files → M algorithms`.

`FileLabel` rotates tangentially to its ring and **flips 180°** when its
angle exceeds 90° or falls below −90°, so no label renders upside down on the
left-hand arc.

**Tests**: 12 backend, 10 frontend.

---

## 47. A2 — Preset sensitivity strip

### Plain English

Every Mosca verdict depends on one number you cannot measure: *when does a
quantum computer arrive?* Blindspot ships seven answers to that question
(§58) and defaults to one of them.

A2 puts that choice next to a single finding. Pick a different timeline from
the dropdown and the risk chip and the inequality update in place. If the
tier actually changes, a flip indicator says so.

The point is not to let you shop for a comfortable answer. The point is to
show which findings are *robust* — red under every preset — versus which are
*sensitive* to an assumption. A finding that flips between "overdue" and
"transitional" depending on whether you believe 2030 or 2035 is a finding you
should discuss, not one you should silently schedule.

### Technical

**No new backend endpoint.** A2 reuses `GET /api/compliance`, which already
returns every finding evaluated against every preset. Adding a second
endpoint would have created a second path to the same number, which is how
two numbers start disagreeing.

**Component**: `frontend/src/components/FindingPresetSensitivity.tsx`, mounted
in `FindingDetail.tsx` immediately after the header.

Flow:

1. Fetch `/api/compliance`.
2. Locate this finding's row by `findingId`.
3. Render a `<select>` of the preset names from that row.
4. On change, live-swap the `RiskChip` and the Mosca equation from the
   selected preset's evaluation.
5. Compare `activeTier.tier` against `baselineTier.tier`; if they differ,
   render the flip indicator.

The **Z source string** is read from
`evaluation.presets.find(p => p.name === selected)?.source` — the provenance
text travels with the preset, so the UI never authors its own justification
for a horizon (§61, provenance is never faked).

**Failure behaviour**: `return null` on fetch error *or* on finding-not-found.
Silent. This is a supplementary panel on a page whose primary job is showing
one finding; a compliance endpoint hiccup must not take down the finding
detail view. The absence of the panel is the error message.

**Tests**: 5.

---

## 48. A3 — Wave-plan card

### Plain English

The roadmap page already sequences the work into waves. The dashboard did
not. A3 puts a compact version of the wave plan on the dashboard so the first
screen answers "what do we do, in what order?" without a click.

### Technical

Reuses `GET /api/roadmap`. No new endpoint, no recomputation.

**Component**: `frontend/src/components/WavePlanCard.tsx`

- `_summariseEffort` tallies items per effort band within each wave.
- `_strategyTone` maps `MigrationStrategy` to the card's colour treatment.
- Footer links to `/roadmap` for the full view.

The executive PDF's §4 already carried a wave section (§39). A3 is the
dashboard variant of the same projection — same endpoint, same ordering, same
five waves including empty ones (§35). A wave that renders empty is
information: it says "nothing is deferred", not "we forgot to compute this".

**Tests**: 4.

---

## 49. A4 — Crypto-agility score

### Plain English

Executives ask for one number. Giving them one number is usually a lie,
because a single score hides which part of the estate is actually bad.

A4 gives a number **and** shows its three components with the arithmetic
visible. 0–100, graded A–F. If you disagree with the score you can see
exactly which of the three budgets produced it, and the rationale strings say
so in words.

The three components:

- **Tier posture (60 pts)** — how much of the estate is already safe. Full
  credit for low-risk, half credit for transitional, nothing for overdue.
- **Weakness immunity (25 pts)** — how much is broken *today*, independent of
  quantum. MD5 and DES do not need a quantum computer.
- **HNDL immunity (15 pts)** — how much is harvest-now-decrypt-later
  exposed: long-lived confidential data on quantum-vulnerable crypto.

### Technical

**Module**: `backend/app/agility/score.py`

```python
AGILITY_SCHEMA_VERSION = "blindspot.agility.v1"

_TIER_POSTURE_BUDGET      = 60.0
_WEAKNESS_IMMUNITY_BUDGET = 25.0
_HNDL_IMMUNITY_BUDGET     = 15.0

assert (
    _TIER_POSTURE_BUDGET + _WEAKNESS_IMMUNITY_BUDGET + _HNDL_IMMUNITY_BUDGET
) == 100.0, "agility component budgets must sum to 100"
```

That `assert` is at **module level** — it runs at import. Re-weighting one
budget without fixing the others fails the import, not a test three files
away. The budgets are constants rather than inline literals specifically so
tests can assert the invariant without re-hardcoding it.

**Formulas:**

```python
# Tier posture — 60 pts
tiered_sum   = min(total, low_risk) + 0.5 * min(total, transitional)
tier_posture = 60.0 * (tiered_sum / total)

# Weakness immunity — 25 pts
weakness_immunity = 25.0 * (1 - min(1.0, weak / total))

# HNDL immunity — 15 pts
hndl_immunity = 15.0 * (1 - min(1.0, hndl / total))
```

The `min(total, ...)` guards and the `min(1.0, ...)` clamps are defensive
against a malformed summary where a sub-count exceeds the total. Rather than
emitting a score above 100 or below 0, the component saturates.

Final clamp: `max(0.0, min(100.0, total))`.

**Empty scan.** When `total <= 0`, all three budgets are awarded in full —
score 100 — with an **explicit rationale line**:

> "No findings on this scan. Tier posture defaults to full credit; …"

This is the honest way to handle a divide-by-zero. A scan of a repository
with no crypto genuinely has no crypto debt, so 100 is the right number, but
the rationale prevents the UI from advertising a perfect score for a repo the
operator never actually scanned properly.

**Grades:**

| Score | Grade |
|---|---|
| ≥ 85 | A |
| ≥ 70 | B |
| ≥ 55 | C |
| ≥ 40 | D |
| < 40 | F |

**Input tolerance**: `_read_int` accepts **either** camelCase or snake_case
keys, because the summary dict crosses the Pydantic alias boundary (§55) and
has been observed in both spellings depending on whether it came from a fresh
model or a round-tripped store payload.

**Endpoint**: `GET /api/agility/{scan_id}`. Reads the **persisted**
`scan.summary` verbatim. The caller supplies a scan id and nothing else —
there is no request body, so a client cannot post a flattering summary and
receive an A. The score is a function of stored scan data only.

**Tests**: 30 backend (`tests/test_agility_score.py` +
`tests/test_agility_api.py`), 4 frontend
(`src/components/AgilityScoreCard.test.tsx`).
**Frontend**: `AgilityScoreCard.tsx` + `services/agilityApi.ts`.

---

## 50. A5 — CBOM interoperability diff

### Plain English

Blindspot emits a CycloneDX CBOM. So does IBM's CBOMkit. So do several
others. The obvious reviewer question is: *are these the same thing, or do
you all just use the same file extension?*

A5 answers it. Drop two CBOM files in — from any tools, in any combination —
and it lists which cryptographic assets were added, removed, and changed, and
for changed ones, *what* changed: the algorithm, the parameter set, the
curve, the mode, or the risk tier.

It is the only feature in the platform that reads a CBOM produced by
something else. That is the point.

### Technical

**Module**: `backend/app/cbom/interop_diff.py`

```python
INTEROP_DIFF_SCHEMA_VERSION = "blindspot.cbom.interop.v1"
```

**The match key is the whole design decision:**

```python
key = sha256(f"{name.lower()}|{primitive.lower()}")
```

**Not `bom-ref`.** Different tools assign completely different `bom-ref`
values to the same algorithm — they are document-local identifiers, not
stable identities. Matching on them would report every asset as
simultaneously added and removed. Matching on `(name, primitive)`, lowercased
and hashed, is what makes a cross-tool diff meaningful at all.

This is also the hash-not-fuzz principle from §61: the key is an exact hash of
normalised fields, not a similarity score. Two assets either match or they do
not. There is no threshold to tune and no "probably the same" state.

**Tracked fields:**

```python
_TRACKED_FIELDS = ("primitive", "parameter_set_identifier", "curve", "mode", "tier")
```

**Change classes**, one per tracked field:

| Class | Fires when |
|---|---|
| `algorithm_changed` | `primitive` differs |
| `parameter_changed` | `parameter_set_identifier` differs |
| `curve_changed` | `curve` differs |
| `mode_changed` | `mode` differs |
| `tier_changed` | `tier` differs |

**Tier extraction is deliberately promiscuous** — `_extract_tier` looks for,
in order:

1. `properties[].name` in `{"blindspot:risktier", "risktier", "risk_tier"}`
2. `cryptoProperties.riskTier`

Three spellings plus a fallback location, because risk tier is not a
standardised CycloneDX field. Every tool that emits it invents a place to put
it. The diff would rather find it in an unexpected key than report a
false `tier_changed`.

**Partial-BOM tolerance.** Missing sections, absent `cryptoProperties`,
components with no name — all handled. The input is a file a human dragged in
from another tool; it will be malformed eventually.

`_extract_meta` pulls `specVersion`, `timestamp`, `componentCount`,
`cryptoAssetCount`, and `tools` from each side so the UI can show what it is
actually comparing.

**Endpoint**: `POST /api/cbom/diff`, body `{base, head}`. Returns **400** if
either side is an empty dict — an empty CBOM diffed against a real one would
report everything as removed, which is technically true and completely
useless.

**Tests**: 13 backend (`tests/test_cbom_interop_diff.py`), 4 frontend
(`src/components/CbomInteropDiff.test.tsx`).
**Frontend**: `CbomInteropDiff.tsx` + `services/cbomInteropApi.ts`, dual
drag-and-drop zones. `_readAsText` includes a `FileReader` fallback path
because jsdom's `File.text()` is not reliably available in the test
environment.

### The known gap

Blindspot's own CBOM does **not** currently emit a `blindspot:riskTier`
property (§63). So `tier_changed` cannot fire when diffing two Blindspot
CBOMs. It works when one side comes from a tool that does emit tier, and the
extraction logic is ready for the day Blindspot's builder adds it. Documented
rather than hidden.

---

# Part IX — Surfaces

Four ways in: HTTP, CLI, GitHub Action, browser. All four are thin. Every one
of them calls the same `run_pipeline` (§5) and none of them contains business
logic. That is what makes the CLI's verdict and the dashboard's verdict the
same verdict.

---

## 51. REST API — every endpoint

### Plain English

One FastAPI app, everything under `/api`. Reads are `GET`, actions are `POST`,
policy replacement is `PUT`. Nothing surprising — which is the goal.

### Technical

**Registration**: `backend/app/api/__init__.py` aggregates 15 routers under a
single `APIRouter(prefix="/api")`.

**Complete endpoint inventory:**

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/health` | liveness + storage backend posture |
| `POST` | `/api/scan` | run the pipeline |
| `GET` | `/api/scans` | list scans |
| `GET` | `/api/scans/trend?project_id=` | posture over time |
| `GET` | `/api/scans/diff?base=&head=` | scan delta |
| `GET` | `/api/scans/{scan_id}` | one scan |
| `GET` | `/api/findings` | list findings |
| `GET` | `/api/findings/{finding_id}` | one finding |
| `GET` | `/api/compliance` | all findings × all Z presets |
| `GET` | `/api/roadmap` | wave plan |
| `GET` | `/api/report?format=&scanId=` | HTML / PDF / CSV |
| `GET` | `/api/export/cbom` | CycloneDX CBOM |
| `POST` | `/api/tls-scan` | live TLS handshake probe |
| `GET` | `/api/policy` | active policy |
| `GET` | `/api/policy/default` | shipped default policy |
| `PUT` | `/api/policy` | replace policy |
| `POST` | `/api/policy/reset` | restore default |
| `POST` | `/api/policy/simulate` | dry-run policy against a scan |
| `POST` | `/api/benchmark/run` | run labelled-corpus benchmark |
| `GET` | `/api/benchmark/latest` | last benchmark result |
| `GET` | `/api/agility/{scan_id}` | agility score (§49) |
| `POST` | `/api/cbom/diff` | CBOM interop diff (§50) |
| `GET` | `/api/graph/{scan_id}` | blast-radius graph (§46) |

**Registration order is load-bearing.** From the source, verbatim:

```python
# scans_diff MUST be included BEFORE scans -- the scans router carries a
# ``/scans/{scan_id}`` catch-all that would otherwise greedily match
# ``/scans/diff`` and 404 as "no scan with id 'diff'".
api_router.include_router(scans_diff.router)
api_router.include_router(scans.router)
```

FastAPI matches routes in registration order. `/scans/{scan_id}` is a
wildcard that happily accepts the literal string `diff`. Register the
specific route first or the diff endpoint disappears into a 404 that looks
like a data problem.

**`GET /api/report`** validates `format` against `^(html|pdf|csv)$` at the
route level, so an unsupported format is a 422 from FastAPI rather than a
branch inside the handler.

**`GET /api/health`** reports the Firebase backend as `degraded` **only when
the operator did not pin `STORAGE_BACKEND=local`**. Running deliberately
local is a healthy configuration (air-gap mode, §58); falling back to local
because Firebase failed is not. The same runtime state gets two different
verdicts depending on whether it was chosen, and the setting is how the
endpoint knows which.

---

## 52. CLI — `blindspot-scan`

### Plain English

`blindspot-scan` does three things: scan a path, diff against a baseline, or
gate a build. It prints JSON and sets an exit code. That is the entire
contract, and it is enough for CI.

### Technical

```
blindspot-scan [--quiet] {scan,diff,gate}

scan <path> [--project-id ID] [--out FILE]
diff <path> --baseline FILE [--out FILE]
gate <path> --baseline FILE [--policy FILE] [--out FILE]
```

**`--quiet` is global and must precede the subcommand.** `argparse` binds
global options to the top-level parser; `blindspot-scan scan --quiet .` is a
parse error, not a quiet scan.

**Exit codes:**

| Code | Meaning |
|---|---|
| 0 | success / gate passed |
| 1 | operational error (unreadable baseline, bad path) |
| 2 | gate violation — findings breached policy |
| 3 | usage error |

The separation of **1** from **2** is what makes the Action work. Exit 2 is a
*signal* — the tool ran correctly and the answer was "blocked". Exit 1 means
the tool itself failed. Conflating them turns a broken checkout into a policy
violation.

---

## 53. GitHub Action

### Plain English

Drop four lines in a workflow and every pull request gets scanned against its
own base branch. New crypto debt fails the build; pre-existing debt does not.
That distinction is the whole reason the Action is baseline-aware rather than
threshold-based.

### Technical

**`Dockerfile`** (repository root):

- base `python:3.11-slim`
- apt: `git`, `bash`, `ca-certificates`, `curl`
- `SEMGREP_SEND_METRICS=off` — no telemetry from CI runs
- layered install: `requirements.txt` first, then `pyproject.toml` + `app/`,
  then `pip install --no-deps --editable`. Dependencies cache as one layer;
  application code changes do not invalidate it.
- `ENTRYPOINT /opt/blindspot/entrypoint.sh`

**`action/action.yml`:**

| Inputs | Outputs |
|---|---|
| `path` | `introduced-count` |
| `baseline-branch` | `resolved-count` |
| `policy` | `changed-count` |
| `fail-on-warn` | `violations-count` |
| | `warn-violations-count` |
| | `exit-code` |
| | `delta-json` |

`runs.using: docker` with `image: ../Dockerfile` — the Action builds from the
repository's own Dockerfile rather than a published image, so the Action and
the local CLI are provably the same code. Branding: shield icon, purple.

**`action/entrypoint.sh`** — the interesting part:

```bash
set -euo pipefail
git config --global --add safe.directory ...
```

`safe.directory` is mandatory: the Actions runner checkout is owned by a
different uid than the container user, and modern git refuses to operate on
it otherwise.

Baseline resolution:

```bash
# skip the fetch entirely if origin/<branch> already resolves
git fetch --no-tags --prune --depth=1 ...   # only if needed
git worktree add --detach /tmp/blindspot-base <sha>
```

A conditional fetch because `actions/checkout` with `fetch-depth: 0` has
already brought the ref down; re-fetching is pure latency. `git worktree
add --detach` rather than `git checkout` so the baseline scan runs against a
separate directory and the working tree is never mutated — the head scan and
the baseline scan can both be correct.

Baseline scan writes `/tmp/blindspot-baseline.json`.

Gate invocation:

```bash
set +e
blindspot-scan gate ... ; rc=$?
set -e
```

`set +e` around the gate specifically because **exit 2 is a signal, not an
error** (§52). Under `set -e` a policy violation would kill the script before
it could write outputs, and the PR would show an infrastructure failure
instead of a policy verdict.

An inline Python block then parses the delta JSON for counts and appends them
to `$GITHUB_OUTPUT`. `fail-on-warn` escalation re-raises as `exit 2`.

**Dogfooding**: `.github/workflows/self-guardrail.yml` runs the Action
against Blindspot's own `backend/app`:

- `fetch-depth: 0` so the baseline ref resolves without a fetch
- `uses: ./action` — the local Action, not a marketplace reference
- renders a summary table into `$GITHUB_STEP_SUMMARY`
- uploads the delta JSON as an artifact, 14-day retention

---

## 54. Frontend — pages, panels, components, services

### Plain English

A React single-page app. Fourteen pages, twenty-nine components plus a
six-component design system, thirteen services. It renders what the API
returns and computes nothing that matters.

### Technical

**Pages** (14, `src/pages/`): `Landing`, `Login`, `Signup`, `Dashboard`,
`Findings`, `FindingDetail`, `CBOMPage`, `RoadmapPage`, `CompliancePage`,
`ReportsPage`, `ScanPage`, `TlsScanPage`, `ProjectsPage`, `NotFound`.

**Dashboard panel order** — top to bottom, exactly as composed in
`Dashboard.tsx`. Tier A additions in bold:

1. `Header`
2. `PostureStrip`
3. `HonestyBar`
4. `CryptoSurface` + `NextActions` (side-by-side grid)
5. `TrendChart` + `BackendScanHistory` (side-by-side grid)
6. **`AgilityScoreCard`** (§49)
7. **`DependencyGraph`** (§46)
8. `DiffPanel`
9. `PolicyEditor`
10. `BenchmarkPanel`
11. **`CbomInteropDiff`** (§50)
12. **`WavePlanCard`** (§48)
13. `FindingsSection`
14. `SubsystemStrip`

Seven of those — `Header`, `PostureStrip`, `HonestyBar`, `CryptoSurface`,
`NextActions`, `FindingsSection`, `SubsystemStrip` — are **local `const`
components declared inside `Dashboard.tsx`**, not separate files. They are not
reused anywhere else, so they are not in `src/components/`. That is why the
panel count exceeds the component-file count.

The ordering is a narrative: *where do we stand* → *how honest is the data* →
*what is the surface* → *how is it trending* → *how agile are we* → *how
tangled is it* → *what changed* → *what are the rules* → *do we trust the
detector* → *do we interoperate* → *what do we do* → *the raw list*. Score
before graph before detail, because the reader who stops after one screen
should still have learned something true.

`const PROJECT_ID = 'demo'` — single-project scope. Cross-project rollup is
explicitly deferred (§64).

**Components** (29 files, `src/components/`) — including `AgilityScoreCard`,
`BenchmarkPanel`, `CbomInteropDiff`, `CBOMPreview`, `CBOMVisualizer`,
`CodeEvidence`, `DependencyGraph`, `DetectionSourceBadge`, `DiffPanel`,
`FindingPresetSensitivity`, `FindingTable`, `Icon`, `MoscaCard`, `PhaseNotice`,
`PolicyEditor`, `RecommendationCard`, `RiskBadge`, `StorageBackendChip`,
`TrendChart`, `WavePlanCard`.

**Design system** (6 components, `src/design/`, barrel-exported from
`@/design`): `RiskChip`, `MoscaVisualiser`, `Stat`, `SectionEyebrow`,
`KeyValue`, `PipelineTrace`.

Worth knowing: `RiskChip` and `MoscaVisualiser` live in `src/design/`, **not**
`src/components/`, and they are distinct from the similarly-named
`RiskBadge.tsx` and `MoscaCard.tsx` that do live in `src/components/`.
Importing from the wrong path gets you a different component with a different
prop contract.

`Icon` exposes an `IconName` union of **39 members**, each a named inline SVG.
**There is no `info` icon** — the codebase uses `shield` wherever an info glyph
would be expected. Worth knowing before adding `<Icon name="info" />` and
getting a type error.

**Services** (13): `api.ts`, `scansApi.ts`, `policyApi.ts`, `benchmarkApi.ts`,
`agilityApi.ts`, `cbomInteropApi.ts`, `graphApi.ts`, `firebase.ts`,
`mockData.ts`, `cbomModel.ts`, `cryptoTerms.ts`, `scanHistory.ts`,
`tlsTargets.ts`.

One service module per backend concern. `cryptoTerms.ts` holds the glossary
strings so terminology is defined once rather than re-worded per component.

---

# Part X — Reference tables

---

## 55. Data model

All models inherit `BlindspotModel`:

```python
class BlindspotModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True, ...)
    def serialise(self) -> dict: ...   # by_alias=True
```

Three properties that matter:

- **Emits camelCase** (`by_alias=True`) — the wire format matches JavaScript
  convention, so the frontend never renames fields.
- **Accepts either spelling** (`populate_by_name=True`) — Python code can
  construct with snake_case, JSON can arrive camelCase. Both validate.
- **`.serialise()`** is the single serialisation entry point. Calling
  `.model_dump()` directly bypasses the alias config and produces snake_case
  the frontend will not read.

**Model inventory:**

| Group | Models |
|---|---|
| Discovery | `Finding`, `NormalizedFinding`, `Evidence` |
| Analysis | `Classification`, `CurrentRisk`, `QuantumRisk`, `MoscaAssessment` |
| Advice | `Recommendation`, `CostProfile`, `LatencyProfile` |
| Scan | `Scan`, `ScanSummary` |
| Roadmap | `MigrationRoadmap`, `MigrationWave`, `RoadmapItem` |
| Compliance | `ComplianceEvaluation`, `ComplianceFinding`, `ComplianceTier`, `CompliancePreset`, `ComplianceSummary` |

---

## 56. Every enum value

| Enum | Values |
|---|---|
| `RiskTier` | `overdue`, `transitional`, `low-risk` |
| `Severity` | `critical`, `high`, `medium`, `low`, `none` |
| `QuantumThreat` | `shor_breaks`, `grover_weakens`, `none_known`, `unknown` |
| `MigrationStrategy` | `PQC`, `HYBRID`, `DEFER`, `REMEDIATE_NOW`, `INVESTIGATE` |
| `NistCategory` | `"Category 1"`, `"Category 3"`, `"Category 5"` |
| `Criticality` | `low`, `medium`, `high` |
| `ConfidenceLevel` | `high`, `medium`, `low` |
| `ParameterStatus` | `resolved`, `inferred`, `unresolved`, `not_applicable` |
| `ScanStatus` | scan lifecycle states |
| `ScanMode` | `live`, `cached` |
| `DetectionMethod` | 16 values |
| `CryptoUsage` | 16 members |
| `SecurityGoal` | `confidentiality`, `authenticity`, `integrity`, `unknown` |
| `CryptoPrimitive` | 15 members |
| `CipherMode` | 9 members |
| `ArtefactType` | includes `CLOUD_SERVICE`, `HARDWARE_MODULE`, `CERTIFICATE`, `PROTOCOL` |

**Two traps:**

1. `RiskTier.LOW_RISK` serialises to **`low-risk` with a hyphen**, not
   `low_risk`. Every dict keyed by tier string — `_TIER_RANK` (§46),
   `_TIER_WEIGHT` (§35) — uses the hyphen. A snake_case key silently misses.
2. `NistCategory` values are **strings with a space**, not integers.
   `NistCategory.CAT_3 == "Category 3"`. Comparing against `3` fails quietly.

---

## 57. Schema versions

Every machine-readable artefact carries its own version string:

| Constant / value | Artefact |
|---|---|
| `blindspot.scan.v1` | scan JSON |
| `blindspot.delta.v1` | scan diff |
| `blindspot.policy.v1` | policy document |
| `blindspot.benchmark.v1` | benchmark input |
| `blindspot.benchmark.report.v1` | benchmark report |
| `blindspot.agility.v1` | agility score (§49) |
| `blindspot.cbom.interop.v1` | CBOM diff (§50) |
| `blindspot.graph.v1` | dependency graph (§46) |
| CycloneDX **1.6** | CBOM |

Independent versioning per artefact. The graph schema can change without
forcing a scan-format migration, which means consumers pin only what they
read.

---

## 58. Configuration

All settings are Pydantic `Settings` fields, environment-variable driven,
cached via `get_settings()` (with `.cache_clear()` available for tests).

| Variable | Default | Notes |
|---|---|---|
| `BLINDSPOT_ENV` | — | environment label |
| `BLINDSPOT_CORS_ORIGINS` | — | comma-separated allow-list |
| `QUANTUM_HORIZON_YEARS` | `10.0` | Mosca **Z**; `gt=0` |
| `MIGRATION_TIME_YEARS` | `3.0` | Mosca **Y**; `gt=0` |
| `HIGH_ASSURANCE_MODE` | `false` | forces NIST Category 5 (§32) |
| `STORAGE_BACKEND` | `auto` | `auto` \| `firebase` \| `local` |
| `FIREBASE_PROJECT_ID` | — | |
| `FIREBASE_CREDENTIALS_PATH` | — | |
| `FIREBASE_STORAGE_BUCKET` | — | |
| `AUTH_DISABLED` | `false` | |
| `SEMGREP_PATH` | — | explicit binary path |
| `SEMGREP_TIMEOUT_SECONDS` | — | **0 = no timeout** |
| `ARTIFACTS_DIR` | `backend/artifacts` | always written |
| `FALLBACK_CACHE_PATH` | — | local-store location |
| `DEMO_REPO_PATH` | — | |
| `SCAN_WORK_DIR` | — | |
| `TLS_SCAN_ENABLED` | — | |
| `TLS_SCAN_TIMEOUT_SECONDS` | — | |
| `PKCS11_SCAN_ENABLED` | — | + `PKCS11_MODULE_PATH` |
| `AWS_KMS_SCAN_ENABLED` | — | |
| `AZURE_KV_SCAN_ENABLED` | — | + `AZURE_KV_VAULT_URL` |
| `GCP_KMS_SCAN_ENABLED` | — | + `GCP_KMS_PROJECT` |

Notes worth internalising:

- **`effective_storage_backend`** is a computed property, not a raw field.
  `auto` resolves to Firebase when credentials are present and local
  otherwise. Code reads the computed value; the health endpoint reads the raw
  one to tell *chosen* local from *fallen-back* local (§51).
- **`SEMGREP_TIMEOUT_SECONDS=0` means no timeout at all**, not "time out
  instantly". Set on large monorepos where a bounded semgrep run would return
  a partial scan (§62).
- **`ARTIFACTS_DIR` is always written**, regardless of storage backend. Even
  in Firebase mode there is a local copy of what the scan produced.
- **Air-gap configuration** is `STORAGE_BACKEND=local` **plus**
  `AUTH_DISABLED=true`. No outbound network calls, no auth provider.

**Z presets** — `z_presets` computed property, seven entries with
`current_year = 2026` hardcoded:

1. Demo default (10.0 years)
2. India CII Category A — 2027
3. India CII Category B — 2028
4. India CII Category C — 2029
5. NIST IR 8547 — 2030 deprecation
6. NIST IR 8547 — 2035 disallow
7. CRQC mid-range — 15.0 years

---

## 59. Testing

**802 backend tests. 160 frontend tests.** Both suites green.

**`backend/tests/conftest.py`** carries an **autouse** `isolated_env`
fixture. Every test, whether it asks for it or not, runs against a pinned
environment:

Pinned values:

- `HIGH_ASSURANCE_MODE=false`
- `STORAGE_BACKEND=auto`
- Firebase variables emptied
- `AUTH_DISABLED=false`

Redirected to `tmp_path`:

- `ARTIFACTS_DIR`
- `FALLBACK_CACHE_PATH`
- `DEMO_REPO_PATH`
- `SCAN_WORK_DIR`

Reset calls:

```python
get_settings.cache_clear()
reset_firebase()
reset_firestore()
reset_storage()
_reset_default_store_for_tests()
```

All five run **both before and after** the `yield`. Before, because the
previous test may have dirtied module-level caches; after, because this test
certainly did. Cleaning only on teardown leaves the first test in a session
exposed to whatever import-time state already existed.

The `tmp_path` redirection is why the suite never touches the developer's
real `backend/artifacts` directory or fallback cache.

**Fixtures:**

| Fixture | Behaviour |
|---|---|
| `app` | FastAPI app instance |
| `client` | TestClient with **auth enforced** |
| `auth_bypassed_client` | TestClient with `AUTH_DISABLED=true` |

Auth-on is the default client. Tests that need to skip auth must say so
explicitly, so no endpoint accidentally loses its auth check without a test
noticing.

**Commands:**

```powershell
# backend
cd backend
.venv\Scripts\python.exe -m pytest -q --no-header --ignore=tests/test_multilang_scanner.py

# frontend
cd frontend
npx vitest run
npx tsc -b --pretty false
```

`--ignore=tests/test_multilang_scanner.py` is used in full sweeps.

---

## 60. Deployment

Four supported topologies:

**Local development** — `uvicorn` for the API, `vite` for the frontend. Two
terminals, no containers.

**Docker** — the repository-root `Dockerfile` (§53). The same image backs the
GitHub Action, which means the container is exercised on every push rather
than only at release.

**Firebase Hosting + Cloud Run** — static frontend on Hosting, API container
on Cloud Run, Firestore + Storage for persistence. `STORAGE_BACKEND=firebase`.

**Air-gapped** — `STORAGE_BACKEND=local` plus `AUTH_DISABLED=true` (§58). No
outbound calls. Everything that needs the network — TLS probing, cloud KMS
scanners — is individually feature-flagged off by default and stays off.

---

# Part XI — Engineering discipline

---

## 61. Honesty guardrails

These are not aspirations. Each one is enforced by structure, and each one is
the reason some obvious-looking feature is absent.

**1. Traceability.** Every finding carries evidence: file, line, and the
matched source text. No finding exists without a place you can go and look.
This is why inferred findings are labelled `inferred` (§24) rather than
promoted to `resolved`.

**2. Provenance is never faked.** Every number that came from outside the
codebase carries its citation: FIPS 203/204 for PQC targets, NIST SP
800-131A Rev.2 for deprecations, CRYSTALS Round 3 and Cloudflare's October
2021 measurements for latency (§34). Where a number is a demo assumption, the
string says so —
`"Demo assumption (configurable via QUANTUM_HORIZON_YEARS)"`. A citation is
either real or absent.

**3. Hash-not-fuzz matching.** Identity is always an exact hash of normalised
fields — finding dedup (§23), graph node ids (§46), CBOM diff keys (§50).
Never a similarity score, never a tunable threshold. Two things match or they
do not. A fuzzy matcher would produce a number nobody can audit.

**4. Policy carries both field and value.** A policy violation reports the
field name *and* the offending value, so the message is actionable without
reading the policy file. Names without values force a lookup; values without
names are unattributable.

**5. The pipeline is one-directional.** Discovery → normalisation → analysis
→ output. No stage reads a later stage's output. This is why the report
recomputes nothing (§38) and why Tier A features are projections (Part VIII).
A cycle would make "which number is right" unanswerable.

---

## 62. Failure-mode catalogue

Every failure mode below is a deliberate decision about what to do when
something breaks. The pattern throughout: **degrade visibly, never silently,
and never fabricate a substitute value.**

| Failure | Behaviour |
|---|---|
| semgrep fails or times out | scan continues, marked **partial** |
| per-finding enrichment raises | that finding is skipped, warning recorded |
| CBOM component build raises | that component is skipped, warning recorded |
| CBOM fails schema validation | **warning only** — the CBOM is still emitted |
| roadmap build fails during report | section renders `None`, marked **degraded** |
| compliance build fails during report | section renders `None`, marked **degraded** |
| PDF requested, no headless browser | **503** |
| benchmark already running | **409 Conflict** (non-blocking lock, §45) |
| policy file corrupt | **500** |
| baseline file missing (diff/gate) | treated as an **empty baseline** |
| baseline file unreadable | **exit 1** |
| TLS target is a private IP | **refused** — SSRF guard |
| TLS target unreachable | skipped, scan continues |
| cloud SDK not installed | scanner returns `[]`, logs the reason |

Two rows deserve a note:

**"CBOM invalid → warning only."** An invalid CBOM is still more useful than
no CBOM, and the operator needs to see the thing that failed validation in
order to fix it. Refusing to emit it would hide the evidence.

**"missing baseline → empty baseline"** versus **"unreadable baseline → exit
1"**. A missing baseline is a legitimate first run: everything is introduced,
which is true. An unreadable baseline means a file exists and cannot be
parsed, which is a real error — treating it as empty would silently pass a
gate that should have blocked.

---

## 63. Known quirks, dead code, and documented-but-unwired behaviour

This section exists because the request was for *everything*, and because a
reference that documents only the working parts is a sales document. Every
item below is grep-verified against the tree at the version stated in the
footer. Several are harmless. A few would waste your afternoon.

### Dead code

**`_KEX_PQC_TARGETS` and `_SIG_PQC_TARGETS`** in
`backend/app/recommend/recommender.py` have **no callers**. Grep-verified:
they appear only at their own definition sites. They are legacy
algorithm-name-keyed target tables, superseded by the category-driven
`_TARGETS` in `security_level.py` (§32). Do not read them as live behaviour —
editing them changes nothing.

**`CDX_1_6_SCHEMA_URL`** is declared in `backend/app/cbom/validator.py` and
never used. Validation loads the bundled schema; the URL constant is
vestigial.

### Documented-but-never-emitted values

**`lifetime_source`** only ever emits `"policy_default"`. The values
`usage_inferred` and `declared` are documented in the model but never
assigned by any code path (§27).

**`CurrentRisk.references`** is declared but never populated by
`assess_current_risk` (§28).

**`QuantumThreat.UNKNOWN`** is never returned. Every algorithm resolves to
`shor_breaks`, `grover_weakens`, or `none_known` (§29).

### Docstrings that describe things that do not exist

The classifier docstring mentions **"firmware signing"**, but no such
`CryptoUsage` member exists. The nearest real member is `CODE_SIGNING`.

The `LatencyProfile` docstring mentions **`approx_microseconds`**, but that
field is not declared on the model (§34).

### Shared mutable state

**`_PROFILES` in `latency.py` returns shared singleton `LatencyProfile`
objects.** Two findings on ML-KEM-768 receive the *same instance*. Nothing
mutates them today, so nothing is broken — but a future mutation would leak
across every finding that shares the profile. Copy before mutating.

### CBOM builder gaps

**`build_cbom` / `build_cbom_json` accept `project_name` and never use it.**
`Bom()` is constructed with no arguments and no `metadata.component` is set.
The parameter is accepted and discarded.

**The CBOM injects only `metadata.timestamp`.** No tool metadata — which is
why the executive report's CBOM section renders the producing tool as **"Not
declared"** (§39). And no `blindspot:riskTier` property — which is why the
interop diff's `tier_changed` class cannot fire when both sides are Blindspot
CBOMs (§50).

**Crypto-function extraction, stage A, uses substring-match-then-`break`**, so
at most **one** crypto function is emitted per component. Because `sign`
precedes `verify` in the lookup dict's insertion order, an algorithm that does
both is recorded as `sign`.

### Validator limitations

**The validator calls `validate`, not `iter_errors`.** `validate` raises on
the first schema violation, so only the **first** error is ever reported. A
CBOM with five problems reports one, you fix it, and the next one appears.

**The validator has no warning channel.** Every issue is an error. There is
no way to flag something as a soft concern.

### API oddities

**`GET /api/export/cbom` accepts a `scanId` query parameter and never uses
it.** The endpoint serves the CBOM from the active scan regardless.

**The same endpoint loses its formatting.** The builder produces
`indent=2`-formatted JSON, then FastAPI re-serialises the parsed object and
the indentation is gone.

### Import / export inconsistencies

**`app/report/__init__.py`'s `__all__` omits `cbom_from_json_string`.** The
function is exported from `executive.py` and imported directly by
`api/report.py` via `from app.report.executive import cbom_from_json_string`,
bypassing the package `__all__`. Verified in both files.

**`app/cbom/__init__.py` is docstring-only** — no re-exports at all. Import
from the submodules directly.

### Presentation quirks

**The report's degraded `posture` branch loses its `id="posture"` anchor.**
When the posture section renders in degraded form, in-page links to
`#posture` stop resolving.

**`@bottom-left` / `@bottom-right` paged-media boxes are unverified in
Chrome's PDF output.** The CSS declares them; whether Chrome honours both in
the headless print path has not been confirmed (§40).

### Deliberate omissions that look like bugs

**SHA-256 findings are dropped at the extractor.** Deliberate — SHA-256 is
Grover-weakened, not Shor-broken, and surfacing every SHA-256 call would bury
the actionable findings. One line to change if you disagree (§22).

**Maven dependency `line_number` is always 1.** The Maven parser does not
track line positions; rather than emit a wrong line it emits a constant one.

### The two-metric traps

**Roadmap `blast_radius` ≠ graph `blastRadius`.** The roadmap counts findings
per file; the graph counts distinct algorithms per file. Both correct, both
useful, different numbers for the same file. Fully explained in §46.

**Roadmap `_COST_BAND` and `CostProfile.relative_cost` use different
vocabularies.** `_COST_BAND` maps `HYBRID` to `"medium"`; `CostProfile`
speaks `low` / `moderate` / `high`. Two scales, so `"medium"` and
`"moderate"` are not the same token even though they mean roughly the same
thing. Do not write `cost_band == relative_cost`.

---

## 64. Roadmap and deliberate non-goals

### Deferred — wanted, not built

- **SARIF v2.1.0 output** — would put findings in GitHub's native code
  scanning UI.
- **Idempotent PR comments** — post the delta as a comment that updates in
  place rather than appending on every push.
- **GitLab and Bitbucket wrappers** — the CLI already supports it; only the
  CI wrapper is missing.
- **Full cross-file import graph** — would let the dependency graph draw
  file→file edges (§46) instead of only file→algorithm.
- **Cross-project rollup** — the frontend is hardcoded to
  `PROJECT_ID = 'demo'` (§54).
- **Multi-tenant policy store** — one active policy today.
- **External corpora wiring** — CryptoAPI-Bench and MASC are documented as
  **manifest pointers, not bundled data** (§44). The benchmark runs against
  the labelled corpus that ships with the repository.

### Non-goals — deliberately out of scope

- **Runtime crypto monitoring.** Blindspot is static. Instrumenting a running
  process is a different product with a different failure model.
- **Automated refactoring.** The platform recommends; it does not rewrite
  your crypto. Auto-migrating a key exchange is how you take down production.
- **CVE feed integration.** Blindspot reasons about *algorithm* weakness, not
  *implementation* vulnerabilities. Those are different problems and mixing
  them makes both harder to reason about.

---

## 65. Demo Q&A

The five questions that actually get asked, and the honest answers.

**"Do you read our cloud keys?"**
No. The cloud KMS scanners are **metadata-only**. They list key metadata —
algorithm, spec, state — through the provider SDK. No key material is ever
requested, retrieved, or stored. All three cloud scanners are disabled by
default and require explicit environment flags to turn on (§58).

**"What happens if semgrep breaks?"**
The scan continues and is marked **partial** (§62). Other scanners still run,
findings still enrich, and the report says the scan was partial. It does not
claim a clean bill of health from an incomplete scan.

**"How do you know an RSA key is 2048 bits?"**
Often it does not, and it says so. `ParameterStatus` distinguishes
`resolved` (read from source) from `inferred` (derived from context) from
`unresolved` (unknown). An unresolved parameter routes the finding to
`INVESTIGATE` rather than guessing, and unresolved parameters default to NIST
**Category 3**, never Category 1 (§32). Guessing low would be the dangerous
direction.

**"Your F1 is 0.89 — what did you miss?"**
Precision 1.00, recall 0.80, F1 0.889 on the labelled corpus. Two misses,
both named in the benchmark output (§43). Zero false positives. The two
misses are real gaps, and the report names them rather than reporting a
rounded-up aggregate.

**"How is this different from IBM's CBOMkit?"**
The interop diff (§50) answers that concretely rather than rhetorically. Drop
a CBOMkit CBOM and a Blindspot CBOM into the same panel and read the
differences. Blindspot's distinguishing layer is the Mosca risk engine
(§30) — a time-based verdict with the inequality shown and the horizon
configurable — plus baseline-aware CI gating (§53). The CBOM is the
interoperable artefact; the risk reasoning is the product.

---

*Document version: 1.0 — generated against the tree at 802 passing backend
tests and 160 passing frontend tests, `npx tsc -b` clean.*

*Every claim in this document was verified by reading the source. Where a
feature is incomplete, dead, or inconsistent, §63 says so explicitly rather
than omitting it. Anywhere this document diverges from `git ls-files`, treat
the code as the truth.*
