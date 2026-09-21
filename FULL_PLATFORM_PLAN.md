# Blindspot ECDAT — Full-Platform Plan

**SIH 2026 · PS 26164 · Post-demo build plan.** This is the single reference for
*what remains to build*, merging the two backlogs into one prioritised roadmap:

* **PS-remaining** — items where PS 26164 asks for something we only partially
  deliver (from the honest re-audit in this thread).
* **Differentiator-remaining** — items from `STRATEGY.md` that made it into the
  positioning but not yet into the code.

Every item is scored on **PS coverage lift**, **differentiator lift**, and
**effort**. The sprint plan at the end sequences them so we always close the
biggest gap for the least work first.

> **Non-negotiable:** everything is additive on the existing pipeline. Nothing
> in the "already shipped" list gets rebuilt. Every new number is grounded in
> a real observation, a cited standard, or a labelled proxy — no fabricated
> latencies, no invented capabilities.

---

## 1. Where we are today (do not rebuild)

Verified against code and tests as of the demo commit.

### 1.1 PS 26164 coverage — line-by-line
| PS clause | Status |
|---|---|
| (i) algorithms | ✅ Done |
| (i) keys — generation calls | ✅ Done |
| (i) keys — hardcoded key files / material | ⚠️ Not built |
| (i) certificates — live TLS peer | ✅ Done |
| (i) certificates — static cert files / trust stores | ⚠️ Not built |
| (i) protocols — live TLS negotiation | ✅ Done |
| (i) protocols — config-file crypto policy (nginx / sshd / openssl.cnf / java.security) | ⚠️ Not built |
| (i) libraries — pip manifests + binary brand strings | ✅ Done |
| (i) libraries — other ecosystems (Maven / npm / go.mod / Gemfile / Cargo / NuGet) | ⚠️ Not built |
| (i) hardware modules | ⚠️ Declared, not attested |
| (i) cloud services | ⚠️ Declared, not attested |
| (i) across apps / products / infrastructure — aggregation | ⚠️ Single-scan only |
| (ii) quantum risk assessment | ✅ Done |
| (ii) risks to sensitive data (HNDL) | ✅ Done |
| (iii) classification by type / lifetime / criticality + Mosca | ✅ Done |
| (iv) recommend by risk profile | ✅ Done |
| (iv) recommend by cost | ✅ Done (published byte sizes) |
| (iv) recommend by **latency** | ❌ Not done (deliberate honesty tradeoff) |
| Deliverable: scan source / libraries / binaries / containers | ✅ Done |
| Deliverable: standardised report (CycloneDX 1.6) | ✅ Done |
| Deliverable: **executive report** beyond raw CBOM | ⚠️ Not built |
| Deliverable: interactive GUI | ✅ Done |

### 1.2 Differentiator inventory — from `STRATEGY.md`
| # | Differentiator | Status |
|---|---|---|
| ★ 1 | Migration Roadmap (hero, 5 waves, priorityScore) | ✅ Shipped |
| 2 | Crypto Dependency Graph + Blast Radius | ⚠️ Proxy only (co-located file count) |
| 3 | India + NIST Compliance Sensitivity | ✅ Shipped (7 Z presets, live-verified 0→5→8) |
| 4 | Continuous Posture / CI-CD Guardrail | ❌ Not shipped |
| 5 | Latency & Cost-Aware Recommendations | ⚠️ Cost yes, latency no |
| 6 | Honesty / Confidence surfacing | ✅ Shipped |
| 7 | HNDL Exposure Flag | ✅ Shipped |
| 8 | Cross-tool CBOM Diff | ❌ Not shipped |
| 9 | Crypto-Agility Scoring | ❌ Not shipped |

**Bottom line:** feature coverage is strong. What remains is a mix of *filling
PS partials* and *finishing the last four differentiators* — several items
serve both goals simultaneously.

---

## 2. The merged remaining backlog

Every item below has a canonical ID (e.g. **R1**, **D2**). Sprints in §3
reference these IDs directly, so there is one source of truth.

### 2.1 PS-remaining items

**R1 · Static cert & key file discovery**
Grep the scanned target for `.pem`, `.crt`, `.cer`, `.der`, `.p12`, `.pfx`,
`.key`, and inline `-----BEGIN (CERTIFICATE|PRIVATE KEY|RSA PRIVATE KEY|EC
PRIVATE KEY)-----` markers. Parse each certificate with
`cryptography.x509`; extract issuer, subject, `not_valid_after`, key
algorithm, key size, curve, signature algorithm. Emit as normalised findings
with detection method `static_cert_file` / `static_key_material`.
*Closes: PS (i) certificates, PS (i) keys.*
*Effort: 1.5–2 days.*

**R2 · Config-file crypto policy scanning**
Extend `app/scanner/infra.py` (or new `app/scanner/config_policy.py`) with
patterns for `nginx.conf` (`ssl_protocols`, `ssl_ciphers`), `apache/httpd`
SSL directives, `sshd_config` (`Ciphers`, `KexAlgorithms`, `MACs`,
`HostKeyAlgorithms`), `openssl.cnf`, `java.security`
(`jdk.tls.disabledAlgorithms`, `jdk.certpath.disabledAlgorithms`), .NET
`web.config` crypto sections, PostgreSQL `postgresql.conf` SSL settings.
Detection method `config_policy_declared`; classify as protocol findings.
*Closes: PS (i) protocols (beyond live TLS).*
*Effort: 2–3 days.*

**R3 · Multi-language source rules**
Extend the Semgrep rule packs beyond Python + C:
* **R3a · Java** — JCA (`KeyPairGenerator`, `Cipher`, `MessageDigest`, `SSLContext`), Bouncy Castle.
* **R3b · JavaScript / TypeScript** — Node `crypto` module, `subtle.crypto`, `node-forge`, `crypto-js`.
* **R3c · Go** — `crypto/rsa`, `crypto/ecdsa`, `crypto/tls`, `crypto/x509`.
* **R3d · optional** — .NET (`System.Security.Cryptography`), Ruby (`OpenSSL`), Rust (`ring`, `rustls`).

Each is one rules pack; the pipeline is unchanged. Confidence stays at the
existing AST-confirmed band. *Closes: PS (i) algorithms across polyglot
enterprise codebases.*
*Effort: 1 day/language for a first cut.*

**R4 · Multi-ecosystem dependency parsers**
Extend `app/scanner/dependency_parser.py`:
* **R4a · Maven** — `pom.xml` + `dependency-tree` output.
* **R4b · npm / yarn** — `package.json` + `package-lock.json`.
* **R4c · Go modules** — `go.mod` + `go.sum`.
* **R4d · optional** — `Gemfile.lock`, `composer.lock`, `Cargo.lock`, `packages.config` / `.csproj`.

For each ecosystem, maintain a small crypto-provider allowlist (`bcprov-*`,
`node-forge`, `crypto-js`, `golang.org/x/crypto`, ...). Same finding shape.
*Closes: PS (i) libraries across polyglot enterprise codebases.*
*Effort: ½ day/ecosystem for a first cut.*

**R5 · Latency modelling (honest version)**
The PS names *latency* explicitly. We add it without fabricating measurements:
attach cited reference benchmarks per PQC algorithm — TLS handshake byte
overhead (Cloudflare PQ reports), key-encapsulation `keygen` / `encap` /
`decap` cycles from FIPS 203 §5 performance notes, signature `sign` / `verify`
cycles from FIPS 204, and IETF/CFRG measurement papers where applicable.

Every value carries a `source` string (like `zSource`) and a
`platformNote` field ("measured on Skylake @ 3.6 GHz, single-threaded; scale
by your CPU"). Render in the recommendation card next to `CostProfile` as
"Reference latency (source: X)". Never present as *your* system's latency.

*Closes: PS (iv) latency + Differentiator #5.*
*Effort: 2 days — mostly data curation + one UI panel.*

**R6 · Comprehensive standardised report — executive PDF**
Beyond raw CBOM JSON, produce a branded executive report (PDF + HTML) with:
* posture summary (artefact counts, tier distribution, HNDL count, weak-now count)
* wave-by-wave migration plan from the roadmap
* compliance-mapping section under active Z-preset
* full CBOM as an appendix

Reuses the Chrome-headless generation pipeline built for `PRESENTATION_SCRIPT.pdf`.
New endpoint: `GET /api/report?format=pdf&scanId=…`. *Closes: Deliverable
"report displaying all cryptographic assets in standardised format" in its
maximal reading.*
*Effort: 2–3 days.*

**R7 · Live HSM / PKCS#11 attestation**
Upgrade the *declared, not attested* HSM finding class with real PKCS#11
sessions. Start with **SoftHSM** (free, containerisable, perfect for demo and
CI). Open a session, enumerate objects, read `CKA_KEY_TYPE`, `CKA_MODULUS`,
`CKA_EC_PARAMS`, `CKA_LABEL`, emit as findings with detection method
`pkcs11_attested` (high confidence). Same code pattern extends to YubiHSM /
Luna / nShield later. *Closes: PS (i) hardware modules — attested branch.*
*Effort: 3–5 days for SoftHSM (getting a repeatable local session is the hard
part; the scanner code is small).*

**R8 · Live cloud KMS attestation**
Same story for cloud KMS. Start with **AWS KMS** (free tier + `moto`
for tests). `boto3.client('kms').list_keys()` → per key
`describe_key()` for `KeySpec`, `KeyUsage`, `KeyManager`, `SigningAlgorithms`.
Findings tagged `aws_kms_attested`, high confidence. GCP + Azure follow the
same shape. *Closes: PS (i) cloud services — attested branch.*
*Effort: 2–3 days for AWS; +1–2 days each for GCP / Azure.*

### 2.2 Differentiator-remaining items

**D1 · CI/CD Guardrail** *(highest platform-story lift for lowest effort)*
A GitHub Action + webhook that re-scans on every push. Fails the build (or
posts a required PR review) if new **quantum-vulnerable** or **weak-now**
findings appear versus the base branch. Implemented as two pieces:
* A stateless CLI `blindspot-scan` that runs the pipeline locally in-process
  and emits a compact JSON delta (findings introduced, findings resolved).
* A GitHub Action packaged around the CLI (`action.yml` + Docker image).

Blocks the merge when the delta contains findings meeting a configurable
policy (default: any new `overdue` or any new `is_currently_weak`).
*This is the item that turns "tool" into "platform" in a judge's mind.*
*Effort: 3–4 days (packaging + policy engine is the work, scan code exists).*

**D2 · Cross-tool CBOM diff**
Compare two CBOMs — most obviously **this scan vs. the previous scan**, but
also "Blindspot CBOM vs. IBM CBOMkit CBOM" as a proof of interoperability.
Diff engine emits added / removed / algorithm-changed / parameter-changed /
tier-changed. New endpoint `POST /api/cbom/diff` accepting two CycloneDX docs.
Rendered as a GUI page with the two runs side-by-side.
*Nobody else does this. Genuinely unique.*
*Effort: 3–4 days.*

**D3 · Crypto-agility score**
One number per repo (0–100) summarising migration readiness. Composite:
* Share of findings in the `low-risk` tier (higher is better)
* Absence of `is_currently_weak` findings
* Absence of `hndl_exposed` findings
* Fraction of findings with `parameter_status == resolved`
* Recommendation-strategy distribution (fewer `INVESTIGATE`, fewer `REMEDIATE_NOW`)

Every input is data we already compute; the score is a deterministic function
of the fields. Publishable as a badge (`agility-score.svg`) suitable for
project READMEs — a viral surface.
*Effort: 1–2 days.*

**D4 · Real dependency graph** *(upgrade blast-radius proxy)*
Turn the current *co-located-file-count* proxy into a static
import/call graph. Python: `ast.walk` for `import` and function-call chains.
Java: `com.tngtech.archunit` or a Maven-dependency-tree parse. JS: `dependency-tree`
package. Emit a `blast_radius_graph` field per finding: nodes = files/modules,
edges = imports/calls. Roadmap's `blastRadius` becomes the actual reachable set
size, not just co-located.

Rendered as an interactive graph on the finding detail page. This was the
"the visual" bullet in STRATEGY.md — visually the most differentiating single
GUI element in the whole product.
*Effort: 5–7 days minimum for one language, +2/language after.*

**D5 · Enterprise aggregation view**
Multi-project posture dashboard: quantum debt across your whole estate,
project ranking by HNDL exposure count, and trend curves over time. Requires
the async-worker + Firestore-primary work (below) to be meaningful.
*Effort: 2–3 days on top of the production-spine work.*

### 2.3 Production spine (Phase 0 leftovers from `PROJECT_MASTER.md`)

Do only if the goal is a real multi-tenant hosted product.

**P1 · Firestore as source of truth.** GET endpoints read from Firestore,
keyed by `scanId` and scoped by owner. Keep the in-memory fast-path behind a
`DEV_MODE` flag so local dev / tests are unchanged. *Effort: 3–4 days.*

**P2 · Async job queue + worker service.** `POST /api/scan` returns a job
ID; a Railway worker consumes jobs from a Firestore queue and calls
`run_pipeline()` unchanged. `GET /api/scan/{id}/status` for polling.
*Effort: 3–4 days.*

**P3 · RBAC + real multi-tenant auth.** Org boundaries, role-based access,
audit log. *Effort: 4–5 days.*

**P4 · Rate limits + per-user quotas + structured logging + metrics.**
`slowapi` for FastAPI rate limits; OpenTelemetry for traces; JSON logs.
*Effort: 2–3 days.*

---

## 3. Sprint plan — merged, ranked by lift-per-day

Each sprint is scoped so a small team can ship it in about a week of focused
work (or a solo dev in ~2 weeks). Every sprint ends with the standard
verification: full backend suite green, frontend tsc + build + tests green,
one end-to-end live check.

### Sprint 1 · Platform-story wins *(1 week)*
The three cheapest items with the biggest narrative shift.

* **D1 · CI/CD Guardrail** — turns tool into platform.
* **D3 · Crypto-agility score** — one number, viral README badge.
* **R5 · Latency modelling (honest)** — closes the last PS (iv) checkbox.

**Lift after Sprint 1:** PS coverage moves from ⚠️ latency to ✅ latency
(honestly labelled). Differentiator count: 4 shipped → 6 shipped
(D1, D3 added). Platform positioning becomes defensible.

### Sprint 2 · PS breadth *(1 week)*
Close the "everything a real enterprise has" partials.

* **R1 · Static cert & key file discovery.**
* **R2 · Config-file crypto policy scanning.**
* **R6 · Executive PDF report.**

**Lift after Sprint 2:** PS (i) certificates and protocols move from ⚠️ to
✅ full coverage. Report deliverable reads "executive PDF" not just "raw JSON."

### Sprint 3 · Polyglot enterprise fit *(1–2 weeks)*
The one thing an enterprise buyer asks first: *does it scan our language?*

* **R3a · Java rules + R3b · JS/TS rules + R3c · Go rules.**
* **R4a · Maven parser + R4b · npm parser + R4c · Go modules parser.**

**Lift after Sprint 3:** the product covers 5–6 language families at the
source and dependency level. Every subsequent language / ecosystem is an
incremental rulepack, not a rewrite.

### Sprint 4 · The visual differentiator *(1–2 weeks)*
The one users screenshot.

* **D4 · Real dependency graph** — for Python + Java initially, then
  incremental. Upgrade the roadmap's `blastRadius` field to reference the
  graph.
* **D2 · Cross-tool CBOM diff** — endpoint + GUI page.

**Lift after Sprint 4:** the hero (roadmap) now uses a *real* blast radius,
not a proxy. Cross-tool diff is a genuinely unique feature nobody in this
space ships today.

### Sprint 5 · Attested HSM / KMS *(1–2 weeks)*
The credibility jump.

* **R7 · SoftHSM attestation** — a real PKCS#11 session, live-demoable.
* **R8 · AWS KMS attestation** — real `boto3` list_keys / describe_key.

**Lift after Sprint 5:** hardware modules and cloud services move from
⚠️ *declared* to a coexisting ✅ *attested* branch. The tool can honestly say
"we do both — discovery from declarations, attestation from real sessions."

### Sprint 6 · Production spine *(2 weeks, optional)*
Only if the target is a hosted commercial product, not an open-source
reference tool.

* **P1 · Firestore-primary store.**
* **P2 · Async job queue + worker.**
* **P3 · RBAC.**
* **P4 · Rate limits + observability.**
* **D5 · Enterprise aggregation view** (falls out of P1 + P2).

**Lift after Sprint 6:** the product becomes multi-tenant hostable. Multi-
project dashboards work. Rate-limited public API is safe to expose.

### Sprint 7 · Language & ecosystem breadth *(rolling, as needed)*
* **R3d · .NET / Ruby / Rust.**
* **R4d · Gemfile / composer / Cargo / NuGet.**
* **R7 (extra) · YubiHSM / Luna / nShield attestation.**
* **R8 (extra) · GCP KMS + Azure Key Vault attestation.**

Incremental, driven by customer demand or evaluator scope.

---

## 4. Coverage trajectory

| After sprint | PS full coverage | Differentiators shipped | Trajectory |
|---|---|---|---|
| Today | ~85 % (partials on cert/key/protocol/library breadth + latency + report) | 4 of 9 full + 2 partial | Strong prototype |
| S1 | + latency full | 6 of 9 (adds D1, D3) | Platform story defensible |
| S2 | + certs/protocols/report full | 6 of 9 | ~95 % PS full coverage |
| S3 | + polyglot breadth | 6 of 9 | Enterprise-scoped |
| S4 | (no PS change) | 8 of 9 (adds D4, D2) | Visually unrivaled |
| S5 | + attested HSM/KMS branch | 8 of 9 | ~100 % PS with defensible attestation |
| S6 | (no PS change) | 9 of 9 (adds D5) | Multi-tenant hostable |

---

## 5. Honesty guardrails (carried forward, non-negotiable)

Every remaining item ships under the same rules the existing code already
enforces:

1. **No fabricated numbers.** Any latency, cost, or benchmark carries a
   `source` field with a citation. Every Mosca result carries `zSource`.
   Any inferred value is labelled as *policy default* or *proxy* or
   *reference benchmark* — never presented as measurement.
2. **Provenance labels on every finding.** New detection methods get their
   own enum value (`static_cert_file`, `config_policy_declared`,
   `pkcs11_attested`, `aws_kms_attested`, ...). The UI badge distinguishes
   attested from declared.
3. **Confidence bands preserved.** Attested findings are high confidence;
   declared findings stay medium; fingerprint / static-guessed findings stay
   low. `needs_verification` continues to route the uncertain surface.
4. **Additive only.** No stage in the existing pipeline gets rewritten. New
   scanners feed `normalize()`; new fields are added, existing fields never
   changed.
5. **Tests green throughout.** Backend suite (283 today) grows only. No
   regression is acceptable between sprints.

## 6. Explicit non-goals

Called out so nothing here quietly expands.

* **Firmware image scanning.** PS names container images, not firmware.
  Scoped out.
* **Air-gap installation.** Architecture is swappable-persistence /
  swappable-auth; that is enough. No installer or offline distro work.
* **Chatbot / natural-language interface.** Reads as unserious on a
  security PS.
* **Custom crypto-algorithm scoring** beyond what NIST publishes. We consume
  standards, we don't invent them.
* **Threat-intel / CVE integration.** Adjacent, out of scope.
* **Full binary disassembly / control-flow crypto recovery.** Fingerprinting
  (existing) stays the ceiling of binary work — anything more is a research
  project.

## 7. Sequencing decision — one paragraph

The single biggest platform-narrative jump per unit effort is **Sprint 1 · D1
(CI/CD Guardrail)**. It's small code, but a judge or a buyer instantly reads
"they made this into a platform, not a scanner." Do that first. Everything
after can be re-sequenced by whichever backlog item best matches the audience
you're presenting to next: PS-strict evaluator → Sprint 2 + 3; visual demo
audience → Sprint 4; enterprise procurement conversation → Sprint 5 + 6.

---

## 8. What this document is not

* Not a specification. Each item still needs a per-sprint design doc before
  code (contract, data model, test list, honesty label).
* Not a schedule. Effort estimates are for planning, not commitments.
* Not the presentation deck — this is internal engineering planning.
