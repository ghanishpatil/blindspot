# Blindspot ECDAT — Project Master Document

**Enterprise Cryptographic Discovery & Analysis Tool · SIH 2026 · PS26164 · Team Blindspot**

This is the single onboarding + reference document. It covers (1) the working demo, (2) the
complete project vision, (3) the PPT review, and (4) an as-built-vs-target architecture
comparison with the concrete reconciliation changes.

Related docs: `ECDAT_REQUIREMENTS.md` (full formal spec + differentiators + UI), `PPT_ALIGNMENT.md`
(slide-by-slide deck edits), `DEMO_REQUIREMENTS.md` + `BLINDSPOT_ECDAT_DEMO_KIRO_BUILD_SPEC.md`
(original demo scope).

---

## 1. What ECDAT is (in one paragraph)

ECDAT discovers cryptographic assets across code and infrastructure, records evidence for every
finding, produces a standardized CycloneDX CBOM, assesses quantum-migration urgency with a
configurable Mosca-inequality risk engine, and produces cost/latency-aware PQC/hybrid
recommendations. Its differentiator: it does not stop at a list — it produces a **prioritized,
costed Migration Roadmap** and **continuously guards** against new quantum-risk.

**Positioning:** *"Others hand you a list of your cryptography. ECDAT hands you a costed,
prioritized, compliance-mapped migration plan — and stops new quantum-risk from entering your
code. Discovery is where they stop; it's where we start."*

---

## 2. DEMO INFORMATION (what works today)

### 2.1 Current state — verified
The core end-to-end pipeline is real and working (not a mockup):

- **Discovery:** Semgrep custom rules over source (Python + C/OpenSSL rules) + dependency
  manifest parsing.
- **Evidence:** snippet + file/line + AST parameter resolution + module-boundary confidence policy.
- **CBOM:** CycloneDX 1.6 generation + schema validation.
- **Classification:** artefact type, data lifetime (X), criticality, confidentiality-vs-authenticity
  split, trust-anchor escalation.
- **Risk:** configurable-Z Mosca engine (X + Y > Z) with 7 named Z presets; current-weakness vs
  quantum-urgency kept separate.
- **Recommendation:** deterministic PQC / Hybrid / Defer / Remediate-Now / Investigate.
- **Persistence:** best-effort Firebase (Firestore + Storage) + local artifacts + fallback cache.
- **GUI:** React dashboard, findings table, finding detail (evidence + Mosca + recommendation),
  CBOM export, landing + login/signup.

### 2.2 Test status (verified this session)
- **Backend:** 127 test functions across scanner, evidence, CBOM, classifier, Mosca, recommender,
  API contract, models, config, Z-presets.
- **Frontend:** 18 tests (routing, API client, honesty checks).
- (Note: an earlier draft cited "144 backend tests" — the accurate count is **127**.)

### 2.3 How to run the demo
```
# Backend (from d:\blindspot\backend)
python -m uvicorn app.main:app --reload --port 8000

# Frontend (from d:\blindspot\frontend)
npm run dev            # Vite dev server on 5173
```
- Backend health: `GET http://127.0.0.1:8000/api/health` should report `readiness: ready`
  (Firebase, Semgrep, demo repo, fallback cache all available).
- `AUTH_DISABLED=true` in `backend/.env` for local demo (frontend calls succeed without login).
- Proven on real repos: seeded demo-repo (18 findings) and paramiko (12 findings). C rules
  validated against OpenSSL-style code.

### 2.4 Scan modes
- **Live:** actually runs the pipeline against a target (local path today; GitHub URL is the
  planned production path).
- **Cached:** loads the last successful scan from `backend/app/data/cache/last_scan.json` — the
  demo safety net so a stage failure never breaks the presentation.

### 2.5 90-second demo flow
Login → Dashboard (posture) → Run Scan → Findings table → open overdue RSA finding
(evidence → classification → X/Y/Z Mosca inequality → PQC recommendation) → open low-risk finding
(shows it does NOT mark everything urgent) → Export CBOM.

---

## 3. COMPLETE PROJECT INFORMATION (the full platform)

The full production platform is specified formally in `ECDAT_REQUIREMENTS.md` (27 functional +
platform + differentiator + non-functional requirements, plus Part D UI/UX). Summary:

### 3.1 Confirmed stack
Frontend on **Vercel** (React + TS + Tailwind + Recharts). Backend + async worker on **Railway**
(Python + FastAPI). Auth/DB/storage on **Firebase**. Discovery via Semgrep. CBOM via CycloneDX.
Air-gap-*ready* architecture (swappable persistence/auth) but cloud-deployed.

### 3.2 The differentiators (uniqueness)
- ★ **Migration Roadmap (hero)** — prioritized, costed, sequenced waves (Req 16).
- **Dependency / blast-radius graph** (Req 14, 30).
- **CI/CD guardrail + continuous monitoring** (Req 17).
- **India-CII + NIST compliance mapping + sensitivity analysis** (Req 18).
- **Crypto-agility scoring** (Req 19).
- **HNDL exposure flagging** (Req 20).
- **Cross-tool CBOM diff** (Req 23).
- **Cost/latency-aware recommendations** (Req 24).
- **Honest-uncertainty confidence** (Req 22).

Lead the pitch with the top 4: Roadmap, Agility, India-compliance, CBOM diff.

### 3.3 Discovery surfaces (target)
Source (multi-language), dependencies (multi-ecosystem), binaries, container images, live TLS,
HSM/PKCS#11, cloud KMS. *Today: source + dependencies. Rest is roadmap.*

### 3.4 Phased roadmap
Phase 0 spine → Phase 1 compliance/cost/honesty → Phase 2 ★roadmap + graph → Phase 3 discovery
breadth → Phase 4 continuous posture → Phase 5 reporting + hardening. (Details in
`ECDAT_REQUIREMENTS.md` §4 and Part D UI sequencing.)

---

## 4. PPT REVIEW (SIH2026-IDEA-Presentation)

**Verdict: solid structure, wrong emphasis.** The deck currently sells the *commodity* pipeline
(scan → CBOM → Mosca → recommend → GUI) as its "uniqueness" — which is exactly what IBM CBOMkit
and every competitor has. The differentiators are missing or buried.

**Keep:** title/PS framing, technical-approach architecture (accurate), risk split + trust-anchor
nuance, explainability/traceability, honest feasibility slide, real references.

**Fix (details in `PPT_ALIGNMENT.md`):**
1. **Slide 2 (uniqueness) — biggest change:** lead with Migration Roadmap, dependency graph,
   compliance mapping, continuous guardrail. Demote scan/CBOM/Mosca to "proven foundation."
2. **Slide 3:** add *Migration Planner* + *Dependency Graph Builder* components; insert `→ PLAN →`
   in the flow.
3. **Slide 5:** sharpen the bank user story to lead with the costed, wave-based roadmap.
4. **Slide 6 factual fix:** the CBOMkit link `github.com/cbomkit/cbomkit` is wrong → correct is
   `github.com/PQCA/cbomkit` (and `github.com/IBM/CBOM`).

---

## 5. AS-BUILT ARCHITECTURE (verified from the code)

```
Browser (React/Vercel)
      │  HTTP REST (Firebase ID token, or none when AUTH_DISABLED)
      ▼
FastAPI single process (Railway target)
  api/  → health, scan (POST, SYNCHRONOUS), findings, findings/{id}, export/cbom
  pipeline.run_pipeline():
     run_semgrep + parse_dependencies → normalize → build_cbom + validate
     → per finding: classify + current_risk + quantum_risk + Mosca + recommend → summary
  RESULTS STORE: module-global in-memory (_last_scan, _last_findings, _last_cbom in scan.py)
     GET endpoints read from this in-memory store
  Persistence (best-effort, additive): Firestore + Firebase Storage + local artifacts + cache
  Auth: Firebase Admin verify; AUTH_DISABLED bypass
```

**Key as-built facts:**
- Pipeline is **synchronous**, in-process. Explicitly "no queues, no async workers."
- The **source of truth for GET endpoints is in-memory module globals**, not Firestore.
- `run_pipeline()` is a clean pure function returning `(scan, findings, cbom_json)`.
- Scan target is a **local filesystem path** (or the seeded demo repo).
- Scanners called directly in the pipeline: `run_semgrep`, `parse_dependencies`. Output crosses
  the `normalize()` boundary into `NormalizedFinding` before any downstream stage.

---

## 6. TARGET vs AS-BUILT — COMPATIBILITY COMPARISON

| Capability | As-built | Target (ECDAT_REQUIREMENTS) | Compatible? |
|-----------|----------|-----------------------------|-------------|
| Pipeline stages | modular pure functions | same + Migration_Planner | ✅ additive |
| `normalize()` boundary | present | required for new scanners | ✅ already right |
| Scan execution | synchronous in request | async job + worker | ⚠️ **change needed** |
| Results store | in-memory globals | Firestore source of truth | ⚠️ **change needed** |
| Scan target | local path | GitHub URL (clone→scan→cleanup) | ⚠️ **change needed** |
| Scanners | source + dependency | + binary/container/TLS/HSM/cloud | ✅ additive (interface) |
| Persistence | best-effort Firestore | primary Firestore + Storage | ⚠️ promote to primary |
| Auth | Firebase verify + bypass | + RBAC roles | ✅ additive |
| Models | Finding/Scan/etc. | + exposure/HNDL/agility/roadmap | ✅ additive fields |
| CBOM / classifier / Mosca / recommender | done | reused as-is | ✅ no change |
| Config Z-presets | present (7) | feed Compliance_Engine | ✅ reuse |
| Reporting | CBOM export only | + report generator | ✅ additive |
| GUI | dashboard/findings/detail | + roadmap/graph/compliance screens | ✅ additive |

**Conclusion:** the architecture is **largely compatible** because the pipeline is already modular
with a clean `normalize()` boundary and `run_pipeline()` is a pure function. There are **three
real changes** forced by the async + cloud target, all in Phase 0.

---

## 7. RECONCILIATION — architecture changes to make it compatible

These are the concrete changes so the target is compatible with (and evolves from) the existing
system. They are **Phase 0** work, not to be done the night before a presentation.

### CHANGE 1 — Results store: in-memory globals → Firestore as source of truth  *(load-bearing)*
**Why:** On Railway, the web service and the scan worker are **separate processes**. Module-global
`_last_scan/_last_findings/_last_cbom` cannot be shared between them. The GET endpoints must read
from a shared store.
**Change:** Persist scan + findings + CBOM to **Firestore/Storage as the primary store**; GET
`/findings`, `/findings/{id}`, `/export/cbom` read from Firestore keyed by scan id. Keep the
in-memory store only as an optional single-process fast-path for local dev/tests.
**Compatibility:** the existing best-effort Firestore writes already exist — this promotes them
from "additive" to "primary." Existing tests that reset in-memory globals get a Firestore
(or fake) fixture.

### CHANGE 2 — Add async job queue + worker service
**Why:** GitHub-URL clones, containers, and big repos exceed HTTP/Railway request timeouts.
**Change:** `POST /scan` enqueues a job (Firestore-backed state) and returns a scan/job id
immediately; add `GET /scan/{id}/status`. A **separate Railway worker service** consumes jobs and
calls the existing `run_pipeline()` unchanged.
**Compatibility:** `run_pipeline()` is already a pure function — the worker reuses it as-is. Keep a
**synchronous mode behind a flag** so local dev and the 127 backend tests keep running without a
worker.

### CHANGE 3 — Repository-URL ingestion (replaces local path in deployment)
**Why:** a local path is meaningless on Railway.
**Change:** add an ingestion step: validate URL (SSRF: HTTPS-only, host allowlist, reject internal)
→ shallow clone into temp dir → pass path to `run_pipeline()` → delete temp dir in try/finally.
Requires `git` in the backend image. Keep local path behind a dev-only flag.
**Compatibility:** produces a local path, which is exactly what `run_pipeline()` already consumes.

### CHANGE 4 — Formalize a Scanner interface (low-risk refactor)
**Why:** new scanners (binary/container/TLS/HSM/cloud) must plug in without touching downstream.
**Change:** define a `Scanner` protocol that `run_semgrep`/`parse_dependencies` already satisfy in
spirit; new scanners implement it and feed `normalize()`. No downstream change.
**Compatibility:** the `normalize()` boundary already isolates downstream stages — this only
tidies the front.

### CHANGE 5 — Additive model + pipeline extensions
**Why:** differentiators need new data.
**Change:** add fields (exposure, HNDL flag, agility score, roadmap wave) to Pydantic models and
mirror in `frontend/src/types/index.ts`; add a `Migration_Planner` stage after `recommend` in
`run_pipeline()`. All additive — existing fields untouched.
**Compatibility:** existing FE/BE type-mirroring convention is preserved.

### Backward-compatibility principle
- Keep **synchronous + in-memory mode** available (flag) so local dev and all 127 tests keep
  passing unchanged.
- New capabilities are **additive stages/fields**, never rewrites of the proven core (CBOM,
  classifier, Mosca, recommender stay as-is).
- FE and BE types stay mirrored on every model change.

---

## 8. Doc corrections applied
- `ECDAT_REQUIREMENTS.md` §1 test-count claim corrected from "144 backend tests" to the verified
  **127 backend / 18 frontend**.

---

## 9. Where to start
**Phase 0** (production spine) implements CHANGE 1–3 above. That unblocks everything else. When
ready to build, we spec Phase 0 in detail before writing code.
