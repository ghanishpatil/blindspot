# ECDAT — Next Round Upgrade Plan

**What's already built vs. what to add before the next round.** Scope is deliberately small —
this is a targeted upgrade to the existing demo, not a rebuild. Nothing in "Already Implemented"
needs to change. Everything in "To Add" is additive on top of it.

> **STATUS UPDATE:** ★ **Migration Roadmap (item 4) is COMPLETE** — full version with
> blast-radius proxy, backend + API (`GET /api/roadmap`) + frontend (`/roadmap` page, "Migration
> Roadmap" nav) + 9 tests. Live-verified producing the 5-wave plan from a real scan.
>
> ★ **Compliance Sensitivity View (item 1) is COMPLETE** — backend `app/models/compliance.py` +
> `app/compliance/evaluator.py` (re-runs the *same* `mosca.assess` under every named Z preset,
> no math duplication) + API `GET /api/compliance` + 10 tests. Frontend `/compliance` page
> ("Compliance Sensitivity" nav) with a preset selector, baseline-vs-preset delta summary,
> an overdue-by-deadline escalation chart, and a findings table that highlights tier flips.
> Full backend suite **190 passed**; frontend tsc clean, 18 tests pass. **Live-verified on the
> real 18-finding demo scan: overdue climbs 0 (CRQC Z=15) → 5 (baseline Z=10) → 8 (India CII
> 2027, Z=1, +3 vs baseline).**
>
> ★ **HNDL Exposure Flag (item 2) is COMPLETE** — `Finding.is_hndl_exposed` (confidentiality +
> quantum-vulnerable + overdue), `ScanSummary.hndl_exposed` count, findings-table "HNDL" badge,
> and an "HNDL Exposed" dashboard stat. 7 tests. Full suite **197 passed**; frontend tsc clean,
> 18 tests pass. Live-verified: 5 of 18 findings flagged on the real scan.
>
> ★ **Honesty / Confidence Surfacing (item 3) is COMPLETE** — `Finding.needs_verification`
> (low confidence OR unresolved parameter), `ScanSummary.needs_verification` count, a 3-band
> confidence indicator + "Verify" badge on the findings table, and a dashboard honesty banner.
> 6 tests. Full suite **203 passed**; frontend tsc clean, 18 tests pass. Live-verified: 1 of 18
> findings flagged.
>
> Also done: GitHub-URL ingestion (Phase 0 CHANGE 3). **All four code features (items 1–4) are
> complete. Only item 5 remains — a slide-deck re-order, not code.**

---

## Part 1 — Already Implemented (verified working)

This is the real, tested state of the demo as of this session. Don't rebuild any of this.

### Pipeline
| Stage | Status | Detail |
|---|---|---|
| Source scanning | ✅ Done | Semgrep custom rules, Python + C/OpenSSL-style rules |
| Dependency scanning | ✅ Done | Manifest/lockfile parsing |
| Evidence extraction | ✅ Done | File/line snippet, AST parameter resolution, confidence policy |
| CBOM generation | ✅ Done | CycloneDX 1.6, schema-validated |
| Classification | ✅ Done | Artefact type, data lifetime (X), criticality, confidentiality-vs-authenticity split, trust-anchor escalation |
| Risk engine (Mosca) | ✅ Done | Configurable Z, **7 named presets already in `config.py`** (India CII categories, NIST IR 8547 both dates, CRQC estimate), current-weakness kept separate from quantum-urgency |
| Recommendation engine | ✅ Done | Deterministic PQC / Hybrid / Defer / Remediate-Now / Investigate, NIST security category derived from each finding's own resolved parameter (FIPS 203/204, SP 800-57) |
| Persistence | ✅ Best-effort | Firebase (Firestore + Storage) + local artifacts + fallback cache |
| GUI | ✅ Done | Dashboard, findings table, finding detail (evidence → classification → Mosca math → recommendation), CBOM export, login/signup |

### Verified test status
- Backend: 127 test functions passing (scanner, evidence, CBOM, classifier, Mosca, recommender, API, models, config, Z-presets)
- Frontend: 18 tests passing

### Verified live behavior
- Live scan on seeded demo repo: 18 findings, correctly tiered
- Live scan on paramiko: 12 findings
- C rules validated against OpenSSL-style code
- RSA-2048 finding correctly resolves to ML-KEM-512 (Category 1), not the earlier incorrect ML-KEM-1024 overshoot
- MD5 finding correctly separates current weakness from quantum risk (`isQuantumVulnerable: false`, `mosca.applicable: false`)
- CBOM export produces valid CycloneDX 1.6 with proper `cryptographic-asset` components

### Known limitation (architectural, not a bug)
- Pipeline is synchronous, in-process; results store is in-memory module globals, not yet Firestore-primary.
- **This is fine for the next round.** It only matters for a multi-process cloud deployment (Railway worker + web service split), which is Phase 0 production work — not visible to a judge in a local demo. Do not "fix" this before the next round; it's not a demo-blocking issue.

---

## Part 2 — What Fulfills vs. Doesn't, Against the 7 Expected Outcomes

| # | Outcome | Status |
|---|---|---|
| 1 | Scan source, binaries, libraries, containers | Partial — source + deps done; binaries/containers not built |
| 2 | Identify algorithms/keys/certs/protocols/libraries incl. versions/modes | Partial — code artefacts covered; certs/protocols need live scanning, not built |
| 3 | Quantum-risk assessment via structured framework | **Full** — strongest area |
| 4 | Classify by type/lifetime/criticality/quantum-risk | **Full** |
| 5 | PQC/Hybrid recommendations by security/latency/cost | Partial — security done; latency/cost not modeled |
| 6 | Standardized report | **Full** |
| 7 | Interactive GUI | **Full** |

**4 of 7 outcomes fully done.** The gap is real but bounded and already understood — this doc exists to close the highest-leverage part of that gap cheaply, not to chase full coverage.

---

## Part 3 — What to Add for the Next Round

Ranked by effort-to-impact ratio. Do them in this order. Each one builds on data the pipeline
already produces — none require new scanners or new detection logic.

### 1. Compliance Sensitivity View — ✅ COMPLETED
**Effort: low. Impact: high.** The single best item on this list.

> **DONE.** Backend: `app/models/compliance.py`, `app/compliance/evaluator.py`,
> `app/api/compliance.py` (`GET /api/compliance`), wired into the router, 10 tests. The evaluator
> re-runs the same `mosca.assess` under all 7 named Z presets — no duplicated math — and returns
> the whole findings × presets matrix in one payload so the GUI switches presets instantly.
> Frontend: `pages/CompliancePage.tsx` at `/compliance` with a "Compliance Sensitivity" sidebar
> item, a preset selector, a baseline-delta summary, an overdue-by-deadline escalation chart, and
> a findings table that highlights every tier flip. 190 backend tests pass; frontend tsc clean,
> 18 tests pass. Live-verified on the real 18-finding scan: overdue 0 → 5 → 8 across CRQC /
> baseline / India-2027.

**What exists already:** 7 named Z-presets are already implemented in `backend/app/config.py`
and exposed via `/api/health` (confirmed live). The Mosca math already recomputes correctly
under any Z value.

**What's missing:** A GUI way to see one finding's tier *change* as the preset changes. Right now
the presets exist in the backend but there's no view that dramatizes them.

**What to build:**
- A preset selector (dropdown) on the finding detail view and/or dashboard.
- Switching presets re-evaluates the visible findings' tiers against the new Z and re-renders
  the Mosca inequality with the new numbers.
- One finding that visibly flips tier (e.g., low-risk under a 15-year CRQC estimate → overdue
  under India's 2027 CII deadline) becomes your best demo moment.
- Optional stretch: a small summary row showing "under [preset], N findings become overdue."

**Backend work:** minimal — likely just an endpoint parameter to select the Z-preset for a
re-evaluation call, since the presets and the Mosca function already exist.

**Why this first:** it directly answers the PS's "structured frameworks" language with something
close to zero competing tools do, and it's almost entirely a GUI + thin API layer on top of
logic you've already built and tested.

---

### 2. HNDL (Harvest-Now-Decrypt-Later) Exposure Flag — ✅ COMPLETED
**Effort: very low. Impact: medium-high.**

> **DONE.** Backend: `Finding.is_hndl_exposed` computed field (confidentiality goal +
> quantum-vulnerable + Mosca-overdue — derived purely from existing fields, asserts nothing new),
> flows through `serialise()` and the Firestore flatten; `ScanSummary.hndl_exposed` count added and
> tallied in `pipeline._build_summary`; 7 tests in `tests/test_hndl.py`. Frontend: `isHndlExposed`
> on the Finding type + `hndlExposed` on ScanSummary, an "HNDL" badge on findings-table rows, and
> an "HNDL Exposed" dashboard stat card. 197 backend tests pass; frontend tsc clean, 18 tests pass.
> Live-verified on the real scan: **5 of 18 findings flagged** (the overdue RSA/ECC key-exchange
> ones; signatures and symmetric/hash correctly excluded).

**What exists already:** X, Y, Z are already computed per finding; confidentiality-vs-authenticity
classification already exists.

**What's missing:** An explicit flag/label derived from data you already have.

**What to build:**
- Backend: if a finding is confidentiality-type (key-exchange/encryption) and `X + Y` approaches
  or meets `Z`, tag it `hndl_exposed: true`.
- Frontend: a small "HNDL Exposed" badge on the finding card/table row.
- Dashboard: one summary stat — "N findings are Harvest-Now-Decrypt-Later exposed."

**Why this matters:** it's a named, specific concept (attackers recording ciphertext today to
decrypt once a quantum computer exists) that most generic scanners don't call out explicitly.
Cheap to add, sounds sophisticated, and it's mechanically just a derived label.

---

### 3. Surface the Honesty / Confidence Story — ✅ COMPLETED
**Effort: very low. Impact: medium.**

> **DONE.** Backend: `Finding.needs_verification` computed field (low detection confidence OR an
> unresolved parameter — derived, asserts nothing new); `ScanSummary.needs_verification` count
> tallied in `pipeline._build_summary`; `confidenceLevel` also promoted in the Firestore flatten;
> 6 tests in `tests/test_honesty.py`. Frontend: `needsVerification` on the Finding type +
> `needsVerification` on ScanSummary; the findings table now shows a 3-band confidence indicator
> (high/medium/low with dot + label) and a "Verify" badge on low-confidence rows; the dashboard
> carries an honesty banner ("N findings flagged for manual verification — we surface what we are
> not certain about"). 203 backend tests pass; frontend tsc clean, 18 tests pass. Live-verified:
> 1 of 18 findings flagged (the low-confidence, unresolved-parameter RSA).

**What exists already:** Confidence scoring (`high`/`low`) and unresolved-parameter handling are
already implemented and tested (verified live: the unresolved-parameter case works correctly).

**What's missing:** Visibility. This is currently buried in the detail view.

**What to build:**
- Add a small confidence indicator directly on the findings table row, not just the detail view.
- Add one dashboard summary stat: "N findings flagged for manual verification" (i.e., confidence
  = low, or unresolved parameters present).

**Why this matters:** it's a trust signal — "we tell you what we're not sure about" — and it
costs almost nothing since the data already exists; this is pure surfacing.

---

### 4. Migration Roadmap — ✅ COMPLETED (full version, not the cut-down)
**Effort: moderate. Impact: high.** Built as the hero feature.

> **DONE.** Backend: `app/models/roadmap.py`, `app/roadmap/planner.py`, `app/api/roadmap.py`
> (`GET /api/roadmap`), wired into the router, 9 tests. Frontend: `pages/RoadmapPage.tsx` at
> `/roadmap` with a "Migration Roadmap" sidebar item, sequenced wave cards, cost/effort/priority
> per item, and the remediation track visually separated. Includes the blast-radius signal
> (co-located-file proxy) — richer than the planned cut-down three-wave version. The dependency
> graph that upgrades blast radius from proxy to true impact remains future work (Req 14).

**What exists already:** Per-finding `effort` and `migration_notes` fields already exist in the
recommender output (confirmed live). Risk tier and criticality already exist.

**What's missing:** Grouping findings into a sequenced plan.

**What to build (cut-down version — skip the dependency graph):**
- Group findings into three waves without blast-radius weighting:
  - **Wave 1 (now):** overdue + high criticality
  - **Wave 2 (next):** transitional
  - **Wave 3 (monitor):** low-risk, deferred
- Each wave item shows: current algorithm → recommended algorithm, effort, and a one-line
  rationale — all fields your recommender already produces.
- A simple GUI view rendering the three waves as an ordered list or stacked cards.

**Explicitly skip for this round:** the dependency graph / blast-radius weighting (Requirement 14
in the full spec). That needs new graph-construction logic and is real new work — the PS's
"financial and operational investment" line is still meaningfully addressed by the three-wave
version without it.

**Do this only after 1–3 are done and only if time remains.** It's the most PS-relevant gap-closer
(the only outcome-adjacent feature touching "financial and operational investment"), but it's the
most expensive item on this list, so it's ordered last on purpose.

---

## Part 4 — Explicitly Do NOT Build Before the Next Round

These are real, correctly-scoped future work — but invisible to a judge and not worth the time
right now:

- Async job queue + separate worker service (Railway split)
- Firestore-as-primary-store migration (currently in-memory globals — fine for a local demo)
- GitHub-URL repository ingestion / cloning
- Binary scanning
- Container image scanning
- Live TLS / certificate / protocol scanning
- HSM/PKCS#11 discovery
- Cloud KMS discovery
- Cross-tool CBOM diff
- Crypto-agility scoring
- CI/CD guardrail

None of these change what a judge sees in the room. Building any of them now trades limited time
against items 1–3 above, which are cheaper and more visible.

---

## Part 5 — The Non-Code Fix: the Pitch

Even with zero new features, re-order the "uniqueness" slide in the deck. It currently sells the
commodity pipeline (scan → CBOM → Mosca → recommend → GUI) as the differentiator — which is what
every competing tool already has. Lead instead with whichever of items 1–3 you ship, framed
explicitly as "what competitors don't do":

- Compliance sensitivity across real regulatory deadlines (item 1)
- Explicit HNDL exposure flagging (item 2)
- Honest uncertainty instead of false confidence (item 3)

This costs nothing to change and directly affects how the same demo is perceived.

---

## Summary — Build Order

1. ~~Compliance Sensitivity View~~ ✅ **DONE** (backend + API + frontend + 10 tests, live-verified)
2. ~~HNDL Exposure Flag~~ ✅ **DONE** (Finding flag + summary + badge + dashboard stat + 7 tests, live-verified)
3. ~~Honesty/Confidence Surfacing~~ ✅ **DONE** (needs-verification flag + summary + table indicator + dashboard banner + 6 tests, live-verified)
4. ~~Migration Roadmap~~ ✅ **DONE** (full version — backend + API + frontend + tests, live-verified)
5. Slide 2 re-order (zero effort, do regardless) — **the only remaining item; it is a deck edit, not code**

**All four code features in this plan are now complete.** Backend suite: 203 passed. Frontend: tsc
clean, 18 tests pass. Every feature is live-verified on the real seeded scan.
