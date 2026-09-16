# Blindspot ECDAT — Winning Strategy & Roadmap

**SIH 2026 · Problem Statement 26164 · Enterprise Cryptographic Discovery & Analysis Tool**

This document captures the differentiation strategy, the hero feature, the
supporting differentiators, the key architecture decisions, and the phased
build roadmap. It is the single reference for *why we win* and *what we build*.

---

## 1. The positioning (the one thing to remember)

> **Competitors build a cryptography *scanner* — a tool that tells you what crypto you have.
> Blindspot is a cryptography *migration decision platform* — it finds your crypto, then
> plans the transition with architectural, business, and regulatory context, and keeps watching.**

One-line pitch for judges:

> "Others hand you a list of your cryptography. Blindspot hands you a costed, prioritized,
> compliance-mapped migration plan — and stops new quantum-risk from entering your code.
> Discovery is where they stop; it's where we start."

**Why this wins:** research shows discovery is essentially a solved commodity (IBM CBOMkit,
CZERTAINLY CBOM-Lens, commercial tools). The unsolved, high-value part — and the part the
PS explicitly asks for ("preparedness, risk assessment, financial and operational
investment") — is everything *after* discovery. That is our wedge.

**Rule:** do NOT try to out-scan IBM on discovery breadth. Cover surfaces "good enough" to
satisfy the PS; spend real effort on the differentiators below.

---

## 2. HERO DIFFERENTIATOR — Migration Roadmap

Turn the findings list into an **actionable, prioritized, costed migration plan**.

### Inputs (all already produced by our pipeline)
- Mosca risk tier (overdue / transitional / low-risk)
- Business criticality (from classifier)
- Blast radius (how many other assets/services depend on this one — from the dependency graph)
- Current weakness flag (MD5/SHA-1/DES → remediate now, separate track)

### Prioritization logic
Order migrations by a composite score:

```
priority_score = f(Mosca urgency, business criticality, blast radius)
```

- **Overdue + high criticality + high blast radius** → migrate first
- Short-lived / low-risk → defer
- Present-day-weak → immediate remediation track (parallel to quantum track)

### Output (what the judge sees)
A sequenced plan, not a table:
1. **Wave 1 (now):** these N assets — overdue, critical. Target algorithms, effort, est. cost.
2. **Wave 2 (next):** transitional assets — hybrid migration.
3. **Wave 3 (monitor):** low-risk — defer with review date.
- Each item: current algo → recommended PQC/hybrid algo, parameter set, effort (low/med/high),
  relative cost, and rationale.

### Why it wins
A Eurocrypt-track paper states existing CBOMs *"lack architectural intent, rationale, and
security context, limiting their usefulness for migration planning."* We fill exactly that
gap. This maps directly to the PS background line about financial/operational investment.

---

## 3. SUPPORTING DIFFERENTIATORS (build after the hero)

### 3.1 Crypto Dependency Graph / Blast Radius  *(the visual)*
Interactive graph: which library feeds which service, so migrating X forces changes in Y, Z.
- **Gap filled:** existing CBOMs lack architectural/dependency context.
- **PS alignment:** (i) "across applications, products and infrastructure."
- **Why it matters:** instantly differentiates the GUI — everyone else has the same table.
  Feeds the blast-radius input to the migration roadmap.

### 3.2 India + NIST Compliance Mapping  *(the SIH hook — cheapest, high national relevance)*
Map every finding to real regulatory deadlines:
- **NIST IR 8547** — deprecate classical asymmetric by 2030, disallow by 2035.
- **India CERT-In / national PQC guidance** (CII category deadlines).
- We already have the scaffolding: the 7 configurable Z-presets in `backend/app/config.py`.
- Output: "This asset violates the 2030 NIST deprecation deadline."
- **PS alignment:** (iii) "structured frameworks." National relevance scores heavily at SIH.

### 3.3 Continuous Posture + CI/CD Guardrail  *(turns tool → platform)*
A GitHub Action / webhook that re-scans on every push and **fails the build if new
quantum-vulnerable crypto is introduced**.
- **Gap filled:** discovery is one-shot; the IETF CADI lifecycle's "Validation & Monitoring"
  phase is missing from existing tools.
- **Demo value:** push a commit live, watch it get blocked. Memorable.

### 3.4 Latency & Cost-Aware Recommendations  *(quiet PS checkbox most teams skip)*
Add a PQC benchmark model (key/ciphertext sizes, handshake overhead, relative cost) so
recommendations account for latency and cost.
- **PS alignment:** point (iv) literally says "based on risk profile, latency, cost."
- **Gap filled:** almost universally ignored by competitors.

### 3.5 Honesty / Confidence  *(amplify what we already have)*
We already report detection confidence and unresolved parameters ("what we don't know"),
and we separate present-day-weak (MD5) from quantum-urgency.
- **Gap filled:** research scanners sit around F1 0.75 — accuracy/false-certainty is a known
  weakness. "We tell you what we're NOT sure about" is a trust story judges respect.

---

## 4. KEY ARCHITECTURE DECISIONS

### 4.1 GitHub URL ingestion (replaces local path)
Local filesystem path is meaningless once deployed on Railway.
- Flow: **GitHub URL → shallow git clone into temp dir → run pipeline → delete temp dir.**
- The existing `run_pipeline()` is untouched — the clone just produces a local path.
- **SSRF protection (mandatory for public deploy):** HTTPS only; allowlist github.com /
  gitlab.com / bitbucket.org; reject IPs and internal hostnames.
- Optional Personal Access Token for private repos (never stored; used only for that clone).
- Limits: max clone size/depth, scan timeout, per-session rate limit.
- Cleanup in try/finally so a failed scan still removes the temp clone.
- `git` must be installed in the Railway backend image.
- Keep local-path option behind a dev-only flag; deployed UI shows only the URL field.

### 4.2 Async job model (my recommendation)
Long scans (big repos, containers, binaries) exceed HTTP/Railway request timeouts.
- **Separate Railway worker service** that pulls jobs from **Firestore** (job state store).
- Flow: submit URL → get job ID → poll status → results.
- Stays entirely on the Firebase stack (no Redis/Postgres needed).
- **Prototype note:** synchronous scanning is fine for tomorrow's prototype; the worker is a
  production-build item.

### 4.3 Deployment
- Frontend → **Vercel**. Backend (+ worker) → **Railway**. Storage/Auth/DB → **Firebase**.

### 4.4 Storage
- Stay on **Firebase/Firestore**. Caveat: weak at complex analytical queries (cross-project
  trends) — design the data model for that up front so it doesn't bite later.

---

## 5. CONSOLIDATED ROADMAP (production build, post-prototype)

**Phase 0 — Production spine** (unblocks everything)
- GitHub-URL ingestion + SSRF validation
- Async job model (Firestore job state + Railway worker)
- Deploy pipeline (Vercel + Railway, git in image, temp cleanup)

**Phase 1 — Differentiator wave 1** (cheap, high PS-alignment)
- Compliance mapping (leverage Z-presets → CERT-In + NIST IR 8547)
- Latency/cost model in recommender
- Amplify confidence / "what we don't know" in the UI

**Phase 2 — Differentiator wave 2** (the wow) ← HERO LIVES HERE
- **Migration roadmap** (sequence by Mosca × criticality × blast radius + effort/cost)
- Crypto dependency graph / blast-radius visualization

**Phase 3 — Discovery breadth**
- Multi-language source rules (Java, JS/TS, Go)
- Multi-ecosystem dependency parsing (package.json, pom.xml, go.mod, Cargo.toml)
- Certificate / X.509 discovery
- Container image scanning
- (Binary, live TLS, cloud KMS, HSM → later or roadmap-only)

**Phase 4 — Continuous posture**
- CI/CD guardrail (GitHub Action, block new quantum-risk on push)
- Inventory / trends over time

**Phase 5 — Reporting + hardening**
- Executive PDF/HTML report generation
- RBAC, rate limits, tests, performance, polish

---

## 6. WHAT NOT TO DO
- Don't compete on discovery breadth against IBM CBOMkit (Linux Foundation project).
- Don't add gimmicks (chatbots, gamification) — reads as unserious on a security PS.
- Don't claim HSM/cloud-KMS depth you can't demo — present those as architecture roadmap.
- Don't let any feature exist without a PS line it maps to — judges score against the rubric.

---

## 7. PS26164 ALIGNMENT MATRIX

| PS requirement | Covered by |
|----------------|-----------|
| (i) Catalogue algorithms, keys, certs, protocols, libraries, HW, cloud | Core pipeline + Phase 3 discovery breadth |
| (ii) Quantum risk assessment, systems prone to attack | Mosca engine (Shor/Grover split) — done |
| (iii) Classify by type/lifetime/criticality + Mosca | Classifier + Mosca — done |
| (iv) Recommend PQC/Hybrid by risk, latency, cost | Recommender + latency/cost model (3.4) |
| Deliverable: standardised CBOM report | CycloneDX 1.6 — done + Phase 5 reporting |
| Deliverable: interactive GUI | React dashboard + dependency graph (3.1) |
| Deliverable: scan repos/binaries/libraries/containers | Source done; containers/binaries Phase 3 |
| Background: preparedness, financial/operational investment | **Migration roadmap (hero)** |

---

## 8. RESEARCH BASIS (gaps we exploit) — sources

1. Existing CBOMs are inventory-derived, "lack architectural intent, rationale, and security
   context, limiting their usefulness for migration planning." — arXiv 2603.22442
2. "No single scanning tool covers all surfaces." — quantumsecuritydefence.com
3. Platforms that combine "discovery, policy, and change orchestration" save the most time
   (discovery alone is not enough). — startupstash.com
4. Research scanners report ~F1 0.75, ~87% CBOM coverage (accuracy is an open problem). —
   arXiv 2608.04857
5. IETF CADI lifecycle = Awareness, Discovery, Risk Assessment & Planning, Migration
   Execution, Testing, Validation & Monitoring (tools mostly stop at Discovery). — IETF draft-liu-cadi
6. Enterprise discovery alone takes 12–24 months; full migration 5–15 years; HNDL means
   long-lived data is already exposed. — Adnan Masood, "Enterprise Blueprint for PQC Migration"

Existing tools referenced: IBM CBOMkit / Quantum Safe Explorer (Linux Foundation / PQCA),
CZERTAINLY CBOM-Lens, Encryption Consulting CBOM Secure, QScout, AppViewX, Keyfactor.

*(Source content was rephrased for compliance with licensing restrictions.)*
