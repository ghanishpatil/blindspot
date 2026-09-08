# ECDAT — Demo Plan & Requirements

Scope: PS26164, 2-day hackathon build.

---

## 1. Tech stack

| Layer | Choice | Why |
|---|---|---|
| Backend language | Python 3.11+ | Native support for Semgrep, crypto/TLS libraries, CycloneDX tooling — one language, no interop friction |
| API framework | FastAPI | Fast to stand up, async-friendly, auto-generates API docs |
| Source scanning | Semgrep (custom rules) | AST-aware detection, rules are YAML data, easy to extend live if challenged |
| Dependency parsing | Python stdlib, manual parsers | `requirements.txt`, `pom.xml` — small formats, no library needed |
| CBOM construction | `cyclonedx-python-lib` | Schema-correct CycloneDX `cryptographic-asset` objects, avoids hand-rolled JSON |
| Storage | SQLite or flat JSON files (`cbom.json`, `risk.json`) | Zero ops, sufficient for one demo repo — no Postgres needed |
| Frontend | React + Tailwind CSS + Recharts | 3 screens only, fast to build, no design system overhead |
| Task execution | Synchronous (in-process) | One small repo scans in seconds — no queue/Redis/Celery needed |
| Hosting | Local machine | No cloud deployment for the demo |
| Version control | Git + GitHub | Also satisfies the PS deliverable ("source code link") |

**Explicitly not used for the demo:** Docker/Kubernetes, message queues, Postgres, authentication, GraphQL. All are valid for a real deployment (see the full Project Explainer doc) but add setup time the demo doesn't need.

---

## 2. How the demo works, end to end

### 2.1 The pipeline (what happens when you click "Scan")

```
Target repo (seeded demo repo)
        │
        ▼
STAGE 1 — SCANNER
  Semgrep rules over source code
  + lockfile/manifest parser
  → raw findings: file, line, algorithm, params
        │
        ▼
STAGE 2 — CBOM BUILDER
  Maps each finding to a CycloneDX
  cryptographic-asset object
  → writes cbom.json (source of truth)
        │
        ▼
STAGE 3 — CLASSIFIER
  Tags each asset: artefact type
  (key-exchange/signature/encryption/hash),
  data lifetime (X), criticality
        │
        ▼
STAGE 4 — RISK ENGINE (Mosca)
  Computes X + Y vs Z per artefact,
  split by artefact type
  → tier: overdue / transitional / low-risk
        │
        ▼
STAGE 5 — RECOMMENDER
  Tier → strategy: Pure PQC / Hybrid / Defer
  + specific algorithm suggestion
        │
        ▼
STORAGE — risk.json + recommendations
        │
        ▼
DASHBOARD — React
  Findings table → drill-down →
  evidence → classification → Mosca math → recommendation
```

### 2.2 System architecture (how the components talk to each other)

```
┌─────────────────────────────┐
│   USER (Browser)             │
│   React Dashboard             │
└──────────────┬────────────────┘
               │ HTTP (REST)
               ▼
┌─────────────────────────────────────────────┐
│   FASTAPI BACKEND (single process)            │
│                                                 │
│   POST /scan                                   │
│     → Scanner Module (Semgrep + parser)        │
│     → CBOM Builder → cbom.json                 │
│     → Classifier                               │
│     → Risk Engine (Mosca)                      │
│     → Recommender                              │
│     → risk.json + recommendations              │
│                                                 │
│   GET /findings, /findings/:id, /export/cbom   │
│     → read from stored JSON/SQLite             │
└──────────────┬────────────────────────────────┘
               │ reads
               ▼
┌─────────────────────────────┐
│   Target repo (input)         │
│   Source code + lockfiles      │
└─────────────────────────────┘
```

Everything runs inside **one backend process** — no microservices, no separate containers between your own modules. This is deliberate: it removes integration risk a 2-day team can't afford, while keeping clean internal module boundaries (`scanner/`, `cbom/`, `classifier/`, `risk/`, `recommend/`, `api/`) so it can be split into real services later if the project continues.

### 2.3 The live demo script (what you actually click, in order)

1. Open dashboard → click **Scan** → backend runs the full pipeline against the seeded repo (a few seconds).
2. Findings table populates → point out the 5 planted artefacts and their tiers at a glance.
3. Click the **overdue** finding → show the drill-down: evidence (file + line) → classification (type, data lifetime) → the actual Mosca arithmetic on screen (`X + Y > Z`) → recommendation (Pure PQC, e.g. ML-KEM-768).
4. Click the **low-risk** finding → same drill-down, show it resolves to **Defer**, contrasting with step 3.
5. Click **Export CBOM** → show the CycloneDX JSON is real and schema-valid (only if asked — don't dwell on raw JSON in the main flow).

Target: full script under 90 seconds. Have a **pre-run cached result** ready as a fallback in case live scanning misbehaves on stage.

---

## 3. Functional requirements

### Stage 1 — Scan
- Detect algorithm usage in source code for at least one language (recommend Python + Java for broadest Semgrep coverage).
- Detect at minimum: RSA, ECC/ECDSA/ECDH, AES, DES/3DES, MD5, SHA-1.
- Extract, where resolvable: algorithm name, key size, mode of operation, file path, line number.
- Parse at least one manifest format (`requirements.txt` or `pom.xml`).
- Emit a `confidence` value and `unknown` fallback when a parameter can't be resolved (e.g. key size behind a variable).

### Stage 2 — CBOM Builder
- Convert every finding into a CycloneDX `cryptographic-asset` component.
- Populate at minimum: `bom-ref`, `assetType`, `primitive`, algorithm/parameter identifier, key size or mode, `evidence.occurrences` (file + line).
- Write to a single `cbom.json` (or SQLite) that all downstream stages read from.
- Output must pass CycloneDX schema validation.

### Stage 3 — Classifier
- Tag each asset with `artefact_type` (key-exchange/signature/encryption/hash), `data_lifetime_years` (X, config-declared is fine), `criticality` (low/medium/high).
- Apply the confidentiality-vs-authenticity split: key-exchange/encryption scored on data lifetime; signatures scored differently unless flagged as a long-lived trust anchor (root CA, code-signing, firmware-signing).

### Stage 4 — Risk Engine (Mosca)
- Compute `X + Y` vs `Z` per artefact.
- Output a `tier`: overdue / transitional / low-risk.
- Support at least one alternate `Z` source (e.g. CRQC estimate vs. a named regulatory deadline like NIST IR 8547 2030/2035 or India CII 2027/2028/2029).

### Stage 5 — Recommender
- Map tier → strategy: Pure PQC / Hybrid / Defer (risk-tiered, Option 3 approach).
- Recommend a specific algorithm: RSA/ECDH → ML-KEM (name the parameter set); ECDSA/RSA signatures → ML-DSA (name the parameter set); hybrid recommendations name both components (e.g. `X25519 + ML-KEM-768`).
- Include a one-line `rationale` string per recommendation.

### Dashboard
- Screen 1: trigger scan.
- Screen 2: findings table (algorithm, tier, recommendation at a glance).
- Screen 3: detail drill-down (evidence → classification → Mosca math → recommendation).
- Visible CycloneDX export action.

### API
- `POST /scan`, `GET /findings`, `GET /findings/{id}`, `GET /export/cbom`.

---

## 4. Data requirements

### Must have
- **Seeded demo repository** (built by the team) containing:
  - 1 "overdue" artefact (e.g. RSA-2048 key exchange protecting long-lifetime data)
  - 1 "transitional" artefact (e.g. classical ECDH in active use)
  - 1 "low-risk" artefact (e.g. short-lived session signature)
  - 1 non-quantum weak-crypto finding (MD5 or hardcoded key)
  - 1 deliberately unresolvable case (key size behind a variable) to show confidence-scoring honesty

### Should have, not blocking
- One real open-source repo scanned for generalization (OpenSSL is explicitly permitted by the PS as a dataset source).
- Output from a second tool (IBM CBOMkit or CZERTAINLY CBOM-Lens) on the same target, for a cross-tool comparison slide.

### Not needed
- No labeled training dataset (rule-based detection, not ML).
- No live network traffic/packet captures.
- No real organizational cryptographic inventory data.

---

## 5. Non-functional requirements

- Single backend process — no external services beyond API and storage.
- Scan of the seeded repo completes in well under 30 seconds.
- Cached fallback result available in case live scanning misbehaves during the demo.
- No authentication required for this build (explicitly deferred; required before any real deployment).

---

## 6. Acceptance criteria

- [ ] Clicking Scan against the seeded repo returns findings for all 5 planted artefacts.
- [ ] Each finding's tier and recommendation are consistent (overdue → Pure PQC, transitional → Hybrid, low-risk → Defer).
- [ ] The overdue finding's drill-down shows the actual X, Y, Z numbers and the inequality.
- [ ] CycloneDX export validates against the CycloneDX schema.
- [ ] Re-running the same scan produces identical results.
- [ ] Full click-through (scan → table → drill-down → export) completes in under 90 seconds.

---

## 7. Explicitly out of scope for the demo

Deferred to the full project (see `ECDAT_Project_Explainer.docx`, Part 2):

- Binary and container image scanning
- Live TLS handshake / certificate store scanning
- Hardware module (HSM/PKCS#11) and cloud KMS discovery
- Latency and cost as modeled recommendation inputs
- Authentication / role-based access control
- Async job queue for long-running scans
- Multi-user, multi-organization, trend-over-time views
