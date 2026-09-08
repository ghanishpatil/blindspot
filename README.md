# Blindspot — ECDAT Demo

**Enterprise Cryptographic Discovery & Analysis Tool**
SIH 2026 · Problem Statement 26164 · Team Blindspot

> You cannot migrate cryptography you cannot find.

Blindspot discovers cryptographic artefacts in source code and dependencies,
captures evidence of where each artefact was found, converts findings into a
standards-compliant CycloneDX CBOM, and connects that discovery to quantum
migration urgency using Mosca's inequality — ending in an actionable PQC or
hybrid recommendation.

---

## Pipeline

```
LOGIN → PROJECT → SCAN → DISCOVERY (semgrep + dependency parsing)
      → EVIDENCE → NORMALIZED FINDINGS → CYCLONEDX CBOM
      → CLASSIFICATION → MOSCA RISK ANALYSIS → RISK TIER
      → PQC / HYBRID RECOMMENDATION → FIRESTORE + STORAGE
      → DASHBOARD → CBOM EXPORT
```

Two ideas are kept deliberately separate throughout the system:

| Concern | Question it answers |
| --- | --- |
| **Current weakness** | Is this cryptography broken *today*? (e.g. MD5, SHA-1, DES) |
| **Quantum migration urgency** | Mosca: is `X + Y > Z`? Should we migrate *now*? |

Mosca measures migration urgency. It is not a complete security risk model.

---

## Tech stack

| Layer | Technology |
| --- | --- |
| Frontend | React, TypeScript, Vite, Tailwind CSS, Recharts, Firebase Web SDK |
| Backend | Python 3.11+, FastAPI, Pydantic v2, Firebase Admin SDK |
| Discovery | Semgrep (custom rules) + Python dependency/manifest parsers |
| CBOM | CycloneDX (`cyclonedx-python-lib`) |
| Storage / Auth | Firebase Authentication, Firestore, Firebase Storage |
| Hosting | Local development (demo scope) |

---

## Repository layout

```
backend/
  app/
    main.py              FastAPI application factory
    config.py            Environment-driven settings
    api/                 scan · findings · export routes
    scanner/             semgrep runner · dependency parser · rules/
    evidence/            evidence extraction + normalization
    cbom/                CycloneDX builder + schema validator
    classifier/          artefact type · data lifetime · criticality
    risk/                Mosca inequality engine
    recommend/           deterministic PQC/hybrid recommender
    models/              Pydantic domain models
    firebase/            auth · firestore · storage adapters
  tests/
  requirements.txt

frontend/
  src/
    pages/               Login · Dashboard · FindingDetail
    components/          ScanButton · FindingsTable · RiskBadge · MoscaCard · …
    services/            api.ts · firebase.ts
    types/               shared TypeScript contracts

demo-repo/               Seeded repository containing the five demo cases
```

---

## Prerequisites

- **Python 3.11 or newer.** On this machine use the `py` launcher: `py -3.13`
  (bare `python` resolves to 3.10, which is too old).
- **Node.js 20.19+.** Verified on v20.19.4.
- **Git.**

### Two platform notes worth knowing before you start

**Semgrep is pinned to an exact version on purpose.** Semgrep only gained native
Windows support in the Community Edition Fall 2025 release. Older releases ship
no `win_amd64` wheel and their source distribution aborts with *"Semgrep does not
support Windows yet"*. With a version range, pip backtracks into those releases
and the entire install fails. Do not relax `semgrep==1.176.1` to a range.

**The frontend test stack is held below the newest releases.** Node 20 lacks
`webidl.util.markAsUncloneable`, which `undici` 8 calls — so `jsdom` 30 and
`vitest` 5 crash on startup here. `vitest` 4.1.11 and `jsdom` 27.4.0 are the
newest versions that support Node 20. Upgrading to Node 22 LTS or 24 removes
this constraint; it is a worthwhile cleanup after the demo, not before it.

---

## Setup

### 1. Backend

```powershell
cd backend
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Run it:

```powershell
uvicorn app.main:app --reload --port 8000
```

- Health check: http://127.0.0.1:8000/api/health
- Interactive docs: http://127.0.0.1:8000/docs

### 2. Frontend

```powershell
cd frontend
npm install
Copy-Item .env.example .env
npm run dev
```

App runs on http://127.0.0.1:5173.

---

## Environment variables

Never commit real credentials. Both `.env` files are gitignored; only the
`.env.example` templates are tracked.

### Backend (`backend/.env`)

| Variable | Required | Purpose |
| --- | --- | --- |
| `BLINDSPOT_ENV` | no | `development` / `production`. Default `development`. |
| `BLINDSPOT_CORS_ORIGINS` | no | Comma-separated allowed origins for the dashboard. |
| `FIREBASE_PROJECT_ID` | yes (Phase 2+) | Firebase project ID. |
| `FIREBASE_CREDENTIALS_PATH` | yes (Phase 2+) | Absolute path to the service account JSON. |
| `FIREBASE_STORAGE_BUCKET` | yes (Phase 10) | Storage bucket, e.g. `my-project.firebasestorage.app`. |
| `AUTH_DISABLED` | no | `true` only for local development without Firebase. |
| `DEMO_REPO_PATH` | no | Path to the seeded scan target. Defaults to `../demo-repo`. |
| `SEMGREP_PATH` | no | Override the semgrep executable location. |
| `QUANTUM_HORIZON_YEARS` | no | Mosca `Z`. Default `10`. Configurable, never hard-coded. |
| `MIGRATION_TIME_YEARS` | no | Mosca `Y` default. Default `3`. |

### Frontend (`frontend/.env`)

| Variable | Required | Purpose |
| --- | --- | --- |
| `VITE_API_BASE_URL` | yes | Backend base URL. Default `http://127.0.0.1:8000`. |
| `VITE_FIREBASE_API_KEY` | yes (Phase 2+) | Firebase Web API key. |
| `VITE_FIREBASE_AUTH_DOMAIN` | yes (Phase 2+) | `<project>.firebaseapp.com`. |
| `VITE_FIREBASE_PROJECT_ID` | yes (Phase 2+) | Firebase project ID. |
| `VITE_FIREBASE_STORAGE_BUCKET` | yes (Phase 10) | Storage bucket. |
| `VITE_FIREBASE_MESSAGING_SENDER_ID` | yes (Phase 2+) | From Firebase web config. |
| `VITE_FIREBASE_APP_ID` | yes (Phase 2+) | From Firebase web config. |

Firebase web config values are not secrets, but they are still environment
specific and stay out of source control.

---

## Tests

```powershell
# backend
cd backend
.\.venv\Scripts\Activate.ps1
pytest -q

# frontend
cd frontend
npm run typecheck
npm run test
npm run build
```

---

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Liveness + subsystem readiness. |
| `POST` | `/api/scan` | Start a scan; runs the pipeline and persists results. |
| `GET` | `/api/findings` | Findings for a scan/project. |
| `GET` | `/api/findings/{id}` | Full finding: evidence, classification, Mosca, recommendation. |
| `GET` | `/api/export/cbom` | Download the generated CycloneDX CBOM. |

Endpoints whose implementing phase has not landed return **HTTP 501** with the
phase named in the body. That is deliberate: an empty success or a sample
payload would be indistinguishable from a working pipeline, and the
specification requires that fabricated data never stand in for the real one.

---

## Build phases

| Phase | Scope | Status |
| --- | --- | --- |
| 1 | Foundation — structure, config, models, API skeleton, Firebase wiring | **complete** |
| 2 | Firebase Authentication | pending |
| 3 | Seeded demo repository (5 cases) | pending |
| 4 | Semgrep scanner + dependency parser | pending |
| 5 | Evidence extraction + normalization | pending |
| 6 | CycloneDX CBOM + schema validation | pending |
| 7 | Classification engine | pending |
| 8 | Mosca risk engine | pending |
| 9 | Recommendation engine | pending |
| 10 | Firebase persistence (Firestore + Storage) | pending |
| 11 | Dashboard | pending |
| 12 | Full integration | pending |
| 13 | Testing + demo hardening | pending |

The governing rule: never move forward while the current phase is broken.
