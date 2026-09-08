# BLINDSPOT — ECDAT DEMO BUILD SPECIFICATION

## SIH 2026 — Problem Statement 26164
### Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)

Team: Blindspot

---

# 0. PURPOSE

This document is the implementation specification for the Blindspot ECDAT demo.

IMPORTANT:
- This document is for the DEMO build only.
- The demo must implement the real end-to-end pipeline, not a fake UI or static mockup.
- Do not expand into the full enterprise architecture unless explicitly instructed later.
- The demo requirements file is the source of truth for demo scope.
- Firebase replaces the original SQLite/JSON storage and also provides authentication and file storage.

The goal is to have a reliable, judge-ready working demonstration by tomorrow.

The core demo flow is:

LOGIN
  -> PROJECT
  -> SCAN
  -> SOURCE/DEPENDENCY DISCOVERY
  -> EVIDENCE EXTRACTION
  -> CBOM
  -> CLASSIFICATION
  -> MOSCA RISK ANALYSIS
  -> RISK TIER
  -> PQC/HYBRID RECOMMENDATION
  -> FIREBASE
  -> DASHBOARD
  -> CBOM EXPORT

---

# 1. DEMO OBJECTIVE

Blindspot demonstrates that an organization can:

1. Discover cryptographic artefacts in source code and dependencies.
2. Capture evidence showing where the cryptography was detected.
3. Convert findings into a standardized CycloneDX CBOM.
4. Classify findings by artefact type, data lifetime, and business criticality.
5. Calculate quantum migration urgency using Mosca's inequality.
6. Categorize findings as overdue, transitional, or low-risk.
7. Recommend PQC, hybrid, or defer strategies.
8. Visualize findings and reasoning in an interactive dashboard.
9. Export a real, schema-valid CBOM.

The central story:

> You cannot migrate cryptography you cannot find.

---

# 2. FINAL DEMO TECH STACK

## Frontend

- React
- TypeScript
- Tailwind CSS
- Recharts
- Firebase Web SDK

## Backend

- Python 3.11+
- FastAPI
- Firebase Admin SDK

## Discovery

- Semgrep with custom rules
- Python-based dependency/manifest parsing

## CBOM

- CycloneDX
- cyclonedx-python-lib

## Storage / Authentication

- Firebase Authentication
- Firebase Firestore
- Firebase Storage

## Version Control

- Git
- GitHub

## Hosting

- Local development for the demo

Do NOT add Kubernetes, microservices, Redis/Celery, GraphQL, Postgres, or other infrastructure unless explicitly requested.

---

# 3. HIGH-LEVEL ARCHITECTURE

Use a modular backend even though it runs as one FastAPI process.

                         USER
                          |
                          v
                    React Dashboard
                          |
                          | Firebase Auth
                          v
                    Firebase ID Token
                          |
                          v
                    FastAPI Backend
                          |
        +-----------------+------------------+
        |                 |                  |
        v                 v                  v
     Scanner          CBOM Builder       Firebase
        |                 |             Firestore/Storage
        v                 |
     Evidence             |
        |                 |
        v                 v
    Classifier -------> Risk Engine
                           |
                           v
                     Recommender
                           |
                           v
                       Findings
                           |
                           v
                       Dashboard

The internal pipeline is:

SCAN
 -> EVIDENCE
 -> NORMALIZE
 -> CBOM
 -> CLASSIFY
 -> RISK
 -> RECOMMEND
 -> STORE
 -> DISPLAY

---

# 4. BACKEND PROJECT STRUCTURE

Use a clean modular structure.

backend/
  app/
    main.py

    api/
      scan.py
      findings.py
      export.py

    scanner/
      semgrep.py
      dependency_parser.py
      rules/

    evidence/
      extractor.py

    cbom/
      builder.py
      validator.py

    classifier/
      classifier.py

    risk/
      mosca.py

    recommend/
      recommender.py

    models/
      asset.py
      finding.py
      scan.py
      recommendation.py

    firebase/
      auth.py
      firestore.py
      storage.py

    config.py

  tests/

  requirements.txt

frontend/
  src/
    pages/
      Login.tsx
      Dashboard.tsx
      FindingDetail.tsx

    components/
      ScanButton.tsx
      FindingsTable.tsx
      RiskBadge.tsx
      MoscaCard.tsx
      RecommendationCard.tsx
      SummaryCards.tsx

    services/
      api.ts
      firebase.ts

    types/
      index.ts

---

# 5. FIREBASE DESIGN

## 5.1 Authentication

Use Firebase Authentication.

Demo authentication:
- Email/password is sufficient.
- React authenticates the user.
- React obtains Firebase ID token.
- Every protected FastAPI request sends the token as a Bearer token.
- FastAPI verifies the token with Firebase Admin SDK.

Flow:

React
 -> Firebase Auth
 -> ID Token
 -> FastAPI Authorization header
 -> Firebase Admin token verification
 -> authorized request

Do not trust a user ID supplied directly by the frontend.

---

# 6. FIRESTORE DATA MODEL

Keep the demo database simple.

## users/{userId}

Fields:
- email
- displayName
- createdAt

## projects/{projectId}

Fields:
- name
- description
- ownerId
- repositoryPath
- createdAt

## scans/{scanId}

Fields:
- projectId
- ownerId
- status
- repository
- startedAt
- completedAt
- findingCount
- summary

## findings/{findingId}

Fields:

- scanId
- projectId
- algorithm
- primitive
- parameter
- mode
- usage
- artefactType
- filePath
- lineNumber
- evidence
- detectionMethod
- confidence
- dataLifetimeYears
- criticality
- currentRisk
- quantumRisk
- mosca
- riskTier
- recommendation
- rationale
- createdAt

The schema must remain easy to query.

---

# 7. FIREBASE STORAGE

Use Firebase Storage for generated artefacts.

Recommended paths:

projects/{projectId}/
scans/{scanId}/
  cbom.json
  raw-findings.json
  report.json

Firestore stores metadata/queryable information.

Storage stores generated files.

The exported CBOM must be downloadable from the UI.

---

# 8. SEEDED DEMO REPOSITORY

Create a controlled repository specifically for the demonstration.

It MUST contain five deliberately designed cases.

## Case 1 — Overdue quantum-risk finding

Example:
- RSA-2048
- key establishment / key-related use
- long-lived sensitive data
- X = 15 years
- Y = 3 years
- Z = 10 years

Mosca:

15 + 3 > 10

Result:
- overdue
- urgent migration
- PQC recommendation

Avoid calling RSA-2048 itself "key exchange" unless the code actually represents a key-establishment/key-transport use.

## Case 2 — Transitional finding

Example:
- X25519/ECDH
- active use
- medium/long-term relevance

Result:
- transitional
- hybrid recommendation
- X25519 + ML-KEM-768

## Case 3 — Low-risk finding

Example:
- short-lived session signature

Result:
- low-risk
- defer/monitor

## Case 4 — Current weak cryptography

Example:
- MD5 or another clearly weak current cryptographic construction

Result:
- current security weakness
- do NOT pretend this is merely quantum risk

## Case 5 — Unresolvable parameter

Example:

KEY_SIZE = config.get("key_size")
RSA.generate(KEY_SIZE)

Expected:
- RSA detected
- key size = unknown
- lower confidence
- clear "unknown/unresolved parameter" state

This demonstrates honest uncertainty.

---

# 9. SCANNER REQUIREMENTS

Use Semgrep custom rules.

Minimum algorithms/cryptographic artefacts to detect:

- RSA
- ECC
- ECDSA
- ECDH
- AES
- DES
- 3DES
- MD5
- SHA-1

The scanner should extract where resolvable:

- algorithm
- parameter/key size
- mode
- usage
- file path
- line number
- detection method
- confidence

The scanner's responsibility is DISCOVERY, not risk calculation.

Do not put recommendation logic into Semgrep rules.

---

# 10. EVIDENCE MODEL

Every finding must retain evidence.

Example:

{
  "file": "auth.py",
  "line": 42,
  "code": "RSA.generate(2048)",
  "detectionMethod": "semgrep_api_pattern",
  "confidence": 0.98
}

A finding should answer:

- What was found?
- Where was it found?
- How was it detected?
- How certain are we?
- What parameters were resolved?
- What parameters remain unknown?

Confidence examples:

- Direct API call: high
- AST-confirmed usage: high
- Dependency metadata: medium/high
- Configuration inference: medium
- String-only match: lower

Do not present uncertain inference as fact.

---

# 11. NORMALIZED FINDING MODEL

All scanners must produce a common normalized finding structure.

Suggested model:

{
  "id": "CRYPTO-001",
  "algorithm": "RSA",
  "primitive": "RSA",
  "parameter": "2048",
  "mode": null,
  "usage": "key_establishment",
  "artefactType": "key-exchange",
  "filePath": "auth.py",
  "lineNumber": 42,
  "evidence": "...",
  "detectionMethod": "semgrep",
  "confidence": 0.98
}

Downstream modules consume this normalized representation.

Do not make the CBOM builder parse raw Semgrep output directly if avoidable.

---

# 12. CBOM BUILDER

Convert every normalized finding into a CycloneDX cryptographic asset.

At minimum include:

- bom-ref
- assetType
- primitive
- algorithm/parameter identifier
- key size or mode where known
- evidence.occurrences
- source file
- source line

Generate:

cbom.json

All downstream stages should work from the normalized finding/CBOM representation rather than rescanning the repository.

The CBOM must validate against the appropriate CycloneDX schema.

Provide a validation test.

---

# 13. CLASSIFICATION ENGINE

Every finding must receive:

## Artefact type

Examples:
- key-exchange
- signature
- encryption
- hash

## Data lifetime

For the demo, configuration-declared values are acceptable.

Example:
- 15 years
- 5 years
- 0.1 years

## Business criticality

Use:
- low
- medium
- high

The classifier must distinguish confidentiality-oriented cryptography from authenticity-oriented cryptography.

Key establishment/encryption:
- data lifetime is highly relevant.

Signatures:
- evaluate differently.
- Long-lived trust anchors such as root CA/code signing/firmware signing should receive special handling.

---

# 14. RISK ENGINE

Implement Mosca as a dedicated module.

Inputs:

X = data secrecy lifetime
Y = migration time
Z = quantum horizon

Core comparison:

X + Y > Z

Example:

X = 15
Y = 3
Z = 10

15 + 3 > 10

=> overdue

Output should include:

{
  "x": 15,
  "y": 3,
  "z": 10,
  "equation": "15 + 3 > 10",
  "result": true,
  "tier": "overdue"
}

Minimum tiers:

- overdue
- transitional
- low-risk

The UI must show the actual numbers and inequality.

If implementing an alternate Z source for the demo, keep the source configurable. Do not hard-code unsupported claims.

Important:
Mosca is a migration-urgency framework, not the entire security risk model.

Keep current weakness and quantum migration urgency conceptually separate.

---

# 15. RECOMMENDATION ENGINE

For the demo, make the recommender deterministic and explainable.

Base strategy:

OVERDUE
 -> Pure PQC / urgent PQC migration

TRANSITIONAL
 -> Hybrid

LOW-RISK
 -> Defer / monitor

Algorithm mapping:

RSA / ECDH
 -> ML-KEM
 -> specify parameter set

ECDSA / RSA signatures
 -> ML-DSA
 -> specify parameter set

Hybrid example:

X25519 + ML-KEM-768

Every recommendation must contain:

- strategy
- algorithm
- parameter set
- rationale

Example:

{
  "strategy": "HYBRID",
  "algorithm": "X25519 + ML-KEM-768",
  "rationale": "Provides a transition path while reducing disruption to an existing classical key-establishment mechanism."
}

Do not implement the recommender as a single simplistic:
"if RSA then ML-KEM"
rule without considering usage.

For the demo, usage + risk tier is enough.

---

# 16. API

Required endpoints:

POST /scan
GET /findings
GET /findings/{id}
GET /export/cbom

Suggested behavior:

POST /scan
- authenticated
- starts the scan
- runs the pipeline
- stores scan + findings
- stores CBOM
- returns scan ID / summary

GET /findings
- authenticated
- returns findings for the current project/scan

GET /findings/{id}
- authenticated
- returns full finding, evidence, classification, Mosca analysis, recommendation

GET /export/cbom
- authenticated
- returns or downloads the generated CBOM

Keep API response models typed with Pydantic.

---

# 17. DASHBOARD

Build only the screens needed for the demo.

## Screen 1 — Login

Simple Firebase email/password login.

After login:
- show Blindspot branding
- route to dashboard

## Screen 2 — Scan Dashboard

Show:
- project/repository
- Scan button
- last scan
- scan status
- summary cards

Example summary:

Total findings
Quantum-sensitive
Overdue
Transitional
Low-risk
Current weak crypto

## Screen 3 — Findings Table

Columns:

- Algorithm
- Usage
- Artefact type
- Confidence
- Risk tier
- Recommendation

Clicking a finding opens detail.

## Screen 4 — Finding Detail

This is the most important screen.

Show:

DETECTION
- algorithm
- parameter
- usage
- file
- line
- evidence
- confidence

CLASSIFICATION
- artefact type
- data lifetime
- criticality

RISK
- current risk if applicable
- quantum risk
- Mosca calculation

MOSCA

X = 15 years
Y = 3 years
Z = 10 years

15 + 3 > 10

OVERDUE

RECOMMENDATION
- strategy
- PQC/hybrid algorithm
- parameter set
- rationale

## Export

Visible "Export CBOM" action.

---

# 18. UI DESIGN PRIORITY

Priority order:

1. Clear
2. Fast
3. Judge-readable
4. Professional
5. Visually polished

Do not spend excessive time on animations.

The judge must immediately understand:

FOUND
 -> WHY
 -> RISK
 -> WHY RISKY
 -> WHAT TO DO

---

# 19. DEMO FALLBACK

Implement a cached fallback.

There should be:

LIVE MODE
- actually scans the seeded repository.

FALLBACK MODE
- loads the last known successful scan result.

The fallback should never be presented as a fake live scan.

UI can indicate:
- Live scan
- Cached result

The objective is to ensure a stage failure does not destroy the presentation.

---

# 20. TESTING REQUIREMENTS

## Scanner

- RSA detected
- ECC/ECDSA/ECDH detected
- AES detected
- DES/3DES detected
- MD5 detected
- SHA-1 detected
- file path captured
- line captured
- parameter captured when resolvable
- unknown parameter handled
- confidence generated

## CBOM

- every finding represented
- required fields populated
- evidence included
- schema validation passes

## Classifier

- artefact type
- lifetime
- criticality
- confidentiality/authenticity distinction

## Risk

- X/Y/Z values
- inequality calculation
- overdue
- transitional
- low-risk

## Recommendation

- PQC
- Hybrid
- Defer
- named algorithm
- named parameter set
- rationale

## Firebase

- login
- token verification
- Firestore write
- Firestore read
- Storage upload
- CBOM retrieval/export

## Integration

The same repository scanned twice should produce deterministic equivalent results.

---

# 21. ACCEPTANCE CRITERIA

The demo is complete when:

[ ] Login works.

[ ] User can start a scan.

[ ] Seeded repository produces all five intended cases.

[ ] RSA-2048 overdue case appears.

[ ] Transitional ECDH/X25519 case appears.

[ ] Low-risk short-lived signature appears.

[ ] Current weak crypto finding appears.

[ ] Unknown-parameter case appears with reduced/appropriate confidence.

[ ] Findings are stored in Firestore.

[ ] CBOM is generated.

[ ] CBOM passes schema validation.

[ ] CBOM is stored in Firebase Storage.

[ ] Findings table works.

[ ] Finding detail works.

[ ] Evidence file + line is visible.

[ ] Classification is visible.

[ ] X/Y/Z values are visible.

[ ] Actual Mosca inequality is visible.

[ ] Risk tier is visible.

[ ] Recommendation is visible.

[ ] Recommendation has rationale.

[ ] CBOM export works.

[ ] Repeated scans are deterministic/equivalent.

[ ] Scan is comfortably below 30 seconds for the seeded repository.

[ ] Full click-through can be completed in under 90 seconds.

[ ] Cached fallback works.

---

# 22. IMPLEMENTATION ORDER

DO NOT build everything in one giant step.

## Phase 1 — Foundation

Build:
- repo structure
- FastAPI
- React
- environment configuration
- Pydantic models
- API skeleton
- Firebase initialization

Verify:
- backend starts
- frontend starts
- Firebase connection works

## Phase 2 — Authentication

Build:
- Firebase login
- token retrieval
- FastAPI token verification
- protected API routes

Verify:
Login -> authenticated API request -> successful response

## Phase 3 — Seeded repository

Create the five test cases.

Verify:
All intended cases are present and understandable.

## Phase 4 — Scanner

Implement Semgrep rules and dependency parser.

Verify:
Five target cases can be discovered.

## Phase 5 — Evidence normalization

Implement common finding model.

Verify:
Raw scanner output becomes normalized findings.

## Phase 6 — CBOM

Implement CycloneDX generation and validation.

Verify:
Valid cbom.json is produced.

## Phase 7 — Classification

Implement:
- artefact type
- lifetime
- criticality

Verify:
All findings receive expected classification.

## Phase 8 — Mosca

Implement X/Y/Z calculation and tiers.

Verify:
Overdue/transitional/low-risk cases are correctly categorized.

## Phase 9 — Recommendation

Implement deterministic recommendation engine.

Verify:
Recommendations are consistent and explainable.

## Phase 10 — Firebase persistence

Persist:
- scans
- findings
- summaries
- CBOM

Store CBOM/report files in Firebase Storage.

## Phase 11 — Dashboard

Build:
- login
- scan
- findings
- detail
- export

## Phase 12 — Integration

Run:

LOGIN
 -> SCAN
 -> DISCOVERY
 -> EVIDENCE
 -> CBOM
 -> CLASSIFY
 -> MOSCA
 -> RECOMMEND
 -> FIREBASE
 -> DASHBOARD
 -> EXPORT

## Phase 13 — Demo hardening

- performance test
- deterministic scan test
- fallback test
- UI cleanup
- error handling
- final 90-second rehearsal

---

# 23. DEMO PRESENTATION FLOW

Target: under 90 seconds.

0–10 sec:
Login -> Dashboard

10–25 sec:
Click Scan -> show real scan progress

25–40 sec:
Show findings table and risk distribution

40–65 sec:
Open overdue RSA finding:
Evidence
 -> classification
 -> X/Y/Z
 -> Mosca inequality
 -> recommendation

65–80 sec:
Open low-risk finding:
Show that ECDAT does not classify everything as urgent.

80–90 sec:
Export CBOM.

Core message:

> Blindspot doesn't just find cryptography. It connects discovery to migration urgency and an actionable PQC recommendation.

---

# 24. THINGS TO AVOID

Do NOT spend demo time implementing:

- binary scanning
- container scanning
- live TLS scanning
- HSM/PKCS#11
- cloud KMS discovery
- network packet capture
- Kubernetes
- microservices
- Redis/Celery
- GraphQL
- Postgres
- ML
- advanced RBAC
- multi-organization support
- enterprise trend analytics
- dedicated graph database

These are outside the demo.

Do not build a static frontend with fake backend responses.

Do not hard-code the entire findings table.

The scanner -> analysis -> persistence -> dashboard path must actually work.

---

# 25. KIRO WORKING RULES

Use Kiro/Opus incrementally.

Do NOT give it a vague:
"Build ECDAT."

Instead:
- give one phase at a time
- require tests after each phase
- require it to inspect the existing implementation before modifying it
- do not allow unnecessary dependencies
- preserve module boundaries
- do not silently expand scope
- report blockers before making major architectural changes

When a phase is complete:
1. Run tests.
2. Run the application.
3. Verify the phase manually.
4. Only then move to the next phase.

---

# 26. INITIAL KIRO BUILD PROMPT

Use this as the FIRST prompt to Kiro/Opus.

---

You are the lead engineer building the Blindspot ECDAT demo for SIH 2026 Problem Statement 26164.

Read this entire specification before making changes.

We are building a REAL working demo, not a static mockup.

The demo must implement this end-to-end pipeline:

LOGIN
-> PROJECT
-> SCAN
-> SEMGREP SOURCE/DEPENDENCY DISCOVERY
-> EVIDENCE EXTRACTION
-> NORMALIZED CRYPTO FINDINGS
-> CYCLONEDX CBOM
-> CLASSIFICATION
-> MOSCA RISK ANALYSIS
-> RISK TIER
-> PQC/HYBRID RECOMMENDATION
-> FIREBASE FIRESTORE/STORAGE
-> REACT DASHBOARD
-> CBOM EXPORT

IMPORTANT CONSTRAINTS:

1. This is the DEMO scope only. Do not implement full enterprise features.
2. Firebase is the required authentication, database, and file storage platform.
3. Backend is Python 3.11+ with FastAPI.
4. Frontend is React + TypeScript + Tailwind + Recharts.
5. Source scanning uses Semgrep custom rules.
6. Dependency parsing can use Python parsers.
7. CBOM uses CycloneDX/cyclonedx-python-lib.
8. Do not add Postgres, Redis, Celery, Kubernetes, GraphQL, microservices, or unrelated infrastructure.
9. Keep the backend modular even though it is one FastAPI process.
10. Do not create fake/static findings as the primary implementation.
11. All five seeded demo cases must eventually be detected through the real pipeline.
12. Use environment variables/secrets correctly. Never commit Firebase credentials.
13. Write tests as you implement each phase.
14. Do not silently change the architecture or scope. If something is genuinely blocked, explain the blocker.

FIRST TASK — PHASE 1 ONLY:

Set up the project foundation.

Create:

backend/
frontend/

Backend:
- FastAPI application
- configuration system
- Pydantic models
- API structure
- scanner/cbom/classifier/risk/recommend/firebase module structure
- health endpoint
- requirements.txt
- .env.example
- appropriate .gitignore

Frontend:
- React + TypeScript
- Tailwind
- routing
- Firebase client initialization structure
- API client structure
- basic application shell

Firebase:
- prepare Firebase Admin SDK integration structure on backend
- prepare Firebase Web SDK integration structure on frontend
- do not hard-code credentials
- create clear environment variable documentation

Create the following initial API structure:

POST /scan
GET /findings
GET /findings/{id}
GET /export/cbom

For now these can return clearly marked placeholder responses, because this phase is only the foundation.

Create basic automated tests for:
- backend startup
- health endpoint
- model validation
- frontend build

Do NOT implement Semgrep, CBOM, Mosca, recommendations, or the full dashboard in this phase.

At the end:
1. Run backend tests.
2. Run frontend build/tests.
3. Verify both applications start.
4. Report exactly what was created.
5. Report any errors.
6. Do not move to Phase 2 until Phase 1 is working.

Do not ask me broad architectural questions unless a decision is impossible from this specification. Make reasonable implementation decisions within the stated constraints.

---

# 27. AFTER PHASE 1

Use separate prompts for each subsequent phase rather than one giant prompt.

Recommended sequence:

PHASE 2:
Firebase Authentication

PHASE 3:
Seeded Repository

PHASE 4:
Semgrep Scanner

PHASE 5:
Evidence + Normalization

PHASE 6:
CBOM

PHASE 7:
Classification

PHASE 8:
Mosca Risk Engine

PHASE 9:
Recommendation Engine

PHASE 10:
Firebase Persistence

PHASE 11:
Dashboard

PHASE 12:
Full Integration

PHASE 13:
Testing + Demo Hardening

The most important rule:

> **Never move forward while the current phase is broken.**

---

# 28. FINAL DEMO SUCCESS CONDITION

A judge should be able to see:

A real source repository
 -> real cryptographic detection
 -> real evidence
 -> real CBOM
 -> real classification
 -> real Mosca calculation
 -> real risk tier
 -> real PQC/hybrid recommendation
 -> persisted result
 -> interactive visualization
 -> standardized CBOM export

That is the Blindspot ECDAT demo.
