# ECDAT — Master Requirements & Strategy

**Enterprise Cryptographic Discovery & Analysis Tool · SIH 2026 · Problem Statement 26164**

This is the single authoritative document for the full production platform. It merges the
formal requirements spec with the competitive/differentiation strategy. It supersedes
`STRATEGY.md`. Positioning first, then formal requirements (EARS style), then roadmap.

---

## 0. Positioning — why we win

> **Competitors build a cryptography *scanner* — a tool that tells you what crypto you have.
> ECDAT is a cryptography *migration decision platform* — it finds your crypto, then plans the
> transition with architectural, business, and regulatory context, and keeps watching.**

Judge-facing one-liner:

> "Others hand you a list of your cryptography. ECDAT hands you a costed, prioritized,
> compliance-mapped migration plan — and stops new quantum-risk from entering your code.
> Discovery is where they stop; it's where we start."

### The market gap we exploit (research-backed)
- Existing CBOMs are inventory-derived and *"lack architectural intent, rationale, and security
  context, limiting their usefulness for migration planning."* (arXiv 2603.22442)
- *"No single scanning tool covers all surfaces."* (quantumsecuritydefence.com)
- Platforms that combine *"discovery, policy, and change orchestration"* save the most time —
  discovery alone is not enough. (startupstash.com)
- Research scanners sit around F1 0.75 — accuracy/false-certainty is an open problem.
  (arXiv 2608.04857)
- The IETF CADI lifecycle has 6 phases (Awareness, Discovery, **Risk Assessment & Planning,
  Migration Execution, Testing, Validation & Monitoring**); tools mostly stop at Discovery.

Existing tools we differentiate from: IBM CBOMkit / Quantum Safe Explorer (Linux Foundation /
PQCA), CZERTAINLY CBOM-Lens, Encryption Consulting CBOM Secure, QScout, AppViewX, Keyfactor.

### Rules
- Do NOT try to out-scan IBM on discovery breadth. Cover surfaces "good enough"; spend real
  effort on the differentiators (Part C).
- No gimmicks (chatbots, gamification) — reads as unserious on a security PS.
- Every feature must map to a PS line (see §Alignment matrix).

*(Source content rephrased for compliance with licensing restrictions.)*

---

## 1. Introduction

Organizations cannot migrate cryptography they cannot find. Cryptographic algorithms, keys,
certificates, and protocols are scattered across source code, binaries, third-party libraries,
container images, live endpoints, HSMs, and cloud KMS. Most is undocumented, and much is
quantum-vulnerable (RSA, ECC, classical DH). A CRQC will break these, and adversaries are
already harvesting long-lived encrypted data to decrypt later ("harvest-now-decrypt-later").

ECDAT discovers cryptographic assets across code and infrastructure, records evidence for every
finding, produces a standardized CycloneDX CBOM, assesses quantum-migration urgency with a
configurable Mosca-inequality risk engine, produces cost- and latency-aware PQC/hybrid
recommendations, and — its hero capability — **produces a prioritized, costed migration
roadmap** and **continuously guards against new quantum-risk**.

### Who it is for
- Security engineers / cryptography owners maintaining a crypto inventory.
- Compliance/risk officers demonstrating progress against national PQC deadlines.
- Platform teams sequencing the actual migration.
- National critical-infrastructure operators (SIH 2026 PS26164 sponsoring context: NTRO/NCIIPC).

### Regulatory drivers (these are the configurable "Z" values)
- **India** — DST / National Quantum Mission PQC roadmap and NCIIPC guidance (CII 2027/2028/2029).
- **United States** — NIST IR 8547 (deprecate ~2030, disallow ~2035); FIPS 203 (ML-KEM),
  FIPS 204 (ML-DSA), SP 800-57; SP 1800-38 (NCCoE).
- **EU** — coordinated PQC transition timelines.

### Relationship to the existing demo
A verified demo exists (127 backend tests, 18 frontend tests passing): source + dependency
scanning, CycloneDX 1.6 CBOM, classification with confidentiality-vs-authenticity split and
trust-anchor escalation, configurable-Z Mosca engine, deterministic recommendation engine, and
a React GUI, with Firebase wired (AUTH_DISABLED locally). This document specifies the **full
production platform** that retains that proven pipeline and closes its gaps.

---

## 2. Tech stack & deployment decision (SETTLED)

**The PS mandates no tech stack, database, or deployment model.** It is outcome-based. Therefore:

- **Confirmed stack:** Frontend on **Vercel** (React + TypeScript + Tailwind + Recharts).
  Backend + async worker on **Railway** (Python + FastAPI). Auth, database, storage on
  **Firebase** (Authentication, Firestore, Cloud Storage). Discovery via Semgrep custom rules.
  CBOM via CycloneDX / cyclonedx-python-lib.
- **Air-gap posture:** on-prem/air-gapped operation is NOT a PS requirement — it is an inferred
  positioning point for the national-infra context. We therefore adopt an **air-gap-READY
  architecture** (swappable persistence + auth behind interfaces) and *claim* on-prem/air-gap
  capability in the pitch, while shipping the cloud stack for build speed and a clickable demo.
- **Consequence:** requirements that originally assumed PostgreSQL/MinIO/mandatory-air-gap are
  reframed for Firebase + cloud with air-gap-readiness as a design goal (see Req 11, Req 15).

---

## 3. Glossary

- **ECDAT** — the platform as a whole.
- **Discovery_Engine** — locates crypto assets across scan targets.
  - **Source_Scanner** (Semgrep), **Dependency_Scanner** (manifests), **Binary_Scanner**,
    **Container_Scanner**, **Network_Scanner** (live TLS), **Hardware_Scanner** (PKCS#11/HSM),
    **Cloud_Scanner** (cloud KMS).
- **Evidence_Extractor** — records location, snippet/observation, detection method, confidence.
- **Finding** — normalized record of one discovered asset + evidence + resolved/unresolved params.
- **CBOM_Builder / CBOM** — CycloneDX 1.6 Cryptography Bill of Materials.
- **Classifier** — tags artefact type, data lifetime, criticality, exposure, quantum-risk level.
- **Risk_Engine** — evaluates Mosca X + Y > Z, assigns Risk_Tier.
- **Recommender** — maps findings to strategy + algorithm, optimizing security/latency/cost.
- **Migration_Planner** — sequences and costs the migration into ordered waves. *(HERO)*
- **Continuous_Monitor** — CI/CD guardrail that re-scans on change and blocks new quantum-risk.
- **Compliance_Engine** — evaluates findings vs regulatory-deadline presets + sensitivity analysis.
- **Agility_Scorer** — scores how easily each finding's crypto can be changed.
- **Report_Generator** — inventory/risk/recommendation reports.
- **GUI** — React/TypeScript web interface.
- **Auth_Service** — authentication + RBAC (Firebase Auth + roles).
- **Job_Queue** — async job execution (Firestore-backed state + Railway worker).
- **Persistence_Layer** — Firestore (records) + Firebase Storage (artefacts), behind a swappable
  interface (air-gap-ready).
- **X / Y / Z** — data secrecy lifetime / migration time / quantum-regulatory horizon (years).
- **Risk_Tier** — `overdue` | `transitional` | `low-risk`.
- **PQC / Hybrid** — post-quantum (ML-KEM/ML-DSA) / classical+PQC combined mechanism.
- **HNDL** — Harvest-Now-Decrypt-Later exposure.
- **Trust_Anchor** — long-lived authenticity asset (root CA, code-signing, firmware-signing).
- **Exposure** — internal-facing or external-facing.
- **Confidence** — `high` | `medium` | `low` certainty of resolved parameters.
- **Air_Gap_Ready** — architecture that can run without outbound internet by swapping the
  Persistence_Layer and Auth_Service implementations.

---

## Part A — Core Functional Requirements (Expected Outcomes 1–7)

### Requirement 1: Multi-Target Cryptographic Discovery
**User Story:** As a security engineer, I want ECDAT to scan source repositories, binaries,
libraries, and container images, so that no cryptographic asset is missed.

1. WHEN a source repository is submitted, THE Source_Scanner SHALL analyze it with Semgrep custom rules and produce Findings.
2. WHEN a dependency manifest/lockfile is present, THE Dependency_Scanner SHALL parse it and produce a Finding per cryptographic library with resolved version.
3. WHEN a compiled binary/shared library is submitted, THE Binary_Scanner SHALL analyze it and produce a Finding per detected algorithm or embedded library.
4. WHEN a container image reference is submitted, THE Container_Scanner SHALL analyze each layer and produce Findings for that layer.
5. WHERE a target contains an unsupported format, THE Discovery_Engine SHALL record it as `skipped` with a reason.
6. THE Discovery_Engine SHALL associate every Finding with the scan-target identifier and producing scanner.
7. WHEN a scan target is submitted as a **GitHub/GitLab repository URL**, THE Source_Scanner SHALL shallow-clone the repository into an ephemeral working directory, scan it, and delete the clone on completion (success or failure).
8. WHERE a repository URL is submitted, THE Discovery_Engine SHALL validate the URL (HTTPS only, host allowlist, reject internal addresses) before cloning. *(SSRF protection)*

### Requirement 2: Live Environment and Key-Store Discovery
**User Story:** As a platform engineer, I want ECDAT to discover cryptography in running systems,
hardware modules, and cloud key stores.

1. WHEN a live TLS endpoint is submitted, THE Network_Scanner SHALL record negotiated protocol, cipher suite, key-exchange group, and certificate chain as Findings.
2. WHEN a certificate is inspected, THE Network_Scanner SHALL record signature algorithm, public-key algorithm, key size, validity period, and issuer.
3. WHERE a PKCS#11/HSM interface is configured, THE Hardware_Scanner SHALL enumerate accessible key objects and record key type and size.
4. WHERE a cloud KMS is configured, THE Cloud_Scanner SHALL enumerate managed keys and record algorithm, key size, and rotation configuration.
5. IF a live target is unreachable within the timeout, THEN THE Network_Scanner SHALL record it as `unreachable` and continue.
6. WHERE ECDAT runs Air_Gap_Ready with no outbound internet, live/cloud scanners SHALL scan only endpoints reachable within the isolated network.

### Requirement 3: Automated Identification and Classification of Artefacts
1. THE Discovery_Engine SHALL detect at minimum: RSA, ECC, ECDSA, ECDH, Diffie-Hellman, AES, DES, 3DES, MD5, SHA-1, SHA-2.
2. WHERE a parameter is resolvable, THE Discovery_Engine SHALL record algorithm name, key size, mode, and usage.
3. WHEN a library is identified, THE Discovery_Engine SHALL record library name and resolved version.
4. THE Discovery_Engine SHALL record each Finding's artefact category among key, certificate, protocol, algorithm, library.
5. WHEN a protocol is detected, THE Discovery_Engine SHALL record protocol name and version.

### Requirement 4: Standardized CBOM Generation
1. WHEN discovery/normalization completes, THE CBOM_Builder SHALL convert every Finding into a CycloneDX 1.6 cryptographic-asset component.
2. THE CBOM_Builder SHALL populate at minimum `bom-ref`, asset type, primitive, algorithm/parameter identifier, key size or mode where resolved, and `evidence.occurrences`.
3. WHEN a CBOM is generated, it SHALL pass CycloneDX 1.6 schema validation.
4. THE CBOM_Builder SHALL persist the CBOM to the Persistence_Layer (Firebase Storage) keyed by scan id.
5. WHEN a user requests export, THE ECDAT SHALL return the persisted CBOM as a downloadable file.

### Requirement 5: Quantum-Risk Assessment via Structured Framework (Mosca)
1. WHEN a Finding is assessed, THE Risk_Engine SHALL evaluate X + Y > Z using resolved X, configured Y, active Z.
2. THE Risk_Engine SHALL record X, Y, Z, the inequality expression, and the boolean result.
3. WHEN the result is available, THE Risk_Engine SHALL assign Risk_Tier `overdue` | `transitional` | `low-risk`.
4. THE Risk_Engine SHALL support selecting active Z from configurable horizon sources (CRQC estimate + named regulatory deadlines).
5. WHERE X cannot be resolved, THE Risk_Engine SHALL use the configured default X for the sensitivity class and mark the comparison as default-derived.

### Requirement 6: Classification by Type, Lifetime, Criticality, Quantum-Risk
1. THE Classifier SHALL assign artefact type among key-exchange, signature, encryption, hash.
2. THE Classifier SHALL assign a data lifetime in years (X).
3. THE Classifier SHALL assign business criticality `low` | `medium` | `high`.
4. THE Classifier SHALL assign a quantum-risk level derived from Risk_Tier.
5. WHERE a Finding is key-exchange or encryption, THE Classifier SHALL score quantum risk against data lifetime (confidentiality basis).
6. WHERE a Finding is a signature, THE Classifier SHALL score on authenticity basis, unless flagged Trust_Anchor.

### Requirement 7: Risk-Based PQC and Hybrid Recommendations
1. WHEN Risk_Tier is `overdue`, THE Recommender SHALL recommend Pure PQC.
2. WHEN `transitional`, THE Recommender SHALL recommend Hybrid.
3. WHEN `low-risk`, THE Recommender SHALL recommend Defer.
4. WHEN a key-exchange Finding needs migration, THE Recommender SHALL name an ML-KEM parameter set.
5. WHEN a signature Finding needs migration, THE Recommender SHALL name an ML-DSA parameter set.
6. WHEN Hybrid is recommended, THE Recommender SHALL name both classical and PQC components.
7. THE Recommender SHALL derive target NIST security category from the Finding's own resolved parameter (FIPS 203/204, SP 800-57).
8. THE Recommender SHALL include a human-readable rationale per recommendation.

### Requirement 8: Standardized Reporting
1. WHEN a report is requested, THE Report_Generator SHALL produce complete inventory, resolved config, assessed risks, and recommended alternatives.
2. THE Report_Generator SHALL produce a machine-readable (JSON) and a human-readable report.
3. THE Report_Generator SHALL include scan id, target set, and active Z horizon source.
4. WHEN referencing a Finding, THE Report_Generator SHALL include its evidence location.

### Requirement 9: Interactive GUI
1. THE GUI SHALL let an authenticated user trigger a scan against a selected target (including by repo URL).
2. THE GUI SHALL display a findings dashboard with per-Risk_Tier counts and a filterable list.
3. WHEN a Finding is selected, THE GUI SHALL display evidence, classification, the Mosca X/Y/Z calculation and inequality, and the recommendation.
4. THE GUI SHALL provide a visible CBOM export action.
5. WHILE a scan runs, THE GUI SHALL display status and progress.

---

## Part B — Platform & Deployment Requirements

### Requirement 10: Authentication and Role-Based Access Control
1. WHEN a protected operation is requested without a valid session, THE Auth_Service SHALL reject it as unauthorized.
2. WHEN a user authenticates validly (Firebase Auth), THE Auth_Service SHALL establish a session and record identity.
3. THE Auth_Service SHALL enforce RBAC with at minimum administrator, analyst, viewer (Firebase custom claims).
4. IF a viewer requests a scan-triggering operation, THEN THE Auth_Service SHALL reject it as forbidden.
5. WHEN an administrator assigns a role, THE Auth_Service SHALL apply it to subsequent authorization.

### Requirement 11: Persistent Storage of Scans, Findings, and Artefacts *(cloud/Firebase)*
1. WHEN a scan completes, THE Persistence_Layer SHALL store the scan record, Findings, and summary in **Firestore**.
2. WHEN a CBOM/report is generated, THE Persistence_Layer SHALL store the file in **Firebase Storage** keyed by scan id.
3. WHEN a previously completed scan is requested, THE ECDAT SHALL retrieve the scan, Findings, and artefacts.
4. THE Persistence_Layer SHALL retain stored scans until an administrator deletes them.
5. WHEN the same target is scanned repeatedly, THE Persistence_Layer SHALL store each scan as a distinct record under a common target id.
6. THE Persistence_Layer SHALL be accessed through a swappable interface so that an on-prem/air-gapped build can substitute a self-hosted store without changing pipeline code. *(air-gap-ready)*

### Requirement 12: Asynchronous Job Execution for Long-Running Scans
1. WHEN a scan is triggered, THE Job_Queue SHALL enqueue it as an async job and return a scan id immediately.
2. WHILE a job executes, THE Job_Queue SHALL expose status `queued` | `running` | `completed` | `failed` (state in Firestore).
3. WHEN a user queries status, THE ECDAT SHALL return current status and, while running, progress.
4. IF a job fails, THEN THE Job_Queue SHALL record the reason and set status `failed`.
5. WHEN a job completes, THE Job_Queue SHALL persist results before setting status `completed`.
6. THE scan worker SHALL run as a **separate Railway service** consuming jobs from Firestore.

### Requirement 13: Trend-Over-Time Views
1. WHEN two or more scans exist for a target, THE ECDAT SHALL compute the change in Finding count per Risk_Tier between selected scans.
2. THE GUI SHALL display a trend view of per-Risk_Tier counts across a target's scan history.
3. WHEN a user selects a time range, THE ECDAT SHALL restrict the trend to that range.

### Requirement 14: Dependency-Graph Visualization
1. WHEN a scan includes dependency Findings, THE ECDAT SHALL construct a dependency graph relating each crypto Finding to the component that introduced it.
2. THE GUI SHALL render the graph and visually distinguish direct from transitive dependencies.
3. WHEN a user selects a node, THE GUI SHALL display that node's Findings.
4. THE dependency graph SHALL expose a per-Finding **blast radius** (count of dependent components) consumed by the Migration_Planner (Req 16).

### Requirement 15: Cloud Deployment with Air-Gap-Ready Architecture
1. THE ECDAT frontend SHALL deploy to Vercel; the backend and worker SHALL deploy to Railway; auth/DB/storage SHALL use Firebase.
2. THE backend container image SHALL include `git` for repository-URL cloning.
3. THE ECDAT SHALL isolate Persistence_Layer and Auth_Service behind interfaces so a self-contained, containerized on-prem/air-gapped build is possible without changing pipeline code. *(air-gap-ready, not required for the cloud build)*
4. WHERE ECDAT runs on-prem/air-gapped, it SHALL bundle reference data (regulatory presets, detection rules) and SHALL NOT require outbound internet to complete the pipeline.
5. THE ECDAT SHALL NOT transmit scan Findings to any endpoint other than the configured Persistence_Layer.

---

## Part C — Differentiating Requirements (Uniqueness / Selection Criteria)

These define what ECDAT does that IBM CBOMkit, CZERTAINLY CBOM-Lens, AppViewX, and commercial
PQC scanners do NOT. **Requirement 16 is the hero.**

### Requirement 16: Migration Roadmap — Prioritized, Costed, Sequenced Plan  ★ HERO
**User Story:** As a cryptography owner, I want ECDAT to turn findings into a sequenced, costed
migration plan, so that I know what to fix first, at what cost, in what order — not just a list.

1. WHEN a scan's findings are risk-assessed, THE Migration_Planner SHALL compute a priority score per Finding from Risk_Tier urgency, business criticality, and dependency blast radius (Req 14).
2. THE Migration_Planner SHALL group findings into ordered migration waves (e.g., Wave 1 = overdue + critical + high blast radius; later waves = transitional; deferred = low-risk).
3. THE Migration_Planner SHALL assign each wave item a current→target algorithm, effort estimate (`low`|`medium`|`high`), and relative cost basis.
4. WHERE a Finding is currently weak today (e.g., MD5/SHA-1/DES/3DES), THE Migration_Planner SHALL place it on a separate immediate-remediation track distinct from the quantum-migration waves.
5. THE Migration_Planner SHALL produce a human-readable rationale for each wave's ordering.
6. THE GUI SHALL render the roadmap as sequenced waves, and THE Report_Generator SHALL include it in reports.
7. THE Migration_Planner SHALL be deterministic: the same findings and configuration SHALL yield the same roadmap.

### Requirement 17: Continuous Monitoring & CI/CD Guardrail
**User Story:** As a security engineer, I want ECDAT to re-scan on every code change and block new
quantum-vulnerable cryptography, so that the inventory stays current and risk cannot re-enter.

1. THE ECDAT SHALL expose a CI/CD integration (e.g., GitHub Action / webhook) that triggers a scan on a repository change event.
2. WHEN a CI/CD-triggered scan detects a newly introduced Finding whose Risk_Tier is `overdue` (or a currently-weak algorithm), THE Continuous_Monitor SHALL return a non-zero/failing status to the pipeline.
3. THE Continuous_Monitor SHALL report which specific Findings caused a failure, with evidence locations.
4. WHERE a change introduces no new disallowed cryptography, THE Continuous_Monitor SHALL return a passing status.
5. THE Continuous_Monitor SHALL support a configurable policy defining which Risk_Tiers/algorithms fail the build.

### Requirement 18: Jurisdiction-Aware Configurable-Z Compliance Engine with Sensitivity Analysis
1. THE Compliance_Engine SHALL provide named presets including India CII (2027/2028/2029), NIST IR 8547 (2030/2035), and a CRQC estimate.
2. WHEN a preset is selected, THE Compliance_Engine SHALL evaluate every Finding's Mosca inequality with that Z and report per-preset Risk_Tier counts.
3. WHEN sensitivity analysis is requested, THE Compliance_Engine SHALL report how each Finding's Risk_Tier changes across all configured Z presets.
4. THE Compliance_Engine SHALL identify, per Finding, the earliest preset under which it becomes `overdue`.
5. WHERE an administrator defines a custom deadline, THE Compliance_Engine SHALL include it in evaluation and sensitivity analysis.

### Requirement 19: Crypto-Agility Scoring with Non-Agile Code as a First-Class Finding
1. THE Agility_Scorer SHALL assign each source-code Finding a crypto-agility score reflecting replaceability.
2. WHEN an algorithm is invoked directly in business-logic code rather than through a crypto abstraction, THE Agility_Scorer SHALL classify the Finding non-agile.
3. WHEN a Finding is non-agile, THE Agility_Scorer SHALL emit a distinct crypto-agility Finding in the inventory.
4. THE Agility_Scorer SHALL report a per-scan aggregate crypto-agility score.
5. WHEN the same algorithm appears at multiple scattered locations, THE Agility_Scorer SHALL record the count of distinct locations as evidence.

### Requirement 20: Harvest-Now-Decrypt-Later Exposure Flagging
1. WHEN a confidentiality Finding's X + Y ≥ active Z, THE Risk_Engine SHALL flag it HNDL-exposed.
2. WHERE flagged HNDL-exposed, THE GUI SHALL display an HNDL indicator.
3. THE Report_Generator SHALL include a dedicated HNDL section per scan.
4. THE Risk_Engine SHALL apply HNDL flagging only to confidentiality Findings (key-exchange, encryption), not to non-Trust_Anchor signatures.

### Requirement 21: Confidentiality-vs-Authenticity Risk Split with Trust-Anchor Escalation
1. THE Classifier SHALL score confidentiality Findings against data lifetime and authenticity Findings on an authenticity basis.
2. WHEN a signature Finding is a root CA / code-signing / firmware-signing asset, THE Classifier SHALL flag it Trust_Anchor.
3. WHEN flagged Trust_Anchor, THE Risk_Engine SHALL escalate X to the configured long-lived value.
4. THE GUI SHALL visually distinguish confidentiality, authenticity, and Trust_Anchor Findings.

### Requirement 22: Honest-Uncertainty Confidence Scoring
1. THE Evidence_Extractor SHALL assign each Finding Confidence `high` | `medium` | `low` by detection method.
2. WHERE a parameter cannot be resolved, THE Discovery_Engine SHALL record it `unknown` rather than inferring.
3. WHEN a Finding has an unresolved parameter, THE GUI SHALL show it as unresolved with the Confidence.
4. WHEN Confidence is `low`, THE Report_Generator SHALL mark the Finding as requiring manual verification.
5. THE ECDAT SHALL NOT assign a definitive Risk_Tier from an inferred parameter; WHERE the tier depends on an unresolved parameter, THE Risk_Engine SHALL mark it provisional.

### Requirement 23: Cross-Tool Validation and CBOM Diff
1. WHEN a user provides an externally generated CycloneDX CBOM for a scanned target, THE ECDAT SHALL compare it against the ECDAT CBOM.
2. THE ECDAT SHALL report assets present in one CBOM but absent from the other, both directions.
3. WHEN comparing, THE ECDAT SHALL match components by algorithm, parameter, and evidence location.
4. THE Report_Generator SHALL include the comparison when an external CBOM is supplied.

### Requirement 24: Cost- and Latency-Aware Recommendation Optimization
1. THE Recommender SHALL associate each candidate PQC/hybrid algorithm with a latency profile and a cost profile.
2. WHERE a Finding is latency-sensitive, THE Recommender SHALL prefer the lower-latency candidate among those meeting the required security category.
3. WHEN multiple candidates meet the category, THE Recommender SHALL report the latency/cost tradeoff.
4. THE Recommender SHALL include the latency/cost basis in the rationale.
5. WHERE cost/latency data is unavailable, THE Recommender SHALL mark that dimension `unknown` rather than assuming.

### Requirement 25: Internal-vs-External-Facing Asset Tagging
1. THE Classifier SHALL assign each Finding Exposure internal-facing or external-facing.
2. WHERE a Finding originates from a live external endpoint scan, THE Classifier SHALL default to external-facing.
3. WHEN a user filters the dashboard by Exposure, THE GUI SHALL show only matching Findings.
4. THE Report_Generator SHALL report per-Exposure Risk_Tier counts.

---

## Non-Functional Requirements

### Requirement 26: Determinism and Reproducibility
1. WHEN the same unchanged target is scanned repeatedly with the same configuration, THE ECDAT SHALL produce equivalent Findings, Risk_Tiers, recommendations, and roadmap.
2. WHEN a CBOM is regenerated from the same Findings, THE CBOM_Builder SHALL produce an equivalent document.

### Requirement 27: Security of the Platform Itself
1. THE ECDAT SHALL require authentication for every operation that reads or modifies scan data.
2. WHEN storing credentials/secrets, THE ECDAT SHALL keep them outside version-controlled files and outside Findings data.
3. IF an unauthenticated request targets a protected endpoint, THEN THE Auth_Service SHALL reject it and record the rejection.
4. WHEN accepting a repository URL, THE ECDAT SHALL enforce SSRF protections (HTTPS-only, host allowlist, reject internal addresses) and clean up cloned repositories after each scan.

---

## 4. Build roadmap (phased)

**Phase 0 — Production spine:** GitHub-URL ingestion + SSRF (Req 1.7/1.8, 27.4) · async job model
(Req 12) · deploy pipeline Vercel+Railway+Firebase, git in image (Req 15).

**Phase 1 — Differentiator wave 1 (cheap, high alignment):** Compliance engine + presets (Req 18) ·
cost/latency recommendations (Req 24) · amplify confidence/honesty (Req 22).

**Phase 2 — Differentiator wave 2 (the wow):** ★ **Migration Roadmap (Req 16)** · dependency
graph + blast radius (Req 14) · HNDL flagging (Req 20).

**Phase 3 — Discovery breadth:** multi-language source rules (Java/JS/Go) · multi-ecosystem deps ·
certificates/X.509 · container scanning (Req 1, 2, 3). Binary/TLS/HSM/cloud as they land.

**Phase 4 — Continuous posture:** CI/CD guardrail (Req 17) · trend views (Req 13) · agility
scoring (Req 19).

**Phase 5 — Reporting + hardening:** report generation (Req 8) · RBAC (Req 10) · CBOM diff
(Req 23) · exposure tagging (Req 25) · determinism/security (Req 26/27) · polish.

---

## 5. PS26164 alignment matrix

| PS requirement | Covered by |
|----------------|-----------|
| (i) Catalogue algorithms, keys, certs, protocols, libraries, HW, cloud | Req 1–3 (discovery) |
| (ii) Quantum risk assessment, systems prone to attack | Req 5, 20 (Mosca, HNDL) |
| (iii) Classify by type/lifetime/criticality + Mosca | Req 5, 6, 18, 21 |
| (iv) Recommend PQC/Hybrid by risk, latency, cost | Req 7, 24 |
| Deliverable: standardised CBOM report | Req 4, 8, 23 |
| Deliverable: interactive GUI | Req 9, 13, 14 |
| Deliverable: scan repos/binaries/libraries/containers | Req 1 |
| Background: preparedness, financial/operational investment | ★ Req 16 (Migration Roadmap) |
| Continuous inventory (CADI lifecycle: monitoring) | Req 17 |

---

## 6. Research basis (sources)
- arXiv 2603.22442 — CBOMs lack migration usefulness (justifies Req 16 hero).
- arXiv 2608.04857 — "Hidden Ciphers and Where to Find Them"; scanner accuracy ~F1 0.75 (justifies Req 22).
- MDPI Electronics 2025 (QARS) — unified quantum risk assessment.
- IETF draft-liu-cadi — 6-phase discovery→monitoring lifecycle (justifies Req 17).
- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), IR 8547, SP 800-57 — target algorithms + deadlines.
- Reference tools: IBM CBOMkit (github.com/PQCA/cbomkit), IBM/CBOM, CZERTAINLY CBOM-Lens.

*(Source content rephrased for compliance with licensing restrictions.)*


---

## Part D — UI/UX & Experience Requirements (whole platform)

> **Guiding principle: "What gets noticed, gets sold."**
> The GUI is the first thing a judge or buyer experiences. Discovery/analysis is the engine;
> the interface is what earns attention and trust. Every screen — not just the hero ones — must
> feel considered, cohesive, and premium. A generic dark dashboard loses to a memorable one.

### Design ethos (applies to the entire platform)
- **One design language everywhere** — consistent color system, spacing scale, typography,
  iconography, and motion across every screen. No screen should look "unfinished" next to another.
- **Two signature visuals carry the story:** the **Migration Roadmap** and the **Dependency /
  Blast-Radius Graph**. These are what judges remember. They get the most design investment.
- **Show reasoning, not just results** — every risk score, tier, and recommendation is visually
  traceable to its inputs (X/Y/Z, confidence, evidence). Transparency is a design feature.
- **Honest states** — loading, empty, error, and "unresolved/low-confidence" are designed states,
  never blank screens or fake data.
- **Fast and legible** — a judge understands each screen in seconds: FOUND → WHY → RISK → WHAT TO DO.

### Requirement 28: Cohesive Platform Design System
1. THE GUI SHALL apply a single design system (color tokens, typography scale, spacing, iconography, motion) consistently across every screen.
2. THE GUI SHALL use fixed, distinct colors for risk tiers (overdue / transitional / low-risk) and for present-day-weak, applied identically everywhere they appear.
3. THE GUI SHALL provide a consistent application shell (navigation, header, user/context controls) shared by all authenticated views.
4. THE GUI SHALL maintain visual consistency between the public landing page, auth screens, and the authenticated application.
5. THE GUI SHALL be responsive across desktop and laptop breakpoints used for presentation and daily use.
6. THE GUI SHALL meet baseline accessibility (keyboard focus states, sufficient color contrast, semantic structure).

### Requirement 29: Migration Roadmap Visualization  ★ SIGNATURE SCREEN
1. THE GUI SHALL present the Migration Roadmap (Req 16) as a dedicated, prominent view, not a table buried in findings.
2. THE GUI SHALL render migration waves as an ordered, timeline-style sequence, visually distinguishing Wave 1 (urgent) from later waves and the deferred set.
3. THE GUI SHALL display, per wave item, the current→target algorithm, effort estimate, relative cost, and the ordering rationale.
4. THE GUI SHALL visually separate the immediate-remediation track (currently-weak crypto) from the quantum-migration waves.
5. WHEN a user selects a roadmap item, THE GUI SHALL link to the underlying Finding's detail (evidence, Mosca, recommendation).

### Requirement 30: Dependency / Blast-Radius Graph  ★ SIGNATURE VISUAL
1. THE GUI SHALL render the dependency graph (Req 14) as an interactive node-edge visualization.
2. THE GUI SHALL visually encode each node's risk tier and blast radius (e.g., size/color).
3. THE GUI SHALL distinguish direct from transitive dependencies visually.
4. WHEN a user selects a node, THE GUI SHALL display that node's associated Findings.

### Requirement 31: Compliance & Sensitivity View
1. THE GUI SHALL provide a regulatory-preset selector (India CII, NIST IR 8547, CRQC estimate, custom).
2. WHEN a preset is selected, THE GUI SHALL update per-tier counts to reflect that preset's Z.
3. THE GUI SHALL present the sensitivity analysis (Req 18) as a matrix showing how findings' tiers shift across Z presets.
4. THE GUI SHALL indicate, per finding, the earliest preset under which it becomes overdue.

### Requirement 32: Findings & Risk Experience
1. THE GUI SHALL present an overview dashboard with per-tier summary counts and the platform's key metrics.
2. THE GUI SHALL provide a filterable, searchable findings list (by tier, algorithm, exposure, confidence, HNDL).
3. WHEN a Finding is selected, THE GUI SHALL show evidence (file/line or observation), classification, the Mosca X/Y/Z math and inequality, and the recommendation, in one coherent view.
4. THE GUI SHALL display distinct indicators for HNDL exposure (Req 20), Trust_Anchor (Req 21), crypto-agility/non-agile (Req 19), confidence level and unresolved parameters (Req 22), and internal/external exposure (Req 25).
5. THE GUI SHALL make present-day-weak findings visually distinct from quantum-migration findings.

### Requirement 33: Scan Experience
1. THE GUI SHALL accept a repository URL (and, in dev, a local path) as the scan target, with clear input guidance.
2. WHILE a scan runs asynchronously, THE GUI SHALL display live status and stage/progress (Req 12), not a frozen screen.
3. WHEN a scan completes, THE GUI SHALL surface a result summary and route the user toward findings and the roadmap.
4. IF a scan fails, THE GUI SHALL display the failure reason and a retry path.

### Requirement 34: Reporting & Export Experience
1. THE GUI SHALL provide a clearly visible CBOM export action wherever findings are shown.
2. THE GUI SHALL allow generating and downloading the human-readable and machine-readable reports (Req 8).
3. WHERE a CBOM diff (Req 23) exists, THE GUI SHALL present the comparison in a readable side-by-side form.

### Requirement 35: Feedback, Empty, and Error States
1. THE GUI SHALL present a designed empty state (e.g., "no scan yet — start one") rather than a blank screen.
2. THE GUI SHALL present designed loading states during data fetches and scans.
3. THE GUI SHALL present actionable error states when the backend is unreachable or an operation fails.
4. THE GUI SHALL never display fabricated/sample findings as if they were real scan output.

### UI build sequencing (maps to the phase roadmap)
- **Phase 0:** shell + design system baseline (Req 28), scan experience with async progress (Req 33), honest states (Req 35).
- **Phase 1:** compliance & sensitivity view (Req 31), confidence/honesty indicators (Req 32.4).
- **Phase 2 (the wow):** ★ Migration Roadmap visualization (Req 29) + Dependency/Blast-Radius graph (Req 30) — built alongside their backends; these are the demo centerpiece.
- **Phase 3–5:** trends view, CBOM diff view (Req 34.3), agility/exposure indicators, reporting UI, final polish pass across every screen.

> Design debt is not deferred to "later." Each phase ships its screens at presentation quality —
> because what gets noticed, gets sold.
