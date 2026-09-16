# Requirements Document

## Introduction

### The Problem

Organizations cannot migrate cryptography they cannot find. Cryptographic algorithms, keys, certificates, and protocols are scattered across source code, compiled binaries, third-party libraries, container images, live network endpoints, hardware security modules, and cloud key management services. Most of this cryptography is undocumented, and much of it is quantum-vulnerable (RSA, ECC, classical Diffie-Hellman). A cryptographically relevant quantum computer (CRQC) will break these primitives, and adversaries are already harvesting encrypted long-lived data today to decrypt later ("harvest-now-decrypt-later"). Before any organization can plan a post-quantum migration, it must first produce a complete, evidence-backed inventory of where cryptography lives, how it is used, and how urgently each usage must be replaced.

ECDAT (Enterprise Cryptographic Discovery & Analysis Tool) is a single-tenant, on-premises, air-gap-installable platform that discovers cryptographic assets across an organization's code and running infrastructure, records evidence for every finding, produces a standardized CycloneDX Cryptography Bill of Materials (CBOM), assesses quantum-migration urgency using a configurable Mosca-inequality risk engine, and produces cost- and latency-aware post-quantum migration recommendations.

### Who It Is For

- **Security engineers and cryptography owners** who must produce and maintain a cryptographic inventory.
- **Compliance and risk officers** who must demonstrate progress against national PQC-migration mandates and jurisdiction-specific deadlines.
- **Platform and infrastructure teams** who must plan and sequence the actual migration of key-exchange, signature, and encryption mechanisms.
- **National critical-infrastructure operators** (the sponsoring context for SIH 2026 PS26164 is NTRO/NCIIPC) whose cryptographic weakness map is itself sensitive data that must never leave their network.

### What It Solves

ECDAT converts the intractable, manual problem of "find all our cryptography and tell us what to fix first" into a repeatable, evidence-backed, standards-compliant pipeline: discover -> record evidence -> normalize -> CBOM -> classify -> assess quantum risk -> recommend -> report -> visualize -> track over time.

### What Backs It (Regulatory Drivers)

Cryptographic inventory is now a hard requirement, not an optional exercise, because national migration mandates set explicit deadlines:

- **India** — The Department of Science & Technology (DST) / National Quantum Mission PQC roadmap and NCIIPC guidance set staged deadlines for critical information infrastructure (commonly referenced as CII 2027 / 2028 / 2029 milestones).
- **United States** — NIST IR 8547 (transition to PQC standards) sets deprecation around 2030 and disallowance around 2035; NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and SP 800-57 define the target algorithms and security categories; NIST SP 1800-38 (NCCoE) defines migration practice.
- **European Union** — Coordinated EU PQC transition timelines add further jurisdiction-specific deadlines.

These deadlines are exactly the configurable "Z" (quantum/regulatory horizon) values that ECDAT's risk engine evaluates.

### Relationship to the Existing Demo

A verified demo already exists (144 backend tests, 18 frontend tests passing) implementing source-code and dependency scanning, CycloneDX 1.6 CBOM generation, classification with confidentiality-vs-authenticity split and trust-anchor escalation, a configurable-Z Mosca risk engine across regulatory presets, a deterministic recommendation engine, and a React GUI, with Firebase wired but running AUTH_DISABLED locally. This document specifies the **full production platform**, which retains the demo's proven pipeline and closes its gaps: binary/container/live/hardware/cloud discovery, latency and cost modeling, real authentication and RBAC, PostgreSQL and object-storage persistence, an async job queue, trend and dependency-graph views, and air-gapped deployment — while elevating the platform's distinctive, competitor-differentiating capabilities to first-class requirements.

## Glossary

- **ECDAT**: The Enterprise Cryptographic Discovery & Analysis Tool platform as a whole; the top-level system.
- **Discovery_Engine**: The ECDAT subsystem responsible for locating cryptographic assets across scan targets (source, binary, container, live endpoint, hardware, cloud).
- **Source_Scanner**: The Discovery_Engine component that analyzes source code using Semgrep custom rules.
- **Dependency_Scanner**: The Discovery_Engine component that parses dependency manifests and lockfiles.
- **Binary_Scanner**: The Discovery_Engine component that analyzes compiled binaries and shared libraries.
- **Container_Scanner**: The Discovery_Engine component that analyzes container images layer by layer.
- **Network_Scanner**: The Discovery_Engine component that probes live TLS endpoints and inspects negotiated protocols, cipher suites, and certificates.
- **Hardware_Scanner**: The Discovery_Engine component that enumerates cryptographic material exposed through PKCS#11 / HSM interfaces.
- **Cloud_Scanner**: The Discovery_Engine component that enumerates keys and cryptographic configuration from cloud Key Management Services (KMS).
- **Evidence_Extractor**: The ECDAT component that records the evidence (location, snippet or observation, detection method, confidence) for each finding.
- **Finding**: A normalized record of one discovered cryptographic asset and its evidence, resolved parameters, and unresolved parameters.
- **CBOM_Builder**: The ECDAT component that converts findings into a CycloneDX Cryptography Bill of Materials.
- **CBOM**: A CycloneDX 1.6 Cryptography Bill of Materials document.
- **Classifier**: The ECDAT component that tags each finding with artefact type, data lifetime, business criticality, exposure, and quantum-risk level.
- **Risk_Engine**: The ECDAT component that evaluates Mosca's inequality (X + Y > Z) per finding and assigns a risk tier.
- **Recommender**: The ECDAT component that maps each finding to a migration strategy and specific algorithm, optimizing across security, latency, and cost.
- **Compliance_Engine**: The ECDAT component that evaluates findings against jurisdiction-specific regulatory deadline presets and performs sensitivity analysis on the horizon value.
- **Agility_Scorer**: The ECDAT component that scores how easily each finding's cryptography can be changed and flags non-agile cryptography as a first-class finding.
- **Report_Generator**: The ECDAT component that produces standardized inventory, risk, and recommendation reports.
- **GUI**: The ECDAT interactive web interface (React/TypeScript).
- **Auth_Service**: The ECDAT component that authenticates users and enforces role-based access control.
- **Job_Queue**: The ECDAT asynchronous job execution subsystem for long-running scans.
- **Persistence_Layer**: The ECDAT data store comprising a relational database (PostgreSQL) and object storage (MinIO or compatible).
- **X**: Data secrecy lifetime in years (how long the protected data must remain confidential or trusted).
- **Y**: Migration time in years (how long the organization needs to complete migration of the asset).
- **Z**: Quantum/regulatory horizon in years (when quantum-vulnerable cryptography must be gone, sourced from a CRQC estimate or a named regulatory deadline).
- **Risk_Tier**: One of `overdue`, `transitional`, or `low-risk`, derived from the Risk_Engine.
- **PQC**: Post-Quantum Cryptography (e.g., ML-KEM per FIPS 203, ML-DSA per FIPS 204).
- **Hybrid**: A combined classical-plus-PQC mechanism (e.g., X25519 + ML-KEM-768 per RFC 10024/9370).
- **HNDL**: Harvest-Now-Decrypt-Later exposure.
- **Trust_Anchor**: A long-lived authenticity asset such as a root CA, code-signing key, or firmware-signing key.
- **Exposure**: Whether an asset is internal-facing or external-facing.
- **Confidence**: A qualitative measure (`high`, `medium`, `low`) of how certain a Finding's resolved parameters are.
- **Air_Gapped_Deployment**: An ECDAT installation that operates with no outbound network connectivity.

---

## Requirements

## Part A — Core Functional Requirements (Expected Outcomes 1–7)

### Requirement 1: Multi-Target Cryptographic Discovery (Expected Outcome 1)

**User Story:** As a security engineer, I want ECDAT to scan source repositories, compiled binaries, libraries, and container images, so that no cryptographic asset is missed regardless of the artefact form it takes.

#### Acceptance Criteria

1. WHEN a source repository is submitted as a scan target, THE Source_Scanner SHALL analyze the source code using Semgrep custom rules and produce Findings.
2. WHEN a dependency manifest or lockfile is present in a scan target, THE Dependency_Scanner SHALL parse the manifest and produce a Finding for each cryptographic library, including the resolved version identifier.
3. WHEN a compiled binary or shared library is submitted as a scan target, THE Binary_Scanner SHALL analyze the binary and produce a Finding for each detected cryptographic algorithm or embedded cryptographic library.
4. WHEN a container image reference is submitted as a scan target, THE Container_Scanner SHALL analyze each image layer and produce Findings for cryptographic assets discovered in that layer.
5. WHERE a scan target contains a file format that no scanner supports, THE Discovery_Engine SHALL record the unsupported target with a `skipped` status and a reason string.
6. THE Discovery_Engine SHALL associate every Finding with the scan target identifier and the scanner component that produced the Finding.

### Requirement 2: Live Environment and Key-Store Discovery (Expected Outcome 1, gap closure)

**User Story:** As a platform engineer, I want ECDAT to discover cryptography in running systems, hardware modules, and cloud key stores, so that the inventory reflects what is actually in use, not only what is in code.

#### Acceptance Criteria

1. WHEN a live TLS endpoint is submitted as a scan target, THE Network_Scanner SHALL record the negotiated protocol version, cipher suite, key-exchange group, and presented certificate chain as Findings.
2. WHEN a presented certificate is inspected, THE Network_Scanner SHALL record the signature algorithm, public-key algorithm, key size, validity period, and issuer as Finding parameters.
3. WHERE a PKCS#11 or HSM interface is configured as a scan target, THE Hardware_Scanner SHALL enumerate the accessible key objects and record the key type and key size for each as Findings.
4. WHERE a cloud KMS is configured as a scan target, THE Cloud_Scanner SHALL enumerate the managed keys and record the key algorithm, key size, and rotation configuration as Findings.
5. IF a live scan target is unreachable within the configured connection timeout, THEN THE Network_Scanner SHALL record the target with an `unreachable` status and continue scanning remaining targets.
6. WHILE ECDAT operates in Air_Gapped_Deployment mode, THE Cloud_Scanner SHALL scan only cloud KMS endpoints that are reachable within the isolated network and SHALL NOT require internet connectivity to complete.

### Requirement 3: Automated Identification and Classification of Cryptographic Artefacts (Expected Outcome 2)

**User Story:** As a cryptography owner, I want ECDAT to identify the specific algorithms, keys, certificates, protocols, libraries, and implementations including versions and modes, so that I understand exactly what cryptography I have.

#### Acceptance Criteria

1. THE Discovery_Engine SHALL detect at minimum the following algorithm families: RSA, ECC, ECDSA, ECDH, Diffie-Hellman, AES, DES, 3DES, MD5, SHA-1, and SHA-2.
2. WHERE a cryptographic parameter is resolvable from the evidence, THE Discovery_Engine SHALL record the algorithm name, key size, mode of operation, and usage for the Finding.
3. WHEN a cryptographic library is identified, THE Discovery_Engine SHALL record the library name and the resolved version identifier.
4. THE Discovery_Engine SHALL record for each Finding the artefact category among key, certificate, protocol, algorithm, and library.
5. WHEN a protocol is detected, THE Discovery_Engine SHALL record the protocol name and version.

### Requirement 4: Standardized CBOM Generation (Expected Outcome 2 / Outcome 6)

**User Story:** As a compliance officer, I want ECDAT to produce a standards-compliant CBOM, so that the inventory is portable, tool-independent, and auditable.

#### Acceptance Criteria

1. WHEN the discovery and normalization stages complete for a scan, THE CBOM_Builder SHALL convert every Finding into a CycloneDX 1.6 cryptographic-asset component.
2. THE CBOM_Builder SHALL populate for each component at minimum the `bom-ref`, asset type, primitive, algorithm or parameter identifier, key size or mode where resolved, and `evidence.occurrences` including source location.
3. WHEN a CBOM is generated, THE CBOM_Builder SHALL produce a document that passes CycloneDX 1.6 schema validation.
4. THE CBOM_Builder SHALL persist the generated CBOM to the Persistence_Layer object store associated with the scan identifier.
5. WHEN a user requests CBOM export through the GUI, THE ECDAT SHALL return the persisted CBOM document as a downloadable file.

### Requirement 5: Quantum-Risk Assessment via Structured Framework (Expected Outcome 3)

**User Story:** As a risk officer, I want ECDAT to assess quantum-migration urgency using a structured framework based on data lifetime, migration time, and CRQC arrival, so that prioritization is defensible and transparent.

#### Acceptance Criteria

1. WHEN a Finding is assessed, THE Risk_Engine SHALL evaluate Mosca's inequality X + Y > Z using the Finding's resolved X, its configured Y, and the active Z value.
2. THE Risk_Engine SHALL record for each assessed Finding the X value, Y value, Z value, the evaluated inequality expression, and the boolean result.
3. WHEN the inequality result is available, THE Risk_Engine SHALL assign a Risk_Tier of `overdue`, `transitional`, or `low-risk`.
4. THE Risk_Engine SHALL support selecting the active Z value from a configurable set of horizon sources including a CRQC estimate and named regulatory deadlines.
5. WHERE a Finding's X parameter cannot be resolved, THE Risk_Engine SHALL use the configured default X for the Finding's data-sensitivity class and SHALL mark the Z-comparison as derived from a default.

### Requirement 6: Classification by Type, Lifetime, Criticality, and Quantum-Risk Level (Expected Outcome 4)

**User Story:** As a security engineer, I want each finding classified by artefact type, data lifetime, business criticality, and quantum-risk level, so that I can filter and prioritize the inventory.

#### Acceptance Criteria

1. THE Classifier SHALL assign each Finding an artefact type among key-exchange, signature, encryption, and hash.
2. THE Classifier SHALL assign each Finding a data lifetime in years (X).
3. THE Classifier SHALL assign each Finding a business criticality among `low`, `medium`, and `high`.
4. THE Classifier SHALL assign each Finding a quantum-risk level derived from the Risk_Engine Risk_Tier.
5. WHERE a Finding represents key-exchange or encryption, THE Classifier SHALL score quantum risk against data lifetime (confidentiality basis).
6. WHERE a Finding represents a signature, THE Classifier SHALL score quantum risk on an authenticity basis rather than a data-lifetime basis, unless the Finding is flagged as a Trust_Anchor.

### Requirement 7: Risk-Based PQC and Hybrid Recommendations (Expected Outcome 5)

**User Story:** As a cryptography owner, I want risk-based recommendations for PQC or hybrid alternatives that consider security, latency, cost, and application requirements, so that I receive an actionable and realistic migration plan.

#### Acceptance Criteria

1. WHEN a Finding has Risk_Tier `overdue`, THE Recommender SHALL recommend a Pure PQC strategy.
2. WHEN a Finding has Risk_Tier `transitional`, THE Recommender SHALL recommend a Hybrid strategy.
3. WHEN a Finding has Risk_Tier `low-risk`, THE Recommender SHALL recommend a Defer strategy.
4. WHEN a key-exchange Finding requires migration, THE Recommender SHALL recommend an ML-KEM parameter set and SHALL name the parameter set.
5. WHEN a signature Finding requires migration, THE Recommender SHALL recommend an ML-DSA parameter set and SHALL name the parameter set.
6. WHEN a Hybrid strategy is recommended, THE Recommender SHALL name both the classical and the PQC component of the hybrid mechanism.
7. THE Recommender SHALL derive the target NIST security category for each recommendation from that Finding's own resolved parameter, consistent with FIPS 203, FIPS 204, and SP 800-57.
8. THE Recommender SHALL include a human-readable rationale string for each recommendation.

### Requirement 8: Standardized Reporting (Expected Outcome 6)

**User Story:** As a compliance officer, I want standardized reports covering the complete inventory, configurations, risks, and recommended alternatives, so that I can present migration status to auditors and leadership.

#### Acceptance Criteria

1. WHEN a report is requested for a completed scan, THE Report_Generator SHALL produce a report containing the complete Finding inventory, the resolved configuration parameters, the assessed risks, and the recommended alternatives.
2. THE Report_Generator SHALL produce a machine-readable report in a structured format (JSON) and a human-readable report suitable for non-technical stakeholders.
3. THE Report_Generator SHALL include in each report the scan identifier, the target set, and the active Z horizon source used for the assessment.
4. WHEN a report references a Finding, THE Report_Generator SHALL include the Finding's evidence location.

### Requirement 9: Interactive GUI (Expected Outcome 7)

**User Story:** As a security engineer, I want an interactive graphical interface, so that I can trigger scans, browse findings, drill into evidence and reasoning, and export reports.

#### Acceptance Criteria

1. THE GUI SHALL allow an authenticated user to trigger a scan against a selected target.
2. THE GUI SHALL display a findings dashboard showing per-Risk_Tier counts and a filterable findings list.
3. WHEN a user selects a Finding, THE GUI SHALL display the Finding's evidence, classification, Risk_Engine calculation including the X, Y, and Z values and the inequality, and the recommendation.
4. THE GUI SHALL provide a visible action to export the CBOM for the current scan.
5. WHILE a scan is running, THE GUI SHALL display the scan status and progress.

---

## Part B — Platform and Deployment Requirements (Gap Closure)

### Requirement 10: Authentication and Role-Based Access Control

**User Story:** As a platform administrator, I want real authentication and role-based access control, so that only authorized users can run scans and view the organization's cryptographic weaknesses.

#### Acceptance Criteria

1. WHEN a user requests a protected ECDAT operation without a valid authenticated session, THE Auth_Service SHALL reject the request with an unauthorized response.
2. WHEN a user authenticates with valid credentials, THE Auth_Service SHALL establish an authenticated session and record the user identity.
3. THE Auth_Service SHALL enforce role-based access control with at minimum the roles administrator, analyst, and viewer.
4. IF a user holding the viewer role requests a scan-triggering operation, THEN THE Auth_Service SHALL reject the request with a forbidden response.
5. WHEN an administrator assigns a role to a user, THE Auth_Service SHALL apply the assigned role to that user's subsequent authorization decisions.

### Requirement 11: Persistent Storage of Scans, Findings, and Artefacts

**User Story:** As a security engineer, I want scans, findings, and generated artefacts persisted durably, so that results survive restarts and can be queried and compared over time.

#### Acceptance Criteria

1. WHEN a scan completes, THE Persistence_Layer SHALL store the scan record, its Findings, and its summary in the relational database.
2. WHEN a CBOM or report file is generated, THE Persistence_Layer SHALL store the file in the object store keyed by the scan identifier.
3. WHEN a user requests a previously completed scan, THE ECDAT SHALL retrieve the stored scan, its Findings, and its artefacts from the Persistence_Layer.
4. THE Persistence_Layer SHALL retain stored scans until an administrator deletes them.
5. WHEN the same target is scanned more than once, THE Persistence_Layer SHALL store each scan as a distinct record associated with a common target identifier.

### Requirement 12: Asynchronous Job Execution for Long-Running Scans

**User Story:** As a security engineer, I want long-running scans to execute asynchronously, so that the interface stays responsive and large targets can be scanned without blocking.

#### Acceptance Criteria

1. WHEN a scan is triggered, THE Job_Queue SHALL enqueue the scan as an asynchronous job and return a scan identifier without waiting for the scan to complete.
2. WHILE a scan job is executing, THE Job_Queue SHALL expose the job status as one of `queued`, `running`, `completed`, or `failed`.
3. WHEN a user queries a scan status, THE ECDAT SHALL return the current job status and, while running, the progress indication.
4. IF a scan job fails during execution, THEN THE Job_Queue SHALL record the failure reason and set the job status to `failed`.
5. WHEN a scan job completes, THE Job_Queue SHALL persist the results through the Persistence_Layer before setting the job status to `completed`.

### Requirement 13: Trend-Over-Time Views

**User Story:** As a risk officer, I want to see how the cryptographic inventory and risk profile change across scans over time, so that I can demonstrate migration progress.

#### Acceptance Criteria

1. WHEN two or more scans exist for a common target, THE ECDAT SHALL compute the change in Finding count per Risk_Tier between the selected scans.
2. THE GUI SHALL display a trend view showing per-Risk_Tier counts across the scan history of a target.
3. WHEN a user selects a time range, THE ECDAT SHALL restrict the trend view to scans within that range.

### Requirement 14: Dependency-Graph Visualization

**User Story:** As a security engineer, I want to see cryptographic findings in the context of the dependency graph, so that I can tell whether a weakness is in my own code or inherited from a transitive dependency.

#### Acceptance Criteria

1. WHEN a scan includes dependency Findings, THE ECDAT SHALL construct a dependency graph relating each cryptographic Finding to the component that introduced it.
2. THE GUI SHALL render the dependency graph and SHALL visually distinguish direct dependencies from transitive dependencies.
3. WHEN a user selects a node in the dependency graph, THE GUI SHALL display the Findings associated with that node.

### Requirement 15: On-Premises and Air-Gapped Deployment

**User Story:** As a critical-infrastructure operator, I want ECDAT to install and run fully on-premises in an air-gapped network, so that our cryptographic weakness map never leaves our network.

#### Acceptance Criteria

1. THE ECDAT SHALL be installable as a self-contained, containerized package that runs on a single organization's infrastructure without a multi-tenant cloud dependency.
2. WHILE ECDAT operates in Air_Gapped_Deployment mode, THE ECDAT SHALL complete discovery, CBOM generation, classification, risk assessment, recommendation, reporting, and visualization without any outbound internet connectivity.
3. WHERE ECDAT requires reference data such as regulatory deadline presets or detection rules, THE ECDAT SHALL bundle that reference data with the installation package.
4. THE ECDAT SHALL store all scan data, Findings, and artefacts within the organization's own Persistence_Layer and SHALL NOT transmit scan data to any external endpoint.

---

## Part C — Differentiating Requirements (Uniqueness / Selection Criteria)

These requirements elevate ECDAT's distinctive capabilities to first-class status. They define what ECDAT does that competing tools (IBM CBOMkit, CZERTAINLY CBOM-Lens, Korthex, AppViewX, and commercial PQC scanners) do not.

### Requirement 16: Jurisdiction-Aware Configurable-Z Compliance Engine with Sensitivity Analysis

**User Story:** As a compliance officer operating under Indian CII deadlines, I want to evaluate every finding against my jurisdiction's specific mandated deadlines and see how the urgency changes if the horizon shifts, so that my migration plan is defensible to a specific regulator rather than to a generic estimate.

#### Acceptance Criteria

1. THE Compliance_Engine SHALL provide named regulatory deadline presets including at minimum India CII (2027, 2028, 2029), NIST IR 8547 (2030 deprecation, 2035 disallowance), and a CRQC estimate.
2. WHEN a user selects a regulatory preset, THE Compliance_Engine SHALL evaluate every Finding's Mosca inequality using that preset's Z value and SHALL report per-preset Risk_Tier counts.
3. WHEN a user requests sensitivity analysis, THE Compliance_Engine SHALL compute and report how each Finding's Risk_Tier changes across the full set of configured Z presets.
4. THE Compliance_Engine SHALL identify for each Finding the earliest regulatory preset under which that Finding becomes `overdue`.
5. WHERE an administrator defines a custom jurisdiction deadline, THE Compliance_Engine SHALL accept the custom Z value and include it in preset evaluation and sensitivity analysis.

### Requirement 17: Crypto-Agility Scoring with Non-Agile Code as a First-Class Finding

**User Story:** As a security architect, I want ECDAT to flag cryptography that is hardcoded and scattered through business logic rather than placed behind an abstraction, so that I can see not just what to migrate but whether the organization is even capable of migrating.

#### Acceptance Criteria

1. THE Agility_Scorer SHALL assign each source-code Finding a crypto-agility score reflecting how easily the underlying algorithm can be replaced.
2. WHEN a cryptographic algorithm is invoked directly within business-logic code rather than through a dedicated cryptographic abstraction, THE Agility_Scorer SHALL classify the Finding as non-agile.
3. WHEN a Finding is classified as non-agile, THE Agility_Scorer SHALL emit a distinct crypto-agility Finding that appears in the inventory alongside quantum-risk Findings.
4. THE Agility_Scorer SHALL report a per-scan aggregate crypto-agility score summarizing how migration-ready the scanned codebase is.
5. WHEN the same algorithm is invoked at multiple scattered locations, THE Agility_Scorer SHALL record the count of distinct locations as evidence of non-agility.

### Requirement 18: Harvest-Now-Decrypt-Later Exposure Flagging

**User Story:** As a risk officer, I want ECDAT to explicitly flag data that is being harvested today for future decryption, so that I can prioritize confidentiality assets whose secrecy must outlast the arrival of a quantum computer.

#### Acceptance Criteria

1. WHEN a Finding protects confidentiality and its data lifetime X plus its migration time Y meets or exceeds the active Z horizon, THE Risk_Engine SHALL flag the Finding as HNDL-exposed.
2. WHERE a Finding is flagged as HNDL-exposed, THE GUI SHALL display an HNDL indicator on that Finding.
3. THE Report_Generator SHALL include a dedicated section listing all HNDL-exposed Findings for a scan.
4. THE Risk_Engine SHALL apply HNDL flagging only to confidentiality-oriented Findings (key-exchange and encryption) and SHALL NOT apply HNDL flagging to signature Findings that are not Trust_Anchors.

### Requirement 19: Confidentiality-vs-Authenticity Risk Split with Trust-Anchor Escalation

**User Story:** As a cryptography owner, I want confidentiality and authenticity assets scored differently, with long-lived trust anchors escalated, so that a short-lived session signature is not treated with the same urgency as a firmware-signing key.

#### Acceptance Criteria

1. THE Classifier SHALL score confidentiality-oriented Findings against data lifetime and SHALL score authenticity-oriented Findings on an authenticity basis.
2. WHEN a signature Finding is identified as a root CA, code-signing, or firmware-signing asset, THE Classifier SHALL flag the Finding as a Trust_Anchor.
3. WHEN a Finding is flagged as a Trust_Anchor, THE Risk_Engine SHALL escalate the Finding's data lifetime X to the configured long-lived trust-anchor value.
4. THE GUI SHALL visually distinguish confidentiality Findings, authenticity Findings, and Trust_Anchor Findings.

### Requirement 20: Honest-Uncertainty Confidence Scoring

**User Story:** As a security engineer, I want ECDAT to surface unresolved parameters honestly rather than guessing, so that I can trust the inventory and know where manual review is required.

#### Acceptance Criteria

1. THE Evidence_Extractor SHALL assign each Finding a Confidence value of `high`, `medium`, or `low` based on the detection method.
2. WHERE a cryptographic parameter cannot be resolved from the evidence, THE Discovery_Engine SHALL record that parameter as `unknown` rather than inferring a value.
3. WHEN a Finding contains an unresolved parameter, THE GUI SHALL display the parameter as unresolved and SHALL display the Finding's Confidence.
4. WHEN a Finding's Confidence is `low`, THE Report_Generator SHALL mark the Finding as requiring manual verification.
5. THE ECDAT SHALL NOT assign a definitive Risk_Tier based solely on an inferred parameter value; WHERE the tier depends on an unresolved parameter, THE Risk_Engine SHALL mark the tier as provisional.

### Requirement 21: Cross-Tool Validation and CBOM Diff

**User Story:** As a security engineer, I want to compare ECDAT's CBOM against a CBOM produced by another generator, so that I can validate coverage and defend the completeness of my inventory.

#### Acceptance Criteria

1. WHEN a user provides an externally generated CycloneDX CBOM for a scanned target, THE ECDAT SHALL compare the external CBOM against the ECDAT-generated CBOM for the same target.
2. THE ECDAT SHALL report cryptographic assets present in the ECDAT CBOM but absent from the external CBOM, and assets present in the external CBOM but absent from the ECDAT CBOM.
3. WHEN comparing two CBOMs, THE ECDAT SHALL match components by algorithm, parameter, and evidence location.
4. THE Report_Generator SHALL include the cross-tool comparison result when an external CBOM is supplied.

### Requirement 22: Cost- and Latency-Aware Recommendation Optimization

**User Story:** As a platform engineer, I want recommendations that account for the latency and cost impact of PQC algorithms, so that I do not adopt an option that breaks a latency-sensitive service or exceeds a cost constraint.

#### Acceptance Criteria

1. THE Recommender SHALL associate each candidate PQC or hybrid algorithm with a latency profile and a cost profile.
2. WHERE a Finding is tagged as latency-sensitive, THE Recommender SHALL prefer the candidate algorithm with the lower latency profile among options that satisfy the required security category.
3. WHEN more than one candidate algorithm satisfies a Finding's security category, THE Recommender SHALL report the latency and cost tradeoff between the candidates.
4. THE Recommender SHALL include the latency and cost basis in the recommendation rationale.
5. WHERE cost or latency data for a candidate algorithm is unavailable, THE Recommender SHALL mark that dimension as `unknown` rather than assuming a value.

### Requirement 23: Internal-vs-External-Facing Asset Tagging

**User Story:** As a risk officer, I want assets tagged as internal-facing or external-facing, so that I can prioritize externally exposed cryptography that an adversary can reach today.

#### Acceptance Criteria

1. THE Classifier SHALL assign each Finding an Exposure value of internal-facing or external-facing.
2. WHERE a Finding originates from a live external endpoint scan, THE Classifier SHALL assign external-facing Exposure by default.
3. WHEN a user filters the findings dashboard by Exposure, THE GUI SHALL display only Findings matching the selected Exposure.
4. THE Report_Generator SHALL report per-Exposure Risk_Tier counts.

---

## Non-Functional Requirements

### Requirement 24: Determinism and Reproducibility

**User Story:** As a security engineer, I want repeated scans of an unchanged target to produce equivalent results, so that findings and risk tiers are trustworthy and auditable.

#### Acceptance Criteria

1. WHEN the same unchanged target is scanned more than once with the same configuration, THE ECDAT SHALL produce equivalent Findings, Risk_Tiers, and recommendations.
2. WHEN a CBOM is regenerated from the same Findings, THE CBOM_Builder SHALL produce an equivalent CBOM document.

### Requirement 25: Security of the Platform Itself

**User Story:** As a platform administrator, I want ECDAT itself to be secure, so that the sensitive cryptographic weakness map it holds is protected.

#### Acceptance Criteria

1. THE ECDAT SHALL require authentication for every operation that reads or modifies scan data.
2. WHEN ECDAT stores credentials or secrets, THE ECDAT SHALL store them outside version-controlled files and outside the Findings data.
3. IF an unauthenticated request targets a protected endpoint, THEN THE Auth_Service SHALL reject the request and record the rejection.
