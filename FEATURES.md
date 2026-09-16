# Blindspot ECDAT — Feature Details

**Enterprise Cryptographic Discovery & Analysis Tool · SIH 2026 · PS26164**

This document describes *what each differentiating feature is and how it works* —
the mechanics, inputs, logic, and output. It is a feature reference, not a status
tracker. Positioning: ECDAT is a **migration decision platform**, not just a
scanner — it finds cryptography, then plans the transition and keeps watching.

---

## 1. Migration Roadmap  ★ HERO

### What it is
Turns a flat list of findings into an **ordered, costed migration plan** — what
to fix first, in what order, at what effort and cost. Answers the PS background
line about "preparedness, financial and operational investment," which pure
discovery tools ignore.

### Inputs (all already produced by the pipeline)
- **Mosca risk tier** — overdue / transitional / low-risk (from the risk engine)
- **Business criticality** — low / medium / high (from the classifier)
- **Blast radius** — change-impact proxy (co-located crypto in a file today;
  full dependency-graph impact once that lands)
- **Present-day weakness flag** — MD5 / SHA-1 / DES / 3DES → separate track
- **Recommendation** — target PQC/hybrid algorithm + strategy per finding

### How it works
Each finding gets a deterministic composite **priority score**:

```
priority_score = tier_weight × 100 + criticality_weight × 10 + blast_radius
   tier_weight:        overdue = 3, transitional = 2, low-risk = 1
   criticality_weight: high = 3, medium = 2, low = 1
   blast_radius:       number of crypto usages sharing the same file
```

Findings are grouped into strategy-based waves and sorted by priority score
(finding id as a stable tiebreak). Present-day-weak crypto is separated onto an
immediate-remediation track so "broken today" is never laundered into "quantum
urgency."

### Output (what the user sees)
A sequenced plan, not a table:

1. **Immediate Remediation** — weak-today crypto (e.g. MD5 → SHA-256). Fix now.
2. **Wave 1 — Urgent PQC Migration** — overdue findings (e.g. RSA-2048 → ML-KEM-1024).
3. **Wave 2 — Hybrid Transition** — transitional findings (e.g. ECDH → P-256 + ML-KEM-768).
4. **Wave 3 — Monitor & Defer** — low-risk findings.
5. **Needs Investigation** — unresolved parameters requiring manual review.

Each item shows: current → target algorithm, parameter set, effort
(low/moderate/high), cost band, priority score, and rationale.

### Why it wins
Research shows existing CBOMs are inventory-derived and "lack architectural
intent, rationale, and security context, limiting their usefulness for migration
planning." The roadmap fills exactly that gap. Deterministic: same findings →
same plan.

---

## 2. CI/CD Guardrail / Continuous Monitoring

### What it is
Turns ECDAT from a one-shot scanner into a **living guardrail**. A CI/CD
integration (GitHub Action / webhook) re-scans on every code change and **fails
the build when newly introduced cryptography is quantum-vulnerable or broken**.

### Inputs
- A repository change event (push / pull request)
- The scan pipeline output for the changed code
- A configurable **policy**: which risk tiers / algorithms should fail the build
  (e.g. fail on any new `overdue` finding or any currently-weak algorithm)

### How it works
1. On a change event, the guardrail triggers a scan of the repository.
2. It compares the new findings against the policy.
3. If a newly introduced finding violates the policy (new overdue crypto, or a
   weak-today algorithm like MD5/DES), the guardrail returns a **non-zero /
   failing status** to the pipeline, blocking the merge.
4. It reports exactly which findings caused the failure, with evidence
   (file + line), so a developer can fix or justify.
5. If nothing disallowed was introduced, it returns a passing status.

### Output
- A pass/fail gate in the CI pipeline
- A list of the specific offending findings with evidence locations
- Configurable severity policy per team

### Why it wins
Maps to the IETF CADI lifecycle's "Validation & Monitoring" phase, which most
tools skip — they stop at one-time discovery. Prevents quantum-risk from
*re-entering* a codebase after cleanup. Demo-friendly: push a commit, watch it
get blocked.

---

## 3. HNDL Exposure Flagging (Harvest-Now-Decrypt-Later)

### What it is
Explicitly flags data that an adversary can **record today and decrypt later**
once a quantum computer exists — the single most important quantum threat to
long-lived confidential data.

### Inputs
- **X** — data secrecy lifetime (from the classifier)
- **Y** — migration time
- **Z** — active quantum/regulatory horizon
- **Security goal** — confidentiality vs authenticity (from the classifier)

### How it works
A finding is flagged **HNDL-exposed** when:

```
security_goal == confidentiality  AND  (X + Y) ≥ Z
```

The flag applies only to **confidentiality-oriented** cryptography
(key-exchange, encryption). It is deliberately **not** applied to ordinary
signatures: a signature forged years from now is worthless against a token that
already expired, so authenticity assets are not HNDL-exposed unless they are
long-lived trust anchors.

### Output
- A distinct **HNDL indicator** on each affected finding in the GUI
- A dedicated HNDL section in the report listing all exposed assets
- Feeds urgency into the migration roadmap

### Why it wins
Directly answers the PS phrase "highlight risks to sensitive data." Most teams
mention HNDL in slides but do not compute it as a first-class, per-finding flag.

---

## 4. Compliance & Sensitivity View (Jurisdiction-Aware Configurable-Z)

### What it is
Evaluates every finding against **named regulatory deadlines** rather than a
single generic estimate, and shows how urgency shifts as the horizon changes.

### Inputs
- Each finding's X (data lifetime) and Y (migration time)
- A set of named **Z presets** (regulatory horizons):
  - **India CII** — 2027 / 2028 / 2029 category deadlines
  - **NIST IR 8547** — deprecate ~2030, disallow ~2035
  - **CRQC estimate** — expert mid-range quantum-arrival estimate
  - Optional **custom** organization-defined deadline

### How it works
1. For a selected preset, re-evaluate Mosca's inequality (X + Y > Z) for every
   finding using that preset's Z, and report per-preset risk-tier counts.
2. **Sensitivity analysis:** compute how each finding's tier changes across the
   full set of presets — showing which assets are urgent under every timeline vs
   only under aggressive ones.
3. For each finding, identify the **earliest preset under which it becomes
   overdue** — a concrete compliance deadline per asset.

### Output
- A preset selector that instantly re-tiers the whole inventory
- A **sensitivity matrix**: findings × presets, showing tier under each horizon
- Per-finding "earliest overdue deadline" (e.g. "violates the 2030 NIST
  deprecation deadline")

### Why it wins
Maps to PS "structured frameworks," and the India-specific regulatory angle
carries strong national relevance at SIH. Z is always treated as an assumption
with its provenance shown — never presented as settled fact.

---

## 5. Cryptographic Dependency Graph / Blast Radius

### What it is
An interactive graph showing **how cryptographic assets connect** — which
library or component feeds which service — so a user can see that migrating one
asset forces changes in others.

### Inputs
- Findings and their source components
- Dependency relationships (direct and transitive) from manifest parsing

### How it works
1. Build a graph relating each crypto finding to the component that introduced
   it (own code vs a transitive dependency).
2. Compute each finding's **blast radius** — how many other components depend on
   it — which feeds the migration roadmap's priority score.
3. Render nodes encoded by risk tier and blast radius; distinguish direct from
   transitive dependencies.

### Output
- An interactive node-edge visualization (click a node → its findings)
- A blast-radius metric per finding
- Visual answer to "is this weakness in my code or inherited?"

### Why it wins
Existing CBOMs lack architectural/dependency context. The graph differentiates
the GUI instantly (everyone else ships the same flat table) and demonstrates
systems-level thinking.

---

## 6. Crypto-Agility Scoring

### What it is
Scores **how easily each finding's cryptography can be replaced**, and flags
crypto that is hardcoded and scattered through business logic as a first-class
finding. Answers "not just what to migrate, but whether you *can*."

### Inputs
- Source-code findings and their call sites
- Whether the algorithm is invoked directly in business logic vs behind a
  dedicated cryptographic abstraction
- Count of distinct locations where the same algorithm is invoked

### How it works
1. Assign each source finding an agility score reflecting replaceability.
2. When crypto is called directly in business logic (not behind an interface),
   classify the finding **non-agile** and emit a distinct crypto-agility finding.
3. Count scattered occurrences of the same algorithm as evidence of low agility.
4. Roll up to a **per-scan aggregate agility score** — how migration-ready the
   codebase is overall.

### Output
- A per-finding agility score + non-agile flag
- Distinct crypto-agility findings in the inventory
- A codebase-level agility summary

### Why it wins
Novel — almost no competing tool measures migration-readiness of the code
itself. It reframes the problem from "what crypto exists" to "how hard is the
migration going to be."

---

## 7. Latency & Cost-Aware Recommendations

### What it is
Makes recommendations account for the **performance and cost** impact of PQC
algorithms, not just the algorithm swap — so a recommendation never silently
breaks a latency-sensitive service.

### Inputs
- The finding's required NIST security category
- A benchmark model per candidate PQC/hybrid algorithm: key/ciphertext sizes,
  handshake overhead (latency profile), relative cost profile
- Optional "latency-sensitive" tag on a finding

### How it works
1. Associate each candidate algorithm with a latency profile and a cost profile.
2. When multiple candidates satisfy the required security category, report the
   **latency/cost tradeoff** between them.
3. For latency-sensitive findings, prefer the lower-latency candidate that still
   meets the security category.
4. Include the latency/cost basis in the recommendation rationale. Where data is
   unavailable, mark that dimension `unknown` rather than assuming.

### Output
- Recommendations annotated with latency and cost bands
- Tradeoff notes when several targets qualify
- Honest `unknown` markers where no benchmark exists

### Why it wins
PS point (iv) literally says "based on risk profile, latency, cost" — a
requirement most teams ignore entirely.

---

## 8. Cross-Tool Validation & CBOM Diff

### What it is
Compares ECDAT's CBOM against a CBOM produced by another generator (e.g. IBM
CBOMkit) to **validate coverage** and defend inventory completeness.

### Inputs
- An externally generated CycloneDX CBOM for the same target
- ECDAT's own generated CBOM

### How it works
1. Match components across the two CBOMs by algorithm, parameter, and evidence
   location.
2. Report assets present in ECDAT but missing from the external tool, and vice
   versa (both directions).
3. Include the comparison in the report when an external CBOM is supplied.

### Output
- A side-by-side diff of the two inventories
- Coverage gaps in each direction

### Why it wins
Turns the "IBM already does discovery" objection into a strength — ECDAT can
*validate against* IBM's output and show where each tool sees more.

---

## 9. Honest-Uncertainty Confidence Scoring

### What it is
Surfaces what the tool **does not know** rather than guessing — a trust story,
since research scanners hover around F1 0.75 and false certainty is a real
weakness.

### Inputs
- Detection method (direct API call, AST-confirmed, string match, dependency
  manifest, config inference)
- Whether each parameter (e.g. key size) could be statically resolved

### How it works
1. Assign each finding a confidence band (high / medium / low) driven by the
   detection method.
2. When a parameter cannot be resolved, record it as `unknown` — never infer a
   value. (E.g. a key size behind an imported constant is reported unresolved,
   not silently assumed.)
3. Do not assign a definitive risk tier from an inferred parameter; mark such
   tiers **provisional**.
4. Flag low-confidence findings as requiring manual verification in the report.

### Output
- Confidence bands + unresolved-parameter markers in the GUI
- "Requires manual verification" flags on low-confidence findings

### Why it wins
"We tell you what we're *not* sure about" is exactly the credibility signal a
security judge respects.

---

## 10. Confidentiality-vs-Authenticity Split with Trust-Anchor Escalation

### What it is
Scores confidentiality and authenticity cryptography **differently**, so a
short-lived session signature is not treated as urgently as a firmware-signing
key.

### Inputs
- The finding's usage and security goal (from the classifier)
- Whether the asset is a long-lived trust anchor (root CA, code signing,
  firmware signing)

### How it works
1. Score confidentiality findings (key-exchange, encryption) against **data
   lifetime** — harvest-now-decrypt-later applies.
2. Score authenticity findings (signatures) on an **authenticity basis** — a
   future forgery is worthless against expired data.
3. When a signature is a root CA / code-signing / firmware-signing asset, flag
   it a **trust anchor** and escalate its effective lifetime (X) to the
   long-lived value.

### Output
- Confidentiality, authenticity, and trust-anchor findings visually
  distinguished in the GUI
- Correctly differentiated urgency (short-lived signature ≠ firmware key)

### Why it wins
Demonstrates genuine domain understanding, not pattern-matching. Prevents the
"everything is urgent" failure mode that erodes trust in a tool.

---

## 11. Internal-vs-External-Facing Asset Tagging

### What it is
Tags each asset as **internal-facing or external-facing**, so externally
reachable cryptography — which an adversary can touch today — is prioritized.

### Inputs
- The finding's origin (source scan vs live external endpoint scan)
- Deployment/exposure context

### How it works
1. Assign each finding an exposure value (internal / external).
2. Findings from live external endpoint scans default to external-facing.
3. Allow filtering the dashboard by exposure and report per-exposure risk-tier
   counts.

### Output
- Exposure tag on each finding
- Dashboard filter + per-exposure risk breakdown in reports

### Why it wins
Externally exposed weak crypto is a present, reachable risk — prioritizing it
reflects how real attackers operate.

---

## How the features connect

```
Discovery → Evidence → CBOM → Classify → Risk (Mosca) → Recommend
                                   │                        │
        confidentiality/authenticity split (10)            │
        internal/external tagging (11)                      │
        crypto-agility scoring (6)                          │
                                   │                        │
                                   ▼                        ▼
                            HNDL flag (3)          latency/cost recs (7)
                                   │                        │
                                   ▼                        ▼
        dependency graph / blast radius (5) ──▶  MIGRATION ROADMAP (1) ★
                                   │                        │
        compliance & sensitivity (4)                        ▼
        honest-uncertainty confidence (9)          CI/CD guardrail (2)
        cross-tool CBOM diff (8)                    continuous monitoring
```

The core pipeline is the engine; features 3–11 enrich the findings; the
**Migration Roadmap (1)** is where it all converges into an actionable plan; the
**CI/CD guardrail (2)** keeps the plan from regressing over time.
