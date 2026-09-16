# PPT Alignment Review — SIH2026 Idea Presentation vs. Strategy

**Verdict: PARTIAL alignment.** The deck is well-structured and SIH-format-correct,
and the *technical approach* slide accurately reflects our real architecture. BUT the
"innovation & uniqueness" is currently the **core pipeline** — which is a commodity every
competitor (and IBM CBOMkit) already has. The deck sells a *scanner*. Our strategy sells a
*migration decision platform*. This must be fixed before presenting, or judges will file us
under "another CBOM tool."

See `STRATEGY.md` for the full differentiation plan this review references.

---

## 1. What already aligns (KEEP as-is)

- ✅ Title, PS ID, theme — correct.
- ✅ Technical approach / architecture (Slide 3) — matches our real pipeline
  (scan → CBOM → classify → risk → recommend → GUI). Accurate. Keep.
- ✅ Risk split (encryption vs signature) + trust-anchor escalation — genuinely good nuance,
  already a differentiator. Keep and emphasize.
- ✅ Explainability / traceability ("GUI shows exactly why each tier") — this is our
  "honesty/confidence" differentiator. Keep and amplify.
- ✅ Feasibility slide is honest (labels detection limits, phases binaries later). Good.
- ✅ Research references (arXiv 2608.04857, QARS MDPI, FIPS 203, OpenSSL) — real and relevant.

---

## 2. What's MISSING or BURIED (the gap to fix)

| Our differentiator (STRATEGY.md) | In the PPT? | Action |
|----------------------------------|-------------|--------|
| **Migration Roadmap (HERO)** | ❌ Only hinted in user story ("prioritized list") | **Promote to headline uniqueness** |
| Crypto dependency graph / blast radius | ❌ Absent | Add to uniqueness + architecture |
| India + NIST compliance mapping | ⚠️ Only in user-story prose | Make it a named feature |
| CI/CD guardrail / continuous monitoring | ❌ Absent | Add as "platform, not one-shot" |
| Latency & cost-aware recommendations | ⚠️ One bullet, unsubstantiated | Back it with the benchmark model |
| Honesty / confidence / "what we don't know" | ✅ Present | Keep |

**Core problem:** the uniqueness slide leads with "multi-surface scanners" and "CycloneDX CBOM"
— that's table stakes, not uniqueness. Our actual uniqueness is *what happens after discovery.*

---

## 3. Slide-by-slide rewrite guidance

### Slide 2 — Proposed Solution / Innovation & Uniqueness  ← BIGGEST CHANGE
**Problem:** the "uniqueness" bullets are the commodity pipeline.

**Reframe the top line to:**
> "Blindspot doesn't stop at finding cryptography — it produces a costed, prioritized,
> compliance-mapped **migration plan**, and prevents new quantum-risk from entering code."

**Replace the uniqueness bullets with these (paste-ready):**
- **Migration Roadmap** — turns findings into a sequenced, costed plan (what to migrate first
  by risk × business criticality × blast radius), not just a list.
- **Cryptographic dependency graph** — visualizes blast radius: migrating one asset shows
  what else it breaks.
- **Compliance mapping** — every asset mapped to NIST IR 8547 (2030/2035) and India CERT-In
  deadlines.
- **Continuous guardrail** — a CI/CD check re-scans on every commit and blocks new
  quantum-vulnerable crypto.
- **Latency & cost-aware recommendations** — PQC choices account for performance and cost,
  not just algorithm swaps.
- **Explainable & honest** — every risk score shows its X/Y/Z math; unresolved parameters are
  flagged, never guessed.

**Keep** (move to a smaller "foundation" strip): multi-surface scanning, CycloneDX CBOM,
Mosca inequality — frame these as the *proven base*, not the innovation.

### Slide 3 — Technical Approach / Architecture
- **Keep** the pipeline diagram (accurate).
- **Add two components** to the component list:
  - *Dependency Graph Builder* — computes asset relationships / blast radius.
  - *Migration Planner* — sequences and costs the migration (consumes Mosca tier + criticality
    + blast radius).
- **Add** to the flow: `... → recommend → PLAN → GUI` (insert the planner as an explicit stage).

### Slide 4 — Feasibility & Viability
- **Keep** the honest framing.
- **Add one line** on the differentiators' feasibility:
  "The migration planner and dependency graph reuse the existing normalized-finding pipeline —
  no new scanning risk, only new analysis on data we already extract."

### Slide 5 — Impact & Benefits
- Already strong (the bank user story is good). **Sharpen the user story** to lead with the
  hero: "...ECDAT produces a **prioritized migration roadmap** — Wave 1: RSA-2048 on 15-year
  records (overdue, critical); Wave 2: hybrid for active ECDH; deferred low-risk — with effort
  and cost per wave."
- Add a benefit bullet: **"Continuous assurance"** — new quantum-risk is blocked at commit time.

### Slide 6 — Research & References
- **Fix factual error:** the CBOMkit link `github.com/cbomkit/cbomkit` is wrong. The project
  moved to the Post-Quantum Cryptography Alliance / Linux Foundation:
  correct repo is **`github.com/PQCA/cbomkit`** (and IBM's model repo is `github.com/IBM/CBOM`).
- Optionally add: arXiv 2603.22442 (architecture-derived CBOMs) — it directly supports our
  "CBOMs lack migration usefulness" thesis, i.e. why our roadmap matters.

---

## 4. Positioning one-liner to put on Slide 2 (or as a tagline)

> "Others hand you a list of your cryptography. Blindspot hands you a costed, prioritized,
> compliance-mapped migration plan — and stops new quantum-risk from entering your code.
> Discovery is where they stop; it's where we start."

---

## 5. Priority of edits (if short on time)

1. **Slide 2 uniqueness rewrite** — non-negotiable; this is what makes us not-a-clone.
2. **Slide 6 CBOMkit URL fix** — a wrong reference to a tool we're differentiating from looks bad.
3. **Slide 3 add Migration Planner + Dependency Graph components.**
4. **Slide 5 user-story sharpening.**
5. Slide 4 one-liner.

Everything else in the deck can stay. The structure is fine — it's the *emphasis* that needs
to shift from "we scan and make a CBOM" to "we plan your migration."
