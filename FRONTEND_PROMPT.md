# ECDAT Frontend — Build Spec / AI Prompt

Use this as a handoff doc for a teammate, or paste it directly into an AI coding assistant (Kiro, Copilot, Cursor, etc.) to scaffold the frontend.

---

## Pages/screens overview

| # | Page | Purpose |
|---|---|---|
| 1 | Landing / Scan Trigger | Entry point — pick a target, start a scan |
| 2 | Scan Progress | Feedback while the pipeline runs |
| 3 | Findings Dashboard | Overview of all findings, filterable by risk tier |
| 4 | Finding Detail (Drill-down) | Evidence → classification → Mosca math → recommendation for one artefact |
| 5 | CBOM Export View | Preview + download of the standardized report |
| 6 | (Optional) Summary/Report Page | High-level risk summary for a non-technical viewer (judge-facing) |

Pages 1, 3, and 4 are mandatory for the demo. Pages 2, 5, and 6 add polish if time allows — build them last.

---

## Prompt (copy-paste ready)

```
Build a React frontend for a security tool called ECDAT (Enterprise Cryptographic
Discovery & Analysis Tool). It scans a codebase for cryptographic weaknesses,
scores their quantum-risk urgency using Mosca's inequality, and recommends fixes
(Pure PQC / Hybrid / Defer).

Stack: React (Vite), Tailwind CSS, Recharts for charts. Use simple state-based
view switching (a "currentPage" state variable is fine) rather than a routing
library — this is a hackathon demo, not a production app. No authentication.

The backend exposes these REST endpoints. Build against a fixtures.json file
first so the UI is fully demoable before the backend is ready; wire up the real
API calls last.

- POST /scan            → { scan_id, status: "running" | "done" }
- GET  /scan/{id}/status → { status, progress_percent }
- GET  /findings         → array of Finding objects (see shape below)
- GET  /findings/{id}    → single Finding object, full detail
- GET  /export/cbom      → downloadable CycloneDX JSON file

Finding object shape:
{
  "id": "string",
  "algorithm": "RSA-2048" | "ECDH-P384" | "ECDSA-P256" | "MD5" | ...,
  "artefact_type": "key-exchange" | "signature" | "encryption" | "hash",
  "file": "payments/transaction_vault.py",
  "line": 12,
  "code_snippet": "key = RSA.generate(2048)",
  "data_lifetime_years": 15,
  "criticality": "high" | "medium" | "low",
  "confidence": "high" | "low",
  "mosca": { "x": 15, "y": 2, "z": 8, "overdue": true },
  "tier": "overdue" | "transitional" | "low-risk",
  "recommendation": {
    "strategy": "pure_pqc" | "hybrid" | "defer",
    "suggested_algorithm": "ML-KEM-768",
    "rationale": "Long-lived financial data exceeds the quantum-safe migration window."
  }
}

Build these pages:

═══════════════════════════════════════════════════════════
PAGE 1 — Landing / Scan Trigger
═══════════════════════════════════════════════════════════
- Header/hero area: "ECDAT" title, one-line tagline ("Discover, assess, and fix
  quantum-vulnerable cryptography before it's too late").
- A dropdown or text input for target repo — default preset to the seeded demo
  repo, but structure it so a second/third preset (e.g. "OpenSSL sample") could
  be added later without a rewrite.
- One primary button: "Run Scan".
- On click: call POST /scan, capture scan_id, transition to Page 2 (or straight
  to Page 3 if you skip the progress page).
- Keep this page uncluttered — one clear action, nothing else competing for
  attention.

═══════════════════════════════════════════════════════════
PAGE 2 — Scan Progress (optional but recommended)
═══════════════════════════════════════════════════════════
- Simple progress indicator (spinner or progress bar) with stage labels that
  update as the pipeline runs, e.g.:
    "Scanning source code..." → "Building CBOM..." → "Classifying artefacts..."
    → "Computing risk scores..." → "Generating recommendations..."
- Poll GET /scan/{id}/status every second, or just fake a timed sequence through
  these labels if the real backend returns fast — the point is to visually sell
  the pipeline stages to the audience during the demo, since the actual scan on
  a small seeded repo will complete in under a second.
- Auto-transitions to Page 3 when done.

═══════════════════════════════════════════════════════════
PAGE 3 — Findings Dashboard
═══════════════════════════════════════════════════════════
- Top summary strip: 3-4 stat cards — total findings, count overdue, count
  transitional, count low-risk. Use the same red/amber/green color coding
  everywhere in the app.
- Filter bar: tier filter (All / Overdue / Transitional / Low-risk) as tabs or
  a segmented control, not a dropdown — faster to click during a live demo.
- Findings table, columns: Algorithm | Artefact Type | File:Line | Risk Tier
  (colored badge) | Suggested Fix | (chevron/arrow to view detail).
- Clicking a row navigates to Page 4 for that finding's id.
- A visible "Export CBOM Report" button in the header area, routes to Page 5
  or triggers a direct download.
- Optional: a small donut/bar chart (Recharts) showing the tier distribution
  visually next to the stat cards.

═══════════════════════════════════════════════════════════
PAGE 4 — Finding Detail (Drill-down)  ⭐ most important page
═══════════════════════════════════════════════════════════
This page carries the demo's core argument. Structure top to bottom:

1. Header: algorithm name + risk tier badge + a "← Back to findings" link.

2. Evidence card:
   - File path and line number, styled like a code editor reference.
   - The code_snippet field shown in a monospace, syntax-highlighted-looking box.

3. Classification card:
   - Artefact type, data lifetime (years), criticality — shown as 3 labeled
     stat blocks side by side, not a paragraph of text.

4. Risk Calculation card — THE key visual:
   - Show X, Y, Z as three large numbers with labels ("Data Lifetime",
     "Migration Time", "Quantum/Regulatory Horizon").
   - Below them, show the actual inequality being evaluated, e.g.:
       "15 + 2  >  8"   with a clear visual state (red highlight + "OVERDUE"
       label if true, green + "SAFE FOR NOW" if false).
   - This needs to be legible from the back of a room on a projector — large
     font, high contrast, no reliance on hover/tooltip to understand it.

5. Recommendation card:
   - Strategy badge (Pure PQC / Hybrid / Defer) in a distinct color.
   - Suggested algorithm name, shown prominently (e.g. "ML-KEM-768").
   - The rationale text below it in normal-size body text.

═══════════════════════════════════════════════════════════
PAGE 5 — CBOM Export View (optional)
═══════════════════════════════════════════════════════════
- A simple page showing a preview of the exported CycloneDX JSON (syntax
  highlighted, scrollable) with a "Download" button.
- Doesn't need to be pretty — this page exists to prove standards compliance
  if a judge asks to see the raw output, not to be a polished feature.

═══════════════════════════════════════════════════════════
PAGE 6 — Summary/Report Page (optional, judge-facing)
═══════════════════════════════════════════════════════════
- A single print-friendly-looking page summarizing: total artefacts found,
  breakdown by tier, top 3 most urgent findings, and overall "quantum readiness"
  framing in plain language for a non-technical audience.
- Useful if you want a page to leave on screen at the END of your demo, distinct
  from the technical findings table — a "here's the business takeaway" close.
- Build this last, only if Pages 1/3/4 are solid first.

STYLE
- Clean, modern, dashboard-like layout. Simple top nav or sidebar with "ECDAT"
  branding is fine but not required.
- Red/amber/green used strictly and consistently for risk tiers across every
  page — never use those colors decoratively for anything else.
- Must look correct at a normal laptop resolution projected on a screen — avoid
  relying on hover states, tooltips, or small text for anything demo-critical.

Build this now: project scaffold, all mandatory pages (1, 3, 4) fully wired
together with local state, and a fixtures.json file with 5 sample findings
(one per tier plus one MD5/weak-crypto example) so the UI is fully demoable
before the real backend is connected. Add pages 2, 5, 6 only after 1/3/4 work.
```

---

## Notes for whoever runs this prompt

- **Fixtures first, always.** The prompt explicitly asks for `fixtures.json` so the frontend team can build and demo the UI without waiting for the backend team to finish Stages 1-5. Swap in real API calls last, and only once each page already works against static data.
- **Page 4's risk calculation card is the demo's centerpiece.** This is what gets pointed at and explained out loud during the presentation. Don't let this page be the last one built — get it right early, then iterate on the others.
- **Build order matters more than page count.** Page 1 → Page 3 → Page 4 is the mandatory path. Everything else (2, 5, 6) is additive polish — cut it without guilt if you're short on time.
- **Don't let scope creep in.** No auth, no multi-route routing library, no settings panel, no dark mode toggle. If the AI assistant suggests adding any of these, decline.
- **Keep color coding identical across every page and every other artifact** — your architecture diagrams and PPT slides should use the same red/amber/green so the visual language is consistent across the whole presentation, not just within the app.

## If using this as a doc instead of a prompt

Hand this file directly to your frontend teammate — the page-by-page breakdown above doubles as a complete written spec even without an AI tool, since it lists the exact pages, their contents, build order, and data shape needed.
