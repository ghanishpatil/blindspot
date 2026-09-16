# Blindspot ECDAT — PS Coverage Roadmap

**Purpose of this document.** It maps the remaining work needed to cover the
Smart India Hackathon problem statement as completely and *honestly* as
possible. It is a plan only — nothing here is built yet. Each feature entry
explains, in plain language, **what it does**, **why the PS needs it**, **how
we'd build it (reusing what already exists)**, the **effort/risk**, and the
**honesty guardrail** that keeps the project's core promise: never show a
fabricated number.

> **Guiding principle:** every gap is closed either with a *real*
> implementation or with an *explicitly labelled* "architecture-ready /
> roadmap" note. We never silently omit a requirement and we never invent data
> to look complete.

---

> **STATUS UPDATE:** ✅ **Phases A, B, and C are COMPLETE and verified.**
> - **A — Container image scanning:** `app/scanner/container.py` (safe layer extraction +
>   CLI pull) wired into `POST /scan` (`imageRef` / `imageArchivePath`), frontend target-type
>   toggle. **Live-verified: a demo-repo container image produced 18 real findings in ~24s.**
> - **B — Latency/cost:** `CostProfile` on recommendations from published FIPS 203/204 sizes
>   (never fabricated latency), shown in the recommendation card. **Live-verified via a TLS
>   finding recommending ML-DSA-65.**
> - **Live TLS/cert scanning (Phase D below):** `app/scanner/tls.py` + `POST /api/tls-scan` + `/tls` page.
>   **Live-verified against github.com: TLS 1.3, ECDSA-256 cert → tier "overdue" → ML-DSA-65.**
>
> Backend **281 tests pass**; frontend tsc clean, build ok, 18 tests pass. Scan working dirs kept
> off `%TEMP%` in `<backend>/.scan-work` (a Windows-AV-on-temp interaction made semgrep hang; this
> hardens URL-clone and container scans too).
>
> ✅ **Phase C — Binaries (lite):** `app/scanner/binary.py` fingerprints SHA-2/SHA-1/MD5/AES
> constants, ASN.1 OIDs (RSA/ECDSA/ECDH/DH/DSA), and library brand strings (OpenSSL, wolfSSL,
> mbedTLS, libsodium, BoringSSL). Every finding is deliberately low-confidence and auto-routed
> to manual verification. **Live-verified on a synthetic ELF binary: 4 fingerprints matched
> (SHA-256, AES, RSA OID, OpenSSL 3.0.11).** 16 tests.
>
> ✅ **Phase E — HSM / Cloud KMS (declared, not attested):** `app/scanner/infra.py` discovers
> AWS KMS / CloudHSM, GCP KMS, Azure Key Vault, Kubernetes secret-management, and PKCS#11 modules
> (SoftHSM, YubiHSM, Luna, nShield, PyKCS11) from Terraform / CloudFormation / K8s / SDK code.
> New `ArtefactType.HARDWARE_MODULE` and `ArtefactType.CLOUD_SERVICE`. Every declaration routes
> to INVESTIGATE unless a `key_spec` is inline. **Live-verified: an AWS KMS key with
> `key_spec = "RSA_2048"` resolved to RSA-2048 → overdue → ML-KEM-1024.** 15 tests.
>
> **All five PS-coverage phases (A B C D E) are now complete.** 7 of 7 artefact types, 4 of 4
> scan targets — with HSM/KMS coverage clearly labelled *declared, not attested* and live
> PKCS#11 / KMS-SDK attestation designed as the honest next step.

## 1. Where we are today (baseline)

This is the verified current state — do **not** rebuild any of it.

| PS requirement | Status |
|---|---|
| Identify algorithms, keys, key sizes | ✅ Done |
| Identify libraries | ✅ Done |
| Identify certificates | ❌ Missing |
| Identify protocols | ❌ Missing |
| Identify hardware modules (HSM) | ❌ Missing |
| Identify cloud services (KMS) | ❌ Missing |
| Quantum risk assessment | ✅ Done (strongest area) |
| Classify by type / lifetime / criticality + Mosca | ✅ Done |
| Recommend PQC / Hybrid by risk profile | ✅ Done |
| Recommend by **latency / cost** | ❌ Missing |
| Scan **source repositories** | ✅ Done (+ GitHub URL ingestion) |
| Scan **libraries** | ✅ Done |
| Scan **binaries** | ❌ Missing |
| Scan **container images** | ❌ Missing |
| Standardised report (CycloneDX CBOM) | ✅ Done |
| Interactive GUI | ✅ Done |
| "Financial & operational investment" (Background) | ✅ Migration Roadmap |

**Score today:** ~4 of 7 expected outcomes fully covered.
**Target after this roadmap:** 6–7 of 7, with HSM/KMS honestly framed as roadmap.

Why these gaps are cheap to close: the pipeline has clean internal boundaries
(`scanner → normalize() → CBOM → classify → risk → recommend`). Most new work
only needs to produce input at the front (`normalize()`) or add fields at the
back (recommendation) — the middle is reused untouched.

---

## 2. Execution order (recommended)

```
Phase A ─ Container image scanning      (low effort, highest PS payoff)
Phase B ─ Latency / cost in recs        (low effort, closes outcome iv)
Phase C ─ Binaries (lite)               (moderate, closes a named target)
Phase D ─ Live TLS / certificate scan   (moderate, best demo, do as stretch)
Phase E ─ HSM + Cloud KMS               (roadmap-only framing, not built)
```

Rationale: A and B are the highest coverage-per-hour and both fully honest.
C closes a *named* deliverable (binaries) that D and the others don't touch.
D is the strongest live demo moment but the riskiest per minute. E is
genuinely hard and is presented as designed-but-not-integrated.

---

## Phase A — Container Image Scanning ✅ DONE

**PS line closed:** Deliverables — "scan … container images." **Live-verified: 18 findings from a
demo-repo image in ~24s.** Safe extraction (zip-slip/symlink/bomb guards) + reuse of the existing
scanners; `imageRef` (CLI pull) and `imageArchivePath` (dev-only) on `POST /scan`.

**What it does (plain language).** Lets a user point the tool at a container
image (e.g. `python:3.11-slim` or a private app image) and get the same
crypto findings, CBOM, risk tiers, and recommendations they already get for a
source repo. A container image is just a stack of filesystem layers with source
files, binaries, and dependency manifests inside — so once we turn the image
into a folder, the *entire existing pipeline runs on it unchanged*.

**How we'd build it.**
- Add one new capability: *"given an image reference, produce a local
  directory."* Pull the image and extract its layers into a temp folder.
- Then hand that folder to the **existing** `Source_Scanner` and
  `Dependency_Scanner` — no new detection logic, same `normalize()` boundary,
  same everything downstream.
- Wire it as a new scan target alongside "local path" and "repository URL"
  (`POST /scan` gets an `imageRef`), and add an input on the Scan page.

**Effort:** Low for the pipeline reuse; the real work is *safe extraction*.

**Risks / must-handle (do not treat as free):**
- Untrusted tar layers → **path-traversal / zip-slip / symlink escape** and
  **decompression bombs**. Extract defensively (reject paths escaping the temp
  dir, cap total size), the same care we gave the git-clone SSRF hardening.
- Pulling without Docker installed means a system dependency (`skopeo`/`crane`)
  or a library — treat it as the same command/SSRF surface we just hardened.
- **Scope to public images** for the demo; private-registry auth is a rabbit
  hole and out of scope.

**Honesty guardrail:** only report what's actually found in the extracted
layers. If extraction fails, say so — don't fall back to pretending.

**Done when:** a public image reference produces a real CBOM + findings through
the unchanged pipeline, and a malicious/oversized layer is safely rejected.

---

## Phase B — Latency / Cost in Recommendations ✅ DONE

**PS line closed:** Description (iv) — "based on risk profile, **latency, cost**, etc." Implemented
as a `CostProfile` (public-key/ciphertext/signature bytes vs. classical) from published FIPS
203/204 sizes, with an explicit "not measured latency" basis. Shown in the recommendation card.

**What it does (plain language).** Every recommendation (e.g. "replace RSA-2048
with ML-KEM-768") gains a *cost profile*: how much bigger the keys/signatures
/ciphertexts are versus the classical algorithm, and how that affects handshake
size and bandwidth. This is exactly the "financial and operational investment"
signal the PS Background asks for, at the per-finding level.

**How we'd build it.**
- Add a small **reference table** of *published* PQC parameter sizes (key size,
  ciphertext size, signature size, handshake round-trips) for ML-KEM / ML-DSA /
  hybrid, sourced from FIPS 203/204 and the papers already in our reference
  list.
- Add new fields to the recommendation model (e.g. `sizeProfile`,
  `relativeCost`, `costNotes`) — same shape of change as the NIST-category fix
  already shipped. No new pipeline stage.
- Surface it in the finding detail and (optionally) the Migration Roadmap cost
  bands.

**Effort:** Low.

**Honesty guardrail (critical):** present this as **published sizes and
round-trips**, *never* as invented millisecond latency. Real latency depends on
hardware, network, and implementation — printing "+2.3 ms" would fabricate
exactly the kind of number this project refuses to invent. Cite every figure
with its source and let the sizes stand as the honest cost signal.

**Done when:** each recommendation shows real, sourced size/cost deltas vs. the
classical algorithm, with citations, and no fabricated timing.

---

## Phase C — Binary Scanning (lite) ✅ DONE

**Live-verified:** a fake `libcrypto.so` yielded 4 findings — SHA-256 (H0 constants), AES (S-box),
RSA (rsaEncryption OID), and an OpenSSL 3.0.11 linker string — all at **low confidence** and
auto-routed to the manual-verification surface. Backend: `app/scanner/binary.py` + 16 tests. Plugs
into `run_pipeline` at the `normalize()` boundary — the CBOM, classifier, risk, and recommender
run on binary findings unchanged. Frontend: a purple **Binary** provenance badge on findings-table
rows.

**PS line closed:** Deliverables — "scan … **binaries** …" (a named target none
of the other phases touch).

**What it does (plain language).** Detects cryptography inside compiled files
(`.exe`, `.dll`, `.so`, `.dylib`, static libs) without source. A "lite"
approach looks for tell-tale fingerprints: known algorithm constants (e.g. AES
S-box bytes, SHA/MD5 init constants), crypto OIDs, and embedded library
strings/version markers. These become normal findings with lower, clearly
labelled confidence.

**How we'd build it.**
- New scanner component that reads a binary and matches a table of known crypto
  constants / OIDs / library strings, emitting the same `NormalizedFinding`
  shape (so CBOM, classification, risk, and recommendation all reuse).
- Mark detections `detection_method = binary_signature` with **low/medium
  confidence** — they feed the existing "needs verification" honesty flag.

**Effort:** Moderate (lite). Full disassembly / control-flow crypto detection
is genuinely hard and is **out of scope** — call that out explicitly.

**Honesty guardrail:** binary matches are *heuristics*. They must carry lower
confidence and route into the manual-verification surface, never presented with
the same certainty as an AST-confirmed source finding.

**Done when:** a binary with known crypto (e.g. an OpenSSL-linked executable)
produces findings at honest confidence, and the detail view says how they were
detected.

---

## Phase D — Live TLS / Certificate Scanning ✅ DONE

**Live-verified against github.com: TLS 1.3, ECDSA-256 → tier "overdue" → ML-DSA-65.** SSRF-guarded
(private/loopback/reserved addresses refused), reuses classify→risk→recommend, `/tls` page with a
labelled cached fallback for demo resilience.

**PS line closed:** Description (i) — "**certificates, protocols**." Also the
strongest *live* demo moment ("let's scan our own bank's login page now").

**What it does (plain language).** Point the tool at a hostname (e.g.
`example.com:443`), connect, and read the live certificate (issuer, key
algorithm & size, signature algorithm, expiry) plus the negotiated protocol
version and cipher suite. It then risk-scores them the same way: an RSA/ECDSA
cert is Shor-breakable, an old TLS version is a present-day weakness.

**How we'd build it.**
- New scanner using Python's standard `ssl` + `socket` — connect, capture the
  peer certificate and negotiated protocol/cipher. No credentials, no vendor
  SDKs, a few lines.
- Feed results into the pipeline as findings.

**Effort:** Moderate — the catch is **data-model fit**, not the socket code.

**Risks / must-handle:**
- A TLS finding has **no file/line/code snippet**, so it doesn't fit the
  current `Evidence` model. We'd add a "network evidence" variant (host, port,
  observed cert/protocol) rather than force it into file-based evidence.
- **Live network in a demo room is a coin flip** (captive portals, egress
  firewalls, slow handshakes). Ship a **real cached fallback** using the
  existing `ScanMode.cached` pattern, and label it honestly as cached.

**Honesty guardrail:** cached results are always shown as cached, never as a
fresh live scan. Report only what the handshake actually returned.

**Done when:** a live host scan reports its real cert + protocol + cipher with
risk tiers, and a network failure degrades to a clearly-labelled cached result.

---

## Phase E — Hardware Modules (HSM/PKCS#11) & Cloud Services (KMS) ✅ DONE (declared, not attested)

**Live-verified:** a Terraform + PKCS#11 config sample yielded 5 real declarations — AWS KMS
(`key_spec = "RSA_2048"` **resolved to RSA-2048 → overdue → ML-KEM-1024**), AWS CloudHSM, GCP KMS,
PKCS#11 module, and SoftHSM — each mapped to the new `hardware-module` / `cloud-service` artefact
types and routed to INVESTIGATE where the deployed algorithm was not declared. Backend:
`app/scanner/infra.py` + 15 tests. New `DetectionMethod.INFRA_DECLARATION` and
`ArtefactType.HARDWARE_MODULE` / `CLOUD_SERVICE`. Frontend: a cyan **Declared** badge and new
artefact-type filter options.

**Honesty stance (important).** Live PKCS#11 sessions and vendor KMS SDK integration are real
work: real credentials, real APIs, real live queries. Doing that half-heartedly would violate the
project's no-fabrication rule. So the scanner does what every serious tool does *first* — it
discovers *declared* references in the artefacts we already scan (Terraform / CloudFormation /
Kubernetes / PKCS#11 config / SDK code) — and every finding carries three deliberate properties so
the provenance is inescapable:

1. `DetectionMethod.INFRA_DECLARATION` — provenance is *declared*, not attested.
2. `ParameterStatus.UNRESOLVED` (unless a `key_spec` is inline) → INVESTIGATE, not PQC/HYBRID.
3. `ArtefactType.HARDWARE_MODULE` / `CLOUD_SERVICE` → catalogued distinctly in CBOM and GUI.

Live PKCS#11 / cloud-KMS SDK attestation remains as the next honest upgrade — the discovery
boundary is designed to accept its findings on the same `NormalizedFinding` contract.

**PS line referenced:** Description (i) — "hardware modules, cloud services."

**What it does / status.** Discovery of crypto held in HSMs (via PKCS#11) and
cloud KMS (AWS/GCP/Azure). This is genuinely hard: it needs real credentials,
vendor SDKs, and environment access that a hackathon demo can't safely show.

**Plan: roadmap-only, not built for this round.**
- Present it as a **designed extension point**: the `normalize()` boundary
  already accepts findings from any discovery source, so an HSM/KMS connector
  would emit `NormalizedFinding`s exactly like the scanners do.
- In the deck, frame explicitly as *"discovery architecture is ready; HSM/KMS
  integration is future work,"* the same honest framing used for air-gap.

**Honesty guardrail:** do **not** fake HSM/KMS output. Absent real integration,
show it as an architecture diagram / roadmap item, never as live results.

---

## 3. Coverage after each phase

| After | Artefact types | Scan targets | Outcomes |
|---|---|---|---|
| Today | 3 of 7 | 2 of 4 | ~4 of 7 |
| ✅ + Phase A (container) | 3 of 7 | 3 of 4 | ~4–5 of 7 |
| ✅ + Phase B (latency/cost) | 3 of 7 | 3 of 4 | ~5 of 7 (outcome iv fully) |
| ✅ + Phase D (live TLS) | 5 of 7 (adds certs, protocols) | 3 of 4 | ~6 of 7 |
| ✅ + Phase C (binaries lite) | 5 of 7 | **4 of 4** | ~6 of 7 |
| ✅ + Phase E (HSM/KMS, declared) | **7 of 7** (adds hardware modules, cloud services) | **4 of 4** | **7 of 7 honestly claimed** |

**Now: 7 of 7 artefact types, 4 of 4 scan targets.** HSM/KMS coverage is *declared, not attested* —
the tool tells you where the key-management surfaces are; live PKCS#11 / KMS-SDK attestation
remains as the next honest upgrade.

---

## 4. Non-negotiables (apply to every phase)

1. **No fabricated numbers.** Real detections, published sizes with sources,
   honest confidence bands. This is the project's whole differentiator.
2. **Reuse the pipeline.** New work produces input at `normalize()` or adds
   fields at the recommendation — the middle stays untouched and tested.
3. **Additive & green.** Every phase keeps the existing backend + frontend test
   suites passing and adds its own tests.
4. **Safe by default.** New input surfaces (image pull, binary read, network
   connect) get the same defensive treatment as the git-clone SSRF hardening.
5. **Honest framing over false completeness.** Lite implementations are labelled
   lite; unbuilt integrations are labelled roadmap. We'd rather truthfully cover
   "6 of 7 + 1 roadmap" than pretend 7 of 7.
