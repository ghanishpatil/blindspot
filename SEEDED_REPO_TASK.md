# Task: Build the Seeded Demo Repo

## What this is
A small, fake codebase for ECDAT to scan during the demo. You are writing code that deliberately contains specific cryptographic patterns — not a real application. It needs to be predictable, not functional or elegant.

## Why it's needed
The demo scans this repo live on stage. We need to know in advance exactly what the tool should find, so we can confirm it works correctly and script the demo around guaranteed output — not a live, unpredictable scan of a real random repo.

## Requirements: 5 planted artefacts

Build one small file per artefact (any file structure is fine, keep it simple). Each needs a comment marking which artefact it is.

| # | Artefact | What to write | Language/library |
|---|---|---|---|
| 1 | **Overdue** | RSA-2048 key generation + encryption, used on data framed as long-lived/sensitive (e.g. "transaction records," "customer records") | Python `Crypto`/`cryptography`, or Java equivalent |
| 2 | **Transitional** | ECDH key exchange, framed as protecting active/ongoing traffic (e.g. "internal API," "service-to-service link") | Python `cryptography` (ECDH), or Java equivalent |
| 3 | **Low-risk** | ECDSA signature on something explicitly short-lived (e.g. "session token," "1-hour token") | Python `cryptography` (ECDSA), or Java equivalent |
| 4 | **Weak-crypto-today** | MD5 hash usage, or a hardcoded API key/password string in code | Any |
| 5 | **Unresolvable** | A key-generation call where the key size is a variable/constant from elsewhere, not a literal number (e.g. `RSA.generate(KEY_SIZE)` where `KEY_SIZE` is defined in a config file) | Same language as #1 |

## Also needed

- **One dependency manifest file** (`requirements.txt` for Python, or `pom.xml` for Java) listing a crypto library as a dependency — e.g. `pycryptodome` or `cryptography`, or `bouncycastle` for Java. This is for testing the lockfile-parsing detection, separate from the source-code detection.

- **One metadata file** (`artefact_metadata.json` or similar) declaring, per artefact, its assumed values so the risk engine has something to read:
  - `data_lifetime_years` (X) — e.g. 15 for the overdue one, 3 for transitional, ~0.04 (an hour) for low-risk
  - `criticality` — high / medium / low

Ask the risk-engine owner what exact field names/JSON shape they want before finalizing this file, since it feeds directly into their stage.

## Constraints

- Keep it small — 5-6 files total, each short. This is not a real app, don't add unrelated code.
- Pick ONE language if possible (Python is easiest given the team's stack) unless someone wants to also prove multi-language detection.
- Every file should be plausible-looking (realistic variable/function names, brief comments) but doesn't need to run or do anything real.
- Don't use real secrets/keys anywhere, even fake-looking ones that resemble real formats — just use obviously placeholder values.

## Deliverable
A folder (can be its own small Git repo) with the 5 code files + 1 manifest file + 1 metadata file, ready to hand to whoever's building the Stage 1 scanner.
