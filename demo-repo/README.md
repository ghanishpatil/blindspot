# Seeded demo repository — ECDAT scan target

**This is not a real application.** It is a deliberately constructed scan target
for the Blindspot ECDAT demo. The code is plausible but does not run as a
system, and it is not intended to.

Every artefact exists so that we know in advance exactly what the tool should
find, so the demo can be scripted around guaranteed output rather than an
unpredictable scan of a random repository.

Built against `SEEDED_REPO_TASK.md`. Machine-readable expectations live in
`artefact_metadata.json`, which the backend tests read directly.

---

## Artefacts

### The five headline cases

These carry the demo's risk narrative.

| # | File | Artefact | Algorithm | Expected outcome |
| --- | --- | --- | --- | --- |
| 1 | `high_risk_rsa.py` | Overdue | RSA-2048 | `overdue` → urgent PQC |
| 2 | `transitional_tls.py` | Transitional | ECDH P-256 | `transitional` → hybrid |
| 3 | `low_risk_token.py` | Low risk | ECDSA P-256 | `low-risk` → defer |
| 4 | `weak_crypto_md5.py` | Weak today | MD5 | broken **today** → remediate now |
| 5 | `unresolvable_keygen.py` | Unresolvable | RSA, size unknown | `overdue`, reduced confidence → investigate |

`crypto_config.py` supports artefact 5. It holds the constant that artefact 5
imports, and it must stay a **separate module** — that separation is the whole
point of the artefact.

### Coverage artefacts

Build spec §9 requires the scanner to detect nine algorithms, and §20 requires a
passing test for each. The seed task only asked for four of them, so these four
files close the gap.

| # | File | Algorithm | Why it is here |
| --- | --- | --- | --- |
| 6 | `field_encryption_aes.py` | AES-256 (GCM + CBC) | AES coverage, mode extraction, and the contrast case |
| 7 | `legacy_tape_3des.py` | 3DES-CBC | 3DES coverage |
| 8 | `legacy_pin_des.py` | DES-ECB | DES coverage, and a second library API |
| 9 | `partner_manifest_sha1.py` | SHA-1 | SHA-1 coverage |

---

## The three cases that prove the engine is actually reasoning

**Artefact 6 vs artefact 1 — lifetime alone must not decide.** Both hold data
for 15 years at high criticality. Artefact 1 is `overdue`; artefact 6 is
`low-risk`. The difference is that AES is symmetric and Shor does not break it.
If the tool reports artefact 6 as overdue, it is keying off data lifetime and is
wrong.

**Artefact 4 — broken today is not the same as quantum risk.** MD5 is
collision-broken now, yet its *quantum* tier is low, because Grover only halves
preimage resistance. Two independent axes, and the tool must not collapse them.

**Artefact 3 — not everything is urgent.** Shor breaks ECDSA, so this *is*
quantum-vulnerable. It is still low risk, because signatures provide
authenticity rather than confidentiality: harvest-now-decrypt-later does not
apply, and a signature forged in fifteen years is worthless against a token that
expired in an hour.

---

## Dependency manifest

`requirements.txt` declares three crypto providers, so the dependency parser has
something real to read:

- `cryptography` — used throughout, so use is confirmed in source
- `pyOpenSSL` — capability present, use **not** confirmed in source
- `pycryptodome` — used in `legacy_pin_des.py`

`pyOpenSSL` is how OpenSSL appears in a Python dependency graph; there is no
`openssl` package on PyPI. It is deliberately unused in source, because a
declared dependency proves *capability*, not *use*, and its confidence must
therefore sit below the direct API-call findings.

---

## Notes for the scanner

Two constraints were verified empirically against semgrep 1.176.1 before Phase 4
was written. Both are recorded in `artefact_metadata.json`.

**Semgrep CE emits no metavariable bindings**, and gags `lines` and
`fingerprint` to `"requires login"`. Only `check_id`, `path`, and the
`start`/`end` line, column and offset are usable. So semgrep *locates* call
sites; evidence snippets get sliced from the source at those offsets, and
parameters are extracted with Python's `ast`.

**Neither artefact 1 nor artefact 5 uses a literal key size.** Both pass a name.
Artefact 1's constant is defined in the same file; artefact 5's arrives by
import. The module is the resolution boundary: same-file constants resolve,
imported names do not. Following artefact 5's import to recover `2048` would
defeat the artefact.

---

## Safety

No real keys, secrets, or credentials. The one credential-shaped string is
`LEGACY_PARTNER_API_KEY = "PLACEHOLDER_NOT_A_REAL_KEY"`, which is unmistakably a
placeholder. No network calls, no side effects, and nothing nondeterministic, so
repeated scans produce equivalent results.
