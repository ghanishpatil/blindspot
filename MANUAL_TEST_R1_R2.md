# Manual test guide — R1 & R2 (UI walkthrough)

Prove R1 (static cert / key discovery) and R2 (config-file crypto policy
scanning) work end-to-end by driving the actual app: type a path, click a
button, see the findings light up in the dashboard.

Total time: ~5 minutes once you've done it once.

---

## 0 · One-time setup

You need **three terminals** open in `d:\blindspot`.

* **Terminal 1** — backend
* **Terminal 2** — frontend
* **Terminal 3** — the fixture generator (only used once, then you can close it)

If the backend or frontend is already running from a previous session, skip
those steps.

---

## Step 1 — Generate the fixture directory (Terminal 3)

Only needed once. Regenerates a folder full of realistic cert / key / config
files that will exercise every R1 and R2 detection path.

```powershell
cd d:\blindspot
backend\.venv\Scripts\python.exe scripts\make_test_fixtures.py
```

You should see a list of 13 files being written and then:

```
Done. Fixture directory:
  D:\blindspot\test-fixtures
```

That's your scan target. You can close Terminal 3 now.

## Step 2 — Start the backend (Terminal 1)

```powershell
cd d:\blindspot\backend
.venv\Scripts\python.exe -m uvicorn app.main:app --port 8000
```

Wait for:

```
INFO:     Uvicorn running on http://127.0.0.1:8000
```

Leave this terminal running.

## Step 3 — Start the frontend (Terminal 2)

```powershell
cd d:\blindspot\frontend
npm run dev
```

Wait for:

```
  ➜  Local:   http://127.0.0.1:5173/
```

Leave this terminal running too.

---

## Step 4 — Open the app and run the scan

1. Open <http://127.0.0.1:5173> in your browser.
2. Navigate to the **Scan** page (via the top nav / sidebar — depends on the
   current layout; the page title is "Cryptographic Discovery Scanner").
3. **Make sure the "Repository" target type is selected** (not "Container
   Image"). The Repository tab is the default.
4. In the input box labelled *"Target Repository (GitHub URL or local path)"*,
   type exactly:

    ```
    d:\blindspot\test-fixtures
    ```

    The UI will send this as `repositoryPath` because it doesn't start with
    `http://` — local-path scanning is allowed because `BLINDSPOT_ENV` is
    `development` in your `.env`.

5. Leave **Execution Mode** as *"Live Pipeline (Synchronous)"*.
6. Click the big blue **Start Discovery Scan** button (bottom right).

You'll see the pipeline animation for a few seconds:
* Scanning source code...
* Building CBOM...
* Classifying artefacts...
* Computing risk scores...
* Generating recommendations...

Then a green *"Scan Execution Completed"* banner appears. Roughly 1 second
later the app auto-navigates you to the **Dashboard** page.

---

## Step 5 — Verify R1 findings in the Dashboard

R1 gives you certificates and keys discovered on disk. In the Dashboard, look
at the **Cryptographic Inventory & Findings** table (or panel — depending on
which iteration of the UI is running).

**Filter or sort by artefact type = certificate**, and confirm you see:

| Algorithm | Detection method | File | What it proves |
|---|---|---|---|
| RSA-2048 | `static_cert_file` | `certs\server.crt` | Basic RSA PEM certificate read from disk |
| ECDSA (secp256r1) | `static_cert_file` | `certs\signer.pem` | EC certificate — curve resolved from the ASN.1 |
| RSA-2048 | `static_cert_file` | `secrets\.env` | **Inline PEM inside a dotenv file** — proves R1's `.env` classifier fix |

**Filter or sort by artefact type = signature or key-exchange**, and confirm:

| Algorithm | Detection method | File | What it proves |
|---|---|---|---|
| RSA-2048 | `static_key_material` | `certs\server.key` | Private key decoded, key size read |
| Ed25519 | `static_key_material` | `keys\id_ed25519` | **SSH-style filename with no extension** — proves R1's basename-detection fix |

**Look for the keystore entry:**

| Algorithm | Detection method | Parameter status | File |
|---|---|---|---|
| PKCS12-Keystore | `static_keystore` | **UNRESOLVED** | `keys\vault.p12` |

If you click that finding to open the detail view, you should see the
"Unresolved parameters" chip listing `algorithm`, `key_size`, `curve`. That's
the honesty layer: file existence confirmed, contents opaque without the
password.

## Step 6 — Verify R2 findings in the Dashboard

R2 gives you protocols, ciphers, KEX, MACs, and host-key algorithms declared
in seven configuration file families.

**Filter or sort by artefact type = protocol**, and confirm you see:

| Algorithm | Parameter | File | Notes |
|---|---|---|---|
| TLS | 1.2 | `nginx.conf` | Protocol version enabled |
| TLS | 1.3 | `nginx.conf` | Protocol version enabled |
| TLS | 1.2 | `openssl.cnf` | OpenSSL MinProtocol |
| TLS | 1.3 | `openssl.cnf` | OpenSSL MaxProtocol |
| TLS | 1.2 | `postgresql.conf` | PG ssl_min_protocol_version |
| TLS | 1.2 | `webapp\web.config` | .NET sslProtocols |
| TLS | 1.3 | `webapp\web.config` | .NET sslProtocols |
| **TLS-Hardening-Policy** | — | `java.security` | **jdk.tls.disabledAlgorithms** — click it, the evidence snippet lists what's disabled. RC4 / MD5 / DES should NOT appear as their own findings. |
| CertPath-Hardening-Policy | — | `java.security` | jdk.certpath.disabledAlgorithms |
| TLS-Legacy-Policy | — | `java.security` | jdk.tls.legacyAlgorithms |
| TLS-Policy | — | `webserver\httpd.conf` | Apache's `all` cipher class became a policy meta-finding |

**Filter or sort by artefact type = encryption:**

| Algorithm | Parameter | File | Notes |
|---|---|---|---|
| ECDHE-RSA-AES256-GCM-SHA384 | — | `nginx.conf`, `openssl.cnf`, `postgresql.conf`, `webserver\httpd.conf` | Same concrete cipher across four different files — proves the OpenSSL cipher-spec parser is family-agnostic |
| ECDHE-RSA-CHACHA20-POLY1305 | — | `nginx.conf`, `webserver\httpd.conf` | Concrete cipher suite |
| AES | 256 | `sshd_config` | Canonical mapping: `aes256-gcm@openssh.com` → AES-256 |
| ChaCha20-Poly1305 | — | `sshd_config` | Canonical mapping: `chacha20-poly1305@openssh.com` |
| AES | — | `webapp\web.config` | .NET machineKey decryption attribute |

**Filter or sort by artefact type = key-exchange:**

| Algorithm | Parameter | File | Notes |
|---|---|---|---|
| X25519 | — | `sshd_config` | Modern KEX |
| **ML-KEM-768-X25519-Hybrid** | 768 | `sshd_config` | **Post-quantum hybrid recognised** — this is the moment worth demoing |
| ECDH | secp256r1 | `sshd_config` | Classical ECDH |
| ECDH | prime256v1 | `postgresql.conf` | ECDH with the curve pulled from `ssl_ecdh_curve` |

**Filter or sort by artefact type = mac:**

| Algorithm | File | Notes |
|---|---|---|
| HMAC-SHA-256 | `sshd_config`, `webapp\web.config` | Modern MAC |
| HMAC-SHA-512 | `sshd_config` | Modern MAC |
| **HMAC-MD5** | `sshd_config` | **Weak MAC catalogued honestly** — the fixture declares it as enabled so the scanner reports it |

**Filter or sort by artefact type = signature:**

| Algorithm | Parameter | File | Notes |
|---|---|---|---|
| Ed25519 | — | `sshd_config` | SSH host-key algorithm |
| ECDSA | secp256r1 | `sshd_config` | SSH host-key algorithm |
| RSA | — | `sshd_config` | SSH host-key algorithm |

---

## Step 7 — Click a finding to see the detail view

Click any card / row. The FindingDetail page shows:

* **Algorithm** and **display name** at the top
* **Detection method** — this is the field that proves which scanner
  produced the finding. Look for `static_cert_file`, `static_key_material`,
  `static_keystore`, and `config_policy_declared`.
* **Confidence band** — HIGH for R1 findings, MEDIUM for R2 findings.
* **Evidence** — file path, line number where applicable, and the actual
  snippet (subject/issuer/notAfter for certs; the config directive for R2).
* **Chain of analysis** — classify → risk → recommend, showing how the
  finding flowed downstream.

For the `java.security` "TLS-Hardening-Policy" finding, open the detail view
and inspect the evidence snippet — it should contain the disabled-algorithms
list (`SSLv3, TLSv1, TLSv1.1, RC4, DES, MD5withRSA, ...`). Those algorithm
names never appear as their own findings; that's the honesty guardrail
visible in the product.

---

## Success checklist

Tick these off as you click through:

- [ ] Scan completes without error, banner reads *"Scan Execution Completed"*
- [ ] Dashboard shows roughly 40–50 total findings (R1 + R2 + whatever else the source / infra / binary scanners find in the fixture directory — those are additional real detections, not noise)
- [ ] All 6 R1 findings visible with their exact detection methods
- [ ] Ed25519 finding in `keys\id_ed25519` (proves SSH-basename fix)
- [ ] RSA-2048 finding in `secrets\.env` (proves dotenv fix)
- [ ] `vault.p12` finding shows **UNRESOLVED** with the unresolved-parameter chip
- [ ] `ML-KEM-768-X25519-Hybrid` finding visible in `sshd_config`
- [ ] `HMAC-MD5` finding visible in `sshd_config`
- [ ] `TLS-Hardening-Policy` finding visible in `java.security` and clicking into it shows the disabled list in the evidence snippet
- [ ] No finding named `RC4`, `DES`, `MD5withRSA`, `SSLv3`, or `TLSv1` appears (Apache negations and Java disabled list are correctly suppressed)
- [ ] Every finding card shows the detection method label

---

## Rerunning after code changes

If you change scanner code and want to re-verify, you don't need to
regenerate the fixtures — they don't change. Just:

1. Restart the backend (Ctrl+C in Terminal 1, then re-run the uvicorn command)
2. Return to the Scan page, click **Start Discovery Scan** again

If you close the browser, the last scan is still in the backend's in-memory
store, so the Dashboard shows the previous run's findings until you scan again.

---

## Cleanup

`test-fixtures/` is already gitignored, so it will never be committed. To
remove it locally:

```powershell
Remove-Item -Recurse -Force d:\blindspot\test-fixtures
```

---

## Troubleshooting

**"Local path scanning is disabled here. Provide a repositoryUrl instead."**

Your `.env` has `BLINDSPOT_ENV=production`. Change it to
`BLINDSPOT_ENV=development` (the current default value in `backend\.env`
already is) and restart the backend.

**"A scan is already in progress. Please retry shortly."**

The single-flight lock is doing its job. Wait ~10 seconds and click again.

**No findings at all after scan completes**

Confirm you typed `d:\blindspot\test-fixtures` in the input box (backslashes
are fine — the backend resolves the path). If the box was empty when you
clicked Start Scan, the scanner ran against the seeded demo repo instead,
which has different fixtures.

**A specific R1 or R2 finding is missing**

Run Step 1 again (`make_test_fixtures.py`) — it's idempotent and safe to
regenerate. If a finding is still missing after that, please share the
Dashboard listing and I'll investigate.
