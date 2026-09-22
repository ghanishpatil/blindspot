# Manual test — UI features shipped this sprint

Prove every user-visible feature added this session works by driving the
actual app. Each section is standalone; skip to whichever demo moment
you're rehearsing.

| # | Feature | Time | Frontend surface | Backend endpoint |
|---|---|---|---|---|
| A | Storage backend chip (air-gap proof) | 1 min | Top-bar pill | `GET /api/health` |
| B | Live TLS bundled into a source scan | 2 min | Textarea on Scanner | `POST /api/scan` |
| C | Server scan history + trend chart | 3 min | Two Dashboard panels | `GET /api/scans*` |
| D | Detection-source badges on findings | 1 min | Findings table + Findings detail | any scan |
| E | Cloud KMS attestation (moto, no cloud account) | 10 min | Findings table shows AWS KMS | `POST /api/scan` |
| F | Cross-scan aggregation via curl (talking points) | 2 min | Terminal only | `GET /api/scans/trend` |

---

## 0 · One-time setup

You need **two terminals** open, both in `d:\blindspot`.

* **Terminal 1** — backend
* **Terminal 2** — frontend

If they're already running from a previous session, skip to whichever
section you're rehearsing.

### Terminal 1 — backend

```powershell
cd d:\blindspot\backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8000 --reload
```

Wait for `Uvicorn running on http://127.0.0.1:8000`.

### Terminal 2 — frontend

```powershell
cd d:\blindspot\frontend
npm run dev
```

Open the URL Vite prints (usually `http://127.0.0.1:5173`). You should
land on `Landing` -> click `Try the Demo` -> `Dashboard`.

---

## A · Storage backend chip — air-gap proof (1 min)

Goal: point at a chip in the top-right corner and say *"nothing leaves the
box."*

1. Open `d:\blindspot\backend\.env` and set:
   ```
   STORAGE_BACKEND=local
   ```
2. Restart the backend (Ctrl-C Terminal 1, then re-run the uvicorn
   command).
3. In the startup log, look for:
   ```
   Storage backend: requested=local effective=local
   ```
4. Hard-refresh the frontend (Ctrl-Shift-R). Top-right of every page now
   shows a green pill:
   ```
   [shield]  LOCAL · Air-gap
   ```
5. To flip back to Firebase mode, set `STORAGE_BACKEND=auto` (or
   `firebase`) and restart. The chip turns blue: `FIREBASE`.

**Say on stage:** *"Set one env var and no Firebase call ever happens.
Every scan lands on the local disk under `artifacts/`. The frontend
proves the state -- hover the chip for the exact directory paths."*

---

## B · Live TLS bundled into a source scan (2 min)

Goal: show one scan producing both source findings and a live certificate
finding, both flowing through the same risk pipeline.

1. Navigate to `Scanner` (left sidebar, `Scan` icon).
2. Leave the target field blank -- the seeded demo repo will scan.
3. Scroll down to the **Live TLS endpoints (optional)** textarea.
4. Paste:
   ```
   github.com, cloudflare.com:443
   ```
5. You should see a small chip appear: `2 targets`.
6. Click **Start Discovery Scan**.
7. Wait ~10 seconds. The findings table appears, and among the rows
   you'll see two with a cyan **LIVE TLS** badge -- one per host.
8. Click either TLS row. `FindingDetail` shows the full analysis chain:
   evidence (the host:port + cert subject) -> classification (signature,
   long-lived trust anchor if a public CA) -> Mosca risk -> a hybrid /
   PQC recommendation.

**Say on stage:** *"A real ECDSA certificate off the wire is treated
identically to ECDSA in source code -- same classifier, same Mosca
calculation, same recommendation."*

---

## C · Server scan history + trend chart (3 min)

Goal: prove the tool remembers scans across restarts and can show a
trend line.

**Setup:** you need at least 2 completed scans on disk in the same
project. Run one now if you haven't:

1. Go to Scanner, blank target, click **Start Discovery Scan**.
2. Wait for completion.
3. Repeat: another scan, blank target, click again.

Now:

4. Restart the backend (Ctrl-C, re-run uvicorn). Notice the log line:
   ```
   Startup rehydration: last scan restored from cache.
   ```
5. Navigate to **Overview** (Dashboard).
6. Scroll down past the KPIs and Cryptographic surface tiles.
7. You now see **two side-by-side panels**:
   - **Trend / Risk tier over time** -- a line chart with three lines
     (Overdue red, Transitional amber, Low-risk green). One dot per scan.
   - **Server history / Scans on disk** -- a compact table with each
     scan's id, project, timestamp, and per-tier counters.
8. Both survive backend restart. They come from `GET /api/scans` and
   `GET /api/scans/trend`, not localStorage.

**Say on stage:** *"Every scan is mirrored to disk. Restart the backend,
data is still there. In an on-prem deployment, this is your portfolio
view over time -- no database, no Firebase."*

---

## D · Detection-source badges on findings (1 min)

Goal: show that every finding advertises where it came from, at a glance.

1. Navigate to **Findings** (or scroll to the Findings section on the
   Dashboard).
2. The table now has a **Source** column with colored pills:
   - Orange **AWS KMS** -- live cloud-KMS attestation
   - Sky **Azure KV** -- live Azure Key Vault attestation
   - Emerald **GCP KMS** -- live GCP KMS attestation
   - Purple **HSM · PKCS#11** -- live HSM attestation
   - Cyan **LIVE TLS** -- live network certificate
   - Slate **On-disk cert / On-disk key** -- static file discovery
   - Blue **Source (AST)** -- Semgrep AST match
   - Fuchsia **MANIFEST** -- dependency manifest
   - Teal **DECLARED** -- IaC / SDK declaration of an HSM / KMS surface
3. On cloud-KMS rows an extra pill appears next to the source badge:
   `rotation enabled` (green), `rotation disabled` (red), or
   `rotation n/a` (grey). These are read straight off the vendor API.
4. Click any row -> `FindingDetail`. The hero header now displays the
   same source badge next to the algorithm name and the tier chip.

**Say on stage:** *"Ten discovery paths, one dashboard. A judge scanning
the list sees at a glance which findings are attested from a live vault
versus inferred from source."*

---

## E · Cloud KMS attestation via moto (10 min)

Goal: prove AWS KMS live-attestation works, without needing a real AWS
account, with real boto3 calls hitting a local mock.

**Only run this section if you have ~10 minutes and want the ultimate
"real-code-path" demo.** Skip otherwise -- the 27 AWS-KMS unit tests
already prove the same code works.

1. Install moto's HTTP server mode:
   ```powershell
   cd d:\blindspot\backend
   .\.venv\Scripts\pip.exe install "moto[server]"
   ```
2. In a **new terminal**, start the fake AWS server:
   ```powershell
   cd d:\blindspot\backend
   .\.venv\Scripts\python.exe -m moto.server -p 5000
   ```
   Wait for `Running on http://127.0.0.1:5000/`. Leave it running.

3. In a **fourth terminal**, seed the fake AWS with a few keys:
   ```powershell
   cd d:\blindspot\backend
   .\.venv\Scripts\python.exe -c @"
   import boto3
   kms = boto3.client('kms',
       region_name='us-east-1',
       endpoint_url='http://127.0.0.1:5000',
       aws_access_key_id='test',
       aws_secret_access_key='test',
   )
   sym = kms.create_key(KeySpec='SYMMETRIC_DEFAULT', KeyUsage='ENCRYPT_DECRYPT', Description='data-at-rest')
   kms.enable_key_rotation(KeyId=sym['KeyMetadata']['KeyId'])
   kms.create_key(KeySpec='RSA_2048', KeyUsage='SIGN_VERIFY', Description='code-signing')
   kms.create_key(KeySpec='ECC_NIST_P256', KeyUsage='SIGN_VERIFY', Description='jwt-signing')
   print('Seeded 3 keys into local moto KMS.')
   "@
   ```
4. Point the backend at moto by adding these lines to `backend\.env`:
   ```
   AWS_KMS_SCAN_ENABLED=true
   AWS_KMS_REGION=us-east-1
   AWS_ENDPOINT_URL_KMS=http://127.0.0.1:5000
   AWS_ACCESS_KEY_ID=test
   AWS_SECRET_ACCESS_KEY=test
   ```
5. Restart the backend (Ctrl-C Terminal 1, re-run uvicorn).
6. In the frontend, go to **Scanner** and click **Start Discovery Scan**
   (no repository path needed -- KMS attestation is not target-scoped).
7. Open **Findings**. You should see three new rows tagged with the
   orange **AWS KMS** source badge:
   - `AES-256` with `rotation enabled`
   - `RSA-2048` with `rotation n/a` (asymmetric keys don't auto-rotate)
   - `ECDSA-P-256` with `rotation n/a`
8. Click the AES row -> `FindingDetail`. The evidence snippet reads:
   ```
   aws-kms key_id=<uuid> spec=SYMMETRIC_DEFAULT usage=ENCRYPT_DECRYPT
   manager=CUSTOMER state=Enabled origin=AWS_KMS rotation=enabled
   ```

**Say on stage:** *"Same code path as production AWS. The scanner
enumerates keys, reads algorithm and key size and rotation configuration
directly from `DescribeKey` and `GetKeyRotationStatus`, and each key
flows through the same classifier and Mosca engine as source findings."*

Azure Key Vault and GCP KMS follow the exact same pattern -- optional
SDK install, opt-in env vars, tests cover both -- but there's no
local mock for either, so demo those against a real trial subscription
or reference the 47 combined unit tests instead.

---

## F · Cross-scan aggregation via curl (2 min)

Goal: show a judge the raw API surface, no UI in the way.

```powershell
# List every scan on disk (newest first)
curl.exe http://127.0.0.1:8000/api/scans

# Trend line for a project (needs >= 2 scans in that project)
curl.exe "http://127.0.0.1:8000/api/scans/trend?project_id=demo"

# Full record for one specific scan
curl.exe http://127.0.0.1:8000/api/scans/scan-77da684f109b

# Health endpoint -- point at .storage.effective for air-gap proof
curl.exe http://127.0.0.1:8000/api/health
```

Pipe through `python -m json.tool` to pretty-print.

**Say on stage:** *"The dashboard is one client. Any auditor with curl
and an API token can query the same on-disk record set."*

---

## G · Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Storage chip shows `Storage ?` | Backend was up before F1 shipped | Restart backend |
| TLS scan says `refusing to scan internal address` | You used `localhost` or a private IP | Point at a public host |
| No `AWS KMS` badges | `AWS_KMS_SCAN_ENABLED` still false | Check `.env`, restart backend |
| Trend chart is empty | < 2 scans on disk in the project | Run one more scan |
| Frontend shows demo data despite scan | Backend is unreachable (`http://127.0.0.1:8000` down) | Check Terminal 1 |
| `python-pkcs11 not installed; skipping` in logs | Optional dep for HSM demo | Install SoftHSM + `pip install python-pkcs11` |

---

## Verification (belt and braces)

Everything in this doc is also covered by the automated test suites.
When in doubt, run them:

```powershell
# Backend -- 550 tests
cd d:\blindspot\backend
.\.venv\Scripts\python.exe -m pytest -q --no-header --ignore=tests/test_multilang_scanner.py

# Frontend -- 84 tests
cd d:\blindspot\frontend
npm test -- --run
```

Both should exit clean.
