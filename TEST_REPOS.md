# Blindspot ECDAT — Test Repositories

Public repos for exercising the scanner, grouped by the languages the rule packs
actually cover: **Python, C, Java, JavaScript/TypeScript, Go**.

All links are HTTPS GitHub URLs, so they pass the `ALLOWED_GIT_HOSTS` allowlist
and the clone-on-demand flow. Paste one into the Scanner page's target box.

> Note: URL scans require `git` in the environment doing the scan (fine locally;
> on Railway it needs the git build fix). Large repos can exceed
> `SEMGREP_TIMEOUT_SECONDS` (120s) and return empty/errored — start small.

---

## ⭐ Best picks for a live demo (fast + reliable hits)

| Language | Repo | URL |
|---|---|---|
| Python | pynacl | https://github.com/pyca/pynacl |
| C | OpenSSL | https://github.com/openssl/openssl |
| Java | jjwt | https://github.com/jwtk/jjwt |
| JS/TS | node-jsonwebtoken | https://github.com/auth0/node-jsonwebtoken |
| Go | golang-jwt | https://github.com/golang-jwt/jwt |
| — | Seeded demo repo | *(leave target blank)* |

JWT libraries are the sweet spot across Java/JS/Go: they use signing primitives
(RSA/ECDSA/Ed25519/HMAC) directly, lighting up multiple rules with little noise.

---

## Python
Rules target pyca/cryptography, PyCryptodome, hashlib (RSA/EC/AES/DES/MD5/SHA-1).

- https://github.com/pyca/cryptography — the library the rules are written against; densest hits
- https://github.com/paramiko/paramiko — SSH: RSA/ECDSA/AES/3DES
- https://github.com/pyca/pynacl — X25519/Ed25519/AES (fast)
- https://github.com/Legrandin/pycryptodome — DES/3DES/MD5/SHA-1 (weak-crypto signal)

## C (OpenSSL APIs)
Rules match RSA_/EC_/EVP_/AES_/DES_/MD5/SHA1 OpenSSL calls.

- https://github.com/openssl/openssl — flagship "scales to a real codebase" demo (~100 findings)
- https://github.com/libressl/portable — smaller OpenSSL-family; faster
- https://github.com/openssh/openssh-portable — uses OpenSSL RSA/EC/AES/DES

## Java (JCA)
Rules match `KeyPairGenerator.getInstance("RSA"/"EC"/"DSA"/...)`, ciphers, MD5/SHA-1.

- https://github.com/bcgit/bc-java — Bouncy Castle; dense JCA + RSA/EC/DSA/AES/DES/hash
- https://github.com/google/tink — EC/RSA, AEAD, lots of KeyPairGenerator
- https://github.com/jwtk/jjwt — JWT: RSA/EC/HMAC signing (small, fast)

## JavaScript / TypeScript (Node `crypto`)
Rules match `crypto.createHash("md5"/"sha1"/...)`, `createHmac`, cipher APIs.

- https://github.com/expressjs/session — crypto hashing/HMAC (small, quick)
- https://github.com/auth0/node-jsonwebtoken — JWT signing HMAC/RSA/EC (weak-vs-strong contrast)
- https://github.com/nodejs/node — huge, guaranteed hits but slow (big-repo moment only)

## Go (stdlib `crypto/*`)
Rules match `rsa.GenerateKey`, `ecdsa.GenerateKey`, `ed25519.GenerateKey`, `rsa.SignPKCS1v15`, etc.

- https://github.com/golang-jwt/jwt — JWT via rsa/ecdsa/ed25519 (clean, fast, high signal)
- https://github.com/minio/minio — real RSA/ECDSA/AES across the codebase
- https://github.com/cloudflare/cfssl — TLS/PKI toolkit; heavy RSA/ECDSA/cert generation

---

## Won't produce findings (skip — will look broken but isn't)
Any language without a rule pack: Rust, Ruby, PHP, C#, Kotlin, Swift, etc.
Source findings there will be zero (binary/container scanning may still catch
compiled crypto, but source-level rules won't match).
