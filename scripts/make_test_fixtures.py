"""Generate a fixture directory used to manually verify R1 and R2.

Run this once from the repo root::

    d:\\blindspot\\backend\\.venv\\Scripts\\python.exe scripts/make_test_fixtures.py

It writes ``d:\\blindspot\\test-fixtures/`` containing:

* Real cert / key material (RSA, ECDSA, Ed25519) — R1 targets
* A PKCS#12 file stub — R1 keystore target
* Inline PEM inside a ``.env`` file — R1 dotenv target
* Realistic nginx, sshd, Apache, OpenSSL, PostgreSQL, Java, and .NET config
  files — R2 targets

Point Blindspot at the resulting directory to see every R1 / R2 detection
path fire on real artefacts.
"""

from __future__ import annotations

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID


ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "test-fixtures"


def _self_signed(private_key, subject_cn: str = "blindspot-test.example.com"):
    """Return a small self-signed cert for testing purposes only."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=90))
    )
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return builder.sign(private_key, algorithm=None)
    return builder.sign(private_key, algorithm=hashes.SHA256())


def _pem_cert(private_key) -> bytes:
    return _self_signed(private_key).public_bytes(serialization.Encoding.PEM)


def _pem_key(private_key) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _write(path: Path, content: bytes | str) -> None:
    """Write ``content`` to ``path`` and print what was written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, str):
        path.write_text(content, encoding="utf-8")
        size = len(content)
    else:
        path.write_bytes(content)
        size = len(content)
    print(f"  wrote {path.relative_to(ROOT)}  ({size} bytes)")


# ── R1 fixtures — cert / key / keystore ────────────────────────────────────

def build_r1_fixtures() -> None:
    print("Generating R1 fixtures (certs + keys)...")

    # RSA-2048 certificate — the enterprise-normal TLS server cert.
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _write(OUT / "certs" / "server.crt", _pem_cert(rsa_key))

    # RSA-2048 private key — matching pair.
    _write(OUT / "certs" / "server.key", _pem_key(rsa_key))

    # ECDSA P-256 certificate — modern signing key.
    ec_key = ec.generate_private_key(ec.SECP256R1())
    _write(OUT / "certs" / "signer.pem", _pem_cert(ec_key))

    # Ed25519 SSH-style private key with no extension — exercises the SSH
    # basename detection path (id_rsa / id_ed25519 / id_ecdsa / id_dsa).
    ed_key = ed25519.Ed25519PrivateKey.generate()
    _write(OUT / "keys" / "id_ed25519", _pem_key(ed_key))

    # PKCS#12 keystore stub — bytes only, existence is the finding.
    _write(
        OUT / "keys" / "vault.p12",
        b"\x30\x82\x00\x04" + b"blindspot-p12-placeholder" + b"\x00" * 60,
    )

    # Inline PEM inside a .env config file — exercises the dotenv path
    # (``Path('.env').suffix`` returns '', so we match by name).
    env_body = (
        "# Local secrets for the test fixture app.\n"
        "APP_ENV=development\n"
        "TLS_CERT_PEM=\"\"\"\n"
        + _pem_cert(rsa_key).decode()
        + "\"\"\"\n"
        "OTHER_SETTING=42\n"
    )
    _write(OUT / "secrets" / ".env", env_body)


# ── R2 fixtures — config-file crypto policy ────────────────────────────────

_NGINX = """\
# Sample nginx config for Blindspot fixture tests.
server {
    listen              443 ssl;
    server_name         blindspot-test.example.com;

    ssl_certificate     /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers on;

    location / {
        return 200 "hello";
    }
}
"""

_SSHD = """\
# Sample sshd_config for Blindspot fixture tests.
Port 22
Protocol 2

# A deliberately mixed set: modern defaults, one weak MAC, and a PQ hybrid.
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr
KexAlgorithms curve25519-sha256,mlkem768x25519-sha256,ecdh-sha2-nistp256
MACs hmac-sha2-256,hmac-sha2-512,hmac-md5
HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,ssh-rsa

PasswordAuthentication no
PermitRootLogin no
"""

_APACHE = """\
# Sample httpd.conf for Blindspot fixture tests.
Listen 443
ServerName blindspot-test.example.com

<VirtualHost *:443>
    SSLEngine on
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:HIGH:!aNULL
    SSLHonorCipherOrder on
</VirtualHost>
"""

_OPENSSL = """\
# Sample openssl.cnf for Blindspot fixture tests.
openssl_conf = default_conf

[default_conf]
ssl_conf = ssl_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
MinProtocol = TLSv1.2
MaxProtocol = TLSv1.3
CipherString = ECDHE-RSA-AES256-GCM-SHA384
"""

_JAVA_SECURITY = """\
# Sample java.security for Blindspot fixture tests.
# Sample lines only; a real file has hundreds more.

jdk.tls.disabledAlgorithms=SSLv3, TLSv1, TLSv1.1, RC4, DES, MD5withRSA, \\
    DH keySize < 1024, EC keySize < 224, RSA keySize < 2048, \\
    include jdk.disabled.namedCurves

jdk.certpath.disabledAlgorithms=MD2, MD5, SHA1 jdkCA & usage TLSServer, \\
    RSA keySize < 1024, DSA keySize < 1024

jdk.tls.legacyAlgorithms=NULL, anon, RC4, DES, 3DES_EDE_CBC
"""

_POSTGRESQL = """\
# Sample postgresql.conf for Blindspot fixture tests.
listen_addresses = '*'
port = 5432
ssl = on
ssl_ciphers = 'ECDHE-RSA-AES256-GCM-SHA384'
ssl_min_protocol_version = 'TLSv1.2'
ssl_ecdh_curve = 'prime256v1'
"""

_WEB_CONFIG = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <httpProtocol sslProtocols="TLSv1.2,TLSv1.3" />
  </system.webServer>
  <system.web>
    <machineKey validation="HMACSHA256" decryption="AES" />
  </system.web>
</configuration>
"""


def build_r2_fixtures() -> None:
    print("Generating R2 fixtures (config policies)...")
    _write(OUT / "nginx.conf", _NGINX)
    _write(OUT / "sshd_config", _SSHD)
    _write(OUT / "webserver" / "httpd.conf", _APACHE)
    _write(OUT / "openssl.cnf", _OPENSSL)
    _write(OUT / "java.security", _JAVA_SECURITY)
    _write(OUT / "postgresql.conf", _POSTGRESQL)
    _write(OUT / "webapp" / "web.config", _WEB_CONFIG)


def main() -> None:
    if OUT.exists():
        print(f"Fixture directory already exists at {OUT} — overwriting files.")
    build_r1_fixtures()
    build_r2_fixtures()
    print()
    print("Done. Fixture directory:")
    print(f"  {OUT}")
    print()
    print("Point Blindspot at that path — see MANUAL_TEST_R1_R2.md for the")
    print("step-by-step verification flow.")


if __name__ == "__main__":
    main()
