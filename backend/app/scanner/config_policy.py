"""Config-file crypto policy scanner — R2 in PS_ALIGNMENT_PLAN.md.

Real enterprise cryptography does not only live in code and on-disk key
material — an enormous amount of it is *declared* in server and JDK
configuration:

* ``nginx.conf`` — ``ssl_protocols``, ``ssl_ciphers``
* Apache ``httpd.conf`` — ``SSLProtocol``, ``SSLCipherSuite``
* ``sshd_config`` / ``ssh_config`` — ``Ciphers``, ``KexAlgorithms``, ``MACs``,
  ``HostKeyAlgorithms``, ``PubkeyAcceptedKeyTypes``
* ``openssl.cnf`` — ``MinProtocol``, ``MaxProtocol``, ``CipherString``
* ``java.security`` — ``jdk.tls.disabledAlgorithms``,
  ``jdk.certpath.disabledAlgorithms``, ``jdk.tls.legacyAlgorithms``,
  ``securerandom.strongAlgorithms``
* ``postgresql.conf`` — ``ssl_ciphers``, ``ssl_min_protocol_version``,
  ``ssl_ecdh_curve``
* .NET ``web.config`` — ``sslProtocols`` attributes, ``machineKey``

Every finding here uses :attr:`DetectionMethod.CONFIG_POLICY_DECLARED` and
sits at the medium confidence band. Two design rules keep this honest:

1. **Declarations, not observations.** A config file says what the admin
   *asked for*. The running server can still override or ignore that. Live
   TLS probing (``app/scanner/tls.py``) is what proves what actually happens
   on the wire. This scanner is deliberately labelled so a reviewer can see
   the distinction.
2. **Concrete algorithms only.** OpenSSL cipher specs mix concrete cipher
   names (``ECDHE-RSA-AES256-GCM-SHA384``) with policy classes (``HIGH``,
   ``MEDIUM``) and negations (``!aNULL``). Only concrete names become
   algorithm findings. Class-based specs emit a single meta finding under
   :attr:`ArtefactType.PROTOCOL` that records "TLS cipher policy declared"
   without inventing specific ciphers.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from app.config import Settings, get_settings
from app.models.asset import (
    ArtefactType,
    CryptoPrimitive,
    CryptoUsage,
    ParameterStatus,
)
from app.models.finding import DetectionMethod, Evidence, NormalizedFinding

logger = logging.getLogger(__name__)


# ── File → parser matching ──────────────────────────────────────────────────

@dataclass(frozen=True)
class _FileMatcher:
    """Which parser handles a given file, matched against the lower-cased path."""

    key: str
    pattern: re.Pattern[str]


# Ordered so more-specific rules match first (``sshd_config`` before
# ``ssh_config``, ``ssl.conf`` before generic nginx).
_MATCHERS: list[_FileMatcher] = [
    _FileMatcher("nginx", re.compile(
        r"(?:^|[/\\])nginx\.conf$"
        r"|(?:sites-(?:enabled|available)|conf\.d)[/\\][^/\\]+\.conf$"
    )),
    _FileMatcher("apache", re.compile(
        r"(?:^|[/\\])(?:httpd|apache2)\.conf$"
        r"|(?:^|[/\\])(?:ssl|000-default|default-ssl)\.conf$"
    )),
    _FileMatcher("sshd", re.compile(r"(?:^|[/\\])sshd_config(?:\.[^/\\]+)?$")),
    _FileMatcher("ssh_client", re.compile(
        r"(?:^|[/\\])ssh_config(?:\.[^/\\]+)?$|\.ssh[/\\]config$"
    )),
    _FileMatcher("openssl", re.compile(r"(?:^|[/\\])openssl\.(?:cnf|conf)$")),
    _FileMatcher("java_security", re.compile(r"(?:^|[/\\])java\.security$")),
    _FileMatcher("postgresql", re.compile(r"(?:^|[/\\])postgresql\.conf$")),
    _FileMatcher("web_config", re.compile(r"(?:^|[/\\])web\.config$")),
]


def _match_parser(rel_path: str) -> str | None:
    """Return the parser key for a given repo-relative path, or ``None``."""
    lower = rel_path.replace("\\", "/").lower()
    for matcher in _MATCHERS:
        if matcher.pattern.search(lower):
            return matcher.key
    return None


# ── Shared helpers ──────────────────────────────────────────────────────────

def _line_number_of(text: str, offset: int) -> int:
    """1-indexed line number of ``offset`` in ``text``."""
    return text.count("\n", 0, offset) + 1


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name


def _snippet(text: str, offset: int, length: int = 160) -> str:
    """Small snippet around ``offset`` for the finding evidence."""
    start = max(0, offset - 20)
    end = min(len(text), offset + length)
    return text[start:end].strip().replace("\r\n", "\n").replace("\n", " ")[:length]


def _finding_id(prefix: str, rel_path: str, discriminator: str) -> str:
    """Stable, filesystem-safe finding id."""
    safe = rel_path.replace("/", "_").replace("\\", "_")
    return f"CFG-{prefix}-{safe}-{discriminator}"


def _make_finding(
    rel_path: str,
    line_number: int,
    snippet: str,
    algorithm: str,
    parameter: str | None,
    artefact_type: ArtefactType,
    primitive: CryptoPrimitive,
    usage: CryptoUsage,
    parser_key: str,
    kind_label: str,
    curve: str | None = None,
    confidence: float = 0.70,
) -> NormalizedFinding:
    """Build a :class:`NormalizedFinding` from a parsed policy entry."""
    evidence = Evidence(
        file_path=rel_path,
        line_number=line_number,
        code_snippet=snippet[:200],
        detection_method=DetectionMethod.CONFIG_POLICY_DECLARED,
        confidence=confidence,
    )
    return NormalizedFinding(
        id=_finding_id(parser_key, rel_path, f"{kind_label}-{algorithm}-{parameter or 'n'}"),
        algorithm=algorithm,
        primitive=primitive,
        parameter=parameter,
        parameter_status=(
            ParameterStatus.RESOLVED if parameter else ParameterStatus.NOT_APPLICABLE
        ),
        curve=curve,
        usage=usage,
        artefact_type=artefact_type,
        library=parser_key,
        evidence=evidence,
    )


# ── TLS / SSL protocol version tokens ───────────────────────────────────────

# Both server-config and OpenSSL-style names normalise to (algorithm, version).
_TLS_TOKENS: dict[str, tuple[str, str]] = {
    "SSLV2":     ("SSLv2", "2.0"),
    "SSLV3":     ("SSLv3", "3.0"),
    "TLSV1":     ("TLS",   "1.0"),
    "TLSV1.0":   ("TLS",   "1.0"),
    "TLSV1_0":   ("TLS",   "1.0"),
    "TLSV1.1":   ("TLS",   "1.1"),
    "TLSV1_1":   ("TLS",   "1.1"),
    "TLSV1.2":   ("TLS",   "1.2"),
    "TLSV1_2":   ("TLS",   "1.2"),
    "TLSV1.3":   ("TLS",   "1.3"),
    "TLSV1_3":   ("TLS",   "1.3"),
}


def _normalise_tls_token(token: str) -> tuple[str, str] | None:
    """Return (algorithm, version) for a protocol token, or None if unknown."""
    key = token.upper().strip().lstrip("+").lstrip("-")
    return _TLS_TOKENS.get(key)


# ── OpenSSL cipher spec parser ──────────────────────────────────────────────

# A concrete cipher suite name in the OpenSSL/nginx dialect: alphanumeric
# groups joined by hyphens, at least two groups. Deliberately does not match
# class names like HIGH / MEDIUM / kECDHE / aRSA / @STRENGTH.
_OPENSSL_CIPHER_NAME_RE = re.compile(r"^[A-Za-z0-9]{2,}(?:-[A-Za-z0-9_]{2,})+$")


def _parse_openssl_cipher_spec(spec: str) -> tuple[list[str], bool]:
    """Split a colon-delimited cipher spec into (concrete_names, has_class).

    ``concrete_names`` is the list of specific cipher suites (``ECDHE-RSA-...``)
    the spec enables. ``has_class`` is ``True`` when the spec references
    OpenSSL policy classes (``HIGH``, ``ALL``, ...) — those become one meta
    finding under :attr:`ArtefactType.PROTOCOL`, not one bogus finding per
    class name.
    """
    spec = spec.strip().strip('"').strip("'")
    concrete: list[str] = []
    has_class = False
    for raw in spec.split(":"):
        token = raw.strip()
        if not token:
            continue
        # Negations and priorities never produce findings.
        if token.startswith(("!", "-", "+", "@")):
            continue
        if _OPENSSL_CIPHER_NAME_RE.match(token):
            concrete.append(token)
        else:
            has_class = True
    return concrete, has_class


# ── SSH algorithm mappings ──────────────────────────────────────────────────

# Each entry: openssh_name → (algorithm, parameter, artefact_type, primitive, usage)
# Data extracted directly from OpenSSH man pages (``ssh_config(5)``,
# ``sshd_config(5)``); every entry is a well-known named algorithm.

@dataclass(frozen=True)
class _SshAlgo:
    algorithm: str
    parameter: str | None
    artefact_type: ArtefactType
    primitive: CryptoPrimitive
    usage: CryptoUsage
    curve: str | None = None


_SSH_CIPHERS: dict[str, _SshAlgo] = {
    "3des-cbc":                        _SshAlgo("3DES", "CBC", ArtefactType.ENCRYPTION, CryptoPrimitive.BLOCK_CIPHER, CryptoUsage.TRANSPORT_ENCRYPTION),
    "blowfish-cbc":                    _SshAlgo("Blowfish", "CBC", ArtefactType.ENCRYPTION, CryptoPrimitive.BLOCK_CIPHER, CryptoUsage.TRANSPORT_ENCRYPTION),
    "cast128-cbc":                     _SshAlgo("CAST-128", "CBC", ArtefactType.ENCRYPTION, CryptoPrimitive.BLOCK_CIPHER, CryptoUsage.TRANSPORT_ENCRYPTION),
    "arcfour":                         _SshAlgo("RC4", None, ArtefactType.ENCRYPTION, CryptoPrimitive.STREAM_CIPHER, CryptoUsage.TRANSPORT_ENCRYPTION),
    "arcfour128":                      _SshAlgo("RC4", "128", ArtefactType.ENCRYPTION, CryptoPrimitive.STREAM_CIPHER, CryptoUsage.TRANSPORT_ENCRYPTION),
    "arcfour256":                      _SshAlgo("RC4", "256", ArtefactType.ENCRYPTION, CryptoPrimitive.STREAM_CIPHER, CryptoUsage.TRANSPORT_ENCRYPTION),
    "aes128-cbc":                      _SshAlgo("AES", "128", ArtefactType.ENCRYPTION, CryptoPrimitive.BLOCK_CIPHER, CryptoUsage.TRANSPORT_ENCRYPTION),
    "aes192-cbc":                      _SshAlgo("AES", "192", ArtefactType.ENCRYPTION, CryptoPrimitive.BLOCK_CIPHER, CryptoUsage.TRANSPORT_ENCRYPTION),
    "aes256-cbc":                      _SshAlgo("AES", "256", ArtefactType.ENCRYPTION, CryptoPrimitive.BLOCK_CIPHER, CryptoUsage.TRANSPORT_ENCRYPTION),
    "aes128-ctr":                      _SshAlgo("AES", "128", ArtefactType.ENCRYPTION, CryptoPrimitive.BLOCK_CIPHER, CryptoUsage.TRANSPORT_ENCRYPTION),
    "aes192-ctr":                      _SshAlgo("AES", "192", ArtefactType.ENCRYPTION, CryptoPrimitive.BLOCK_CIPHER, CryptoUsage.TRANSPORT_ENCRYPTION),
    "aes256-ctr":                      _SshAlgo("AES", "256", ArtefactType.ENCRYPTION, CryptoPrimitive.BLOCK_CIPHER, CryptoUsage.TRANSPORT_ENCRYPTION),
    "aes128-gcm@openssh.com":          _SshAlgo("AES", "128", ArtefactType.ENCRYPTION, CryptoPrimitive.AE, CryptoUsage.TRANSPORT_ENCRYPTION),
    "aes256-gcm@openssh.com":          _SshAlgo("AES", "256", ArtefactType.ENCRYPTION, CryptoPrimitive.AE, CryptoUsage.TRANSPORT_ENCRYPTION),
    "chacha20-poly1305@openssh.com":   _SshAlgo("ChaCha20-Poly1305", None, ArtefactType.ENCRYPTION, CryptoPrimitive.AE, CryptoUsage.TRANSPORT_ENCRYPTION),
}


_SSH_KEX: dict[str, _SshAlgo] = {
    "diffie-hellman-group1-sha1":                   _SshAlgo("DH", "1024", ArtefactType.KEY_EXCHANGE, CryptoPrimitive.KEY_AGREE, CryptoUsage.KEY_ESTABLISHMENT),
    "diffie-hellman-group14-sha1":                  _SshAlgo("DH", "2048", ArtefactType.KEY_EXCHANGE, CryptoPrimitive.KEY_AGREE, CryptoUsage.KEY_ESTABLISHMENT),
    "diffie-hellman-group14-sha256":                _SshAlgo("DH", "2048", ArtefactType.KEY_EXCHANGE, CryptoPrimitive.KEY_AGREE, CryptoUsage.KEY_ESTABLISHMENT),
    "diffie-hellman-group16-sha512":                _SshAlgo("DH", "4096", ArtefactType.KEY_EXCHANGE, CryptoPrimitive.KEY_AGREE, CryptoUsage.KEY_ESTABLISHMENT),
    "diffie-hellman-group18-sha512":                _SshAlgo("DH", "8192", ArtefactType.KEY_EXCHANGE, CryptoPrimitive.KEY_AGREE, CryptoUsage.KEY_ESTABLISHMENT),
    "diffie-hellman-group-exchange-sha1":           _SshAlgo("DH-GEX", None, ArtefactType.KEY_EXCHANGE, CryptoPrimitive.KEY_AGREE, CryptoUsage.KEY_ESTABLISHMENT),
    "diffie-hellman-group-exchange-sha256":         _SshAlgo("DH-GEX", None, ArtefactType.KEY_EXCHANGE, CryptoPrimitive.KEY_AGREE, CryptoUsage.KEY_ESTABLISHMENT),
    "ecdh-sha2-nistp256":                           _SshAlgo("ECDH", "secp256r1", ArtefactType.KEY_EXCHANGE, CryptoPrimitive.KEY_AGREE, CryptoUsage.KEY_ESTABLISHMENT, curve="secp256r1"),
    "ecdh-sha2-nistp384":                           _SshAlgo("ECDH", "secp384r1", ArtefactType.KEY_EXCHANGE, CryptoPrimitive.KEY_AGREE, CryptoUsage.KEY_ESTABLISHMENT, curve="secp384r1"),
    "ecdh-sha2-nistp521":                           _SshAlgo("ECDH", "secp521r1", ArtefactType.KEY_EXCHANGE, CryptoPrimitive.KEY_AGREE, CryptoUsage.KEY_ESTABLISHMENT, curve="secp521r1"),
    "curve25519-sha256":                            _SshAlgo("X25519", None, ArtefactType.KEY_EXCHANGE, CryptoPrimitive.KEY_AGREE, CryptoUsage.KEY_ESTABLISHMENT, curve="X25519"),
    "curve25519-sha256@libssh.org":                 _SshAlgo("X25519", None, ArtefactType.KEY_EXCHANGE, CryptoPrimitive.KEY_AGREE, CryptoUsage.KEY_ESTABLISHMENT, curve="X25519"),
    "sntrup761x25519-sha512@openssh.com":           _SshAlgo("sntrup761-X25519-Hybrid", None, ArtefactType.KEY_EXCHANGE, CryptoPrimitive.KEM, CryptoUsage.KEY_ESTABLISHMENT),
    "mlkem768x25519-sha256":                        _SshAlgo("ML-KEM-768-X25519-Hybrid", "768", ArtefactType.KEY_EXCHANGE, CryptoPrimitive.KEM, CryptoUsage.KEY_ESTABLISHMENT),
}


_SSH_MACS: dict[str, _SshAlgo] = {
    "hmac-md5":                        _SshAlgo("HMAC-MD5", None, ArtefactType.MAC, CryptoPrimitive.MAC, CryptoUsage.MESSAGE_AUTHENTICATION),
    "hmac-md5-96":                     _SshAlgo("HMAC-MD5", "96", ArtefactType.MAC, CryptoPrimitive.MAC, CryptoUsage.MESSAGE_AUTHENTICATION),
    "hmac-sha1":                       _SshAlgo("HMAC-SHA-1", None, ArtefactType.MAC, CryptoPrimitive.MAC, CryptoUsage.MESSAGE_AUTHENTICATION),
    "hmac-sha1-96":                    _SshAlgo("HMAC-SHA-1", "96", ArtefactType.MAC, CryptoPrimitive.MAC, CryptoUsage.MESSAGE_AUTHENTICATION),
    "hmac-sha2-256":                   _SshAlgo("HMAC-SHA-256", None, ArtefactType.MAC, CryptoPrimitive.MAC, CryptoUsage.MESSAGE_AUTHENTICATION),
    "hmac-sha2-512":                   _SshAlgo("HMAC-SHA-512", None, ArtefactType.MAC, CryptoPrimitive.MAC, CryptoUsage.MESSAGE_AUTHENTICATION),
    "umac-64@openssh.com":             _SshAlgo("UMAC", "64", ArtefactType.MAC, CryptoPrimitive.MAC, CryptoUsage.MESSAGE_AUTHENTICATION),
    "umac-128@openssh.com":            _SshAlgo("UMAC", "128", ArtefactType.MAC, CryptoPrimitive.MAC, CryptoUsage.MESSAGE_AUTHENTICATION),
    "hmac-md5-etm@openssh.com":        _SshAlgo("HMAC-MD5-ETM", None, ArtefactType.MAC, CryptoPrimitive.MAC, CryptoUsage.MESSAGE_AUTHENTICATION),
    "hmac-sha1-etm@openssh.com":       _SshAlgo("HMAC-SHA-1-ETM", None, ArtefactType.MAC, CryptoPrimitive.MAC, CryptoUsage.MESSAGE_AUTHENTICATION),
    "hmac-sha2-256-etm@openssh.com":   _SshAlgo("HMAC-SHA-256-ETM", None, ArtefactType.MAC, CryptoPrimitive.MAC, CryptoUsage.MESSAGE_AUTHENTICATION),
    "hmac-sha2-512-etm@openssh.com":   _SshAlgo("HMAC-SHA-512-ETM", None, ArtefactType.MAC, CryptoPrimitive.MAC, CryptoUsage.MESSAGE_AUTHENTICATION),
}


_SSH_HOSTKEY: dict[str, _SshAlgo] = {
    "ssh-dss":                         _SshAlgo("DSA", None, ArtefactType.SIGNATURE, CryptoPrimitive.SIGNATURE, CryptoUsage.DIGITAL_SIGNATURE),
    "ssh-rsa":                         _SshAlgo("RSA", None, ArtefactType.SIGNATURE, CryptoPrimitive.SIGNATURE, CryptoUsage.DIGITAL_SIGNATURE),
    "rsa-sha2-256":                    _SshAlgo("RSA", None, ArtefactType.SIGNATURE, CryptoPrimitive.SIGNATURE, CryptoUsage.DIGITAL_SIGNATURE),
    "rsa-sha2-512":                    _SshAlgo("RSA", None, ArtefactType.SIGNATURE, CryptoPrimitive.SIGNATURE, CryptoUsage.DIGITAL_SIGNATURE),
    "ecdsa-sha2-nistp256":             _SshAlgo("ECDSA", "secp256r1", ArtefactType.SIGNATURE, CryptoPrimitive.SIGNATURE, CryptoUsage.DIGITAL_SIGNATURE, curve="secp256r1"),
    "ecdsa-sha2-nistp384":             _SshAlgo("ECDSA", "secp384r1", ArtefactType.SIGNATURE, CryptoPrimitive.SIGNATURE, CryptoUsage.DIGITAL_SIGNATURE, curve="secp384r1"),
    "ecdsa-sha2-nistp521":             _SshAlgo("ECDSA", "secp521r1", ArtefactType.SIGNATURE, CryptoPrimitive.SIGNATURE, CryptoUsage.DIGITAL_SIGNATURE, curve="secp521r1"),
    "ssh-ed25519":                     _SshAlgo("Ed25519", None, ArtefactType.SIGNATURE, CryptoPrimitive.SIGNATURE, CryptoUsage.DIGITAL_SIGNATURE),
    "sk-ecdsa-sha2-nistp256@openssh.com": _SshAlgo("ECDSA-SecurityKey", "secp256r1", ArtefactType.SIGNATURE, CryptoPrimitive.SIGNATURE, CryptoUsage.DIGITAL_SIGNATURE, curve="secp256r1"),
    "sk-ssh-ed25519@openssh.com":      _SshAlgo("Ed25519-SecurityKey", None, ArtefactType.SIGNATURE, CryptoPrimitive.SIGNATURE, CryptoUsage.DIGITAL_SIGNATURE),
}


# ── Per-parser directive tables ─────────────────────────────────────────────

@dataclass(frozen=True)
class _Directive:
    """One config directive to look for and how to interpret its value."""

    # Regex capturing the directive value in group 1. Applied per-line.
    line_re: re.Pattern[str]
    # Emit callback: (value_str, rel_path, line_no, parser_key) → findings
    handler: Callable[[str, str, int, str], list[NormalizedFinding]]


# ── Emitters ────────────────────────────────────────────────────────────────

def _emit_tls_protocols(
    value: str, rel: str, line: int, parser: str, snippet: str,
) -> list[NormalizedFinding]:
    """Emit one PROTOCOL finding per TLS/SSL version token in ``value``."""
    findings: list[NormalizedFinding] = []
    # Value may be whitespace-, comma-, or plus/minus-separated. Split on any.
    tokens = re.split(r"[,\s+]", value)
    for tok in tokens:
        tok = tok.strip().rstrip(";").rstrip(",")
        if not tok:
            continue
        # Apache ``SSLProtocol`` supports negations like ``-SSLv3``. A negation
        # means "explicitly disabled" — record it as a policy note, not as an
        # in-use protocol.
        negated = tok.startswith("-")
        normalised = _normalise_tls_token(tok)
        if normalised is None:
            # Common Apache/OpenSSL keyword: ``all`` — represents a policy class.
            if tok.strip().lower() in {"all", "sslv23"}:
                findings.append(_make_finding(
                    rel, line, snippet,
                    algorithm="TLS-Policy",
                    parameter=None,
                    artefact_type=ArtefactType.PROTOCOL,
                    primitive=CryptoPrimitive.UNKNOWN,
                    usage=CryptoUsage.TRANSPORT_ENCRYPTION,
                    parser_key=parser,
                    kind_label="policy",
                ))
            continue
        algo, version = normalised
        if negated:
            # Skip emitting; it's declared *disabled*.
            continue
        findings.append(_make_finding(
            rel, line, snippet,
            algorithm=algo,
            parameter=version,
            artefact_type=ArtefactType.PROTOCOL,
            primitive=CryptoPrimitive.UNKNOWN,
            usage=CryptoUsage.TRANSPORT_ENCRYPTION,
            parser_key=parser,
            kind_label="proto",
        ))
    return findings


def _emit_openssl_cipher_list(
    value: str, rel: str, line: int, parser: str, snippet: str,
) -> list[NormalizedFinding]:
    """Emit findings for a colon-separated OpenSSL cipher spec."""
    findings: list[NormalizedFinding] = []
    concrete, has_class = _parse_openssl_cipher_spec(value)
    for cipher_name in concrete:
        # Cipher-suite names are opaque strings; store the whole name as the
        # algorithm and let the classifier route it via its usage.
        findings.append(_make_finding(
            rel, line, snippet,
            algorithm=cipher_name,
            parameter=None,
            artefact_type=ArtefactType.ENCRYPTION,
            primitive=CryptoPrimitive.UNKNOWN,
            usage=CryptoUsage.TRANSPORT_ENCRYPTION,
            parser_key=parser,
            kind_label="cipher",
        ))
    if has_class and not concrete:
        # No concrete names — represent the policy as a single meta finding.
        findings.append(_make_finding(
            rel, line, snippet,
            algorithm="TLS-Cipher-Policy",
            parameter=None,
            artefact_type=ArtefactType.PROTOCOL,
            primitive=CryptoPrimitive.UNKNOWN,
            usage=CryptoUsage.TRANSPORT_ENCRYPTION,
            parser_key=parser,
            kind_label="cipher-policy",
        ))
    return findings


def _emit_ssh_list(
    table: dict[str, _SshAlgo],
    value: str,
    rel: str,
    line: int,
    parser: str,
    snippet: str,
    kind_label: str,
) -> list[NormalizedFinding]:
    """Emit findings for a comma-separated SSH algorithm list."""
    findings: list[NormalizedFinding] = []
    seen: set[str] = set()
    for raw in value.split(","):
        name = raw.strip()
        # ``+`` / ``-`` / ``^`` are OpenSSH prefixes for "add" / "remove" /
        # "prepend". Strip the prefix; the algorithm name is the token.
        stripped = name.lstrip("+-^")
        if not stripped or stripped in seen:
            continue
        seen.add(stripped)
        meta = table.get(stripped.lower())
        if meta is None:
            # Unknown algorithm — surface as UNKNOWN so it appears in the CBOM
            # rather than being silently swallowed.
            findings.append(_make_finding(
                rel, line, snippet,
                algorithm=f"SSH-{kind_label}:{stripped}",
                parameter=None,
                artefact_type=ArtefactType.UNKNOWN,
                primitive=CryptoPrimitive.UNKNOWN,
                usage=CryptoUsage.TRANSPORT_ENCRYPTION,
                parser_key=parser,
                kind_label=kind_label,
            ))
            continue
        findings.append(_make_finding(
            rel, line, snippet,
            algorithm=meta.algorithm,
            parameter=meta.parameter,
            artefact_type=meta.artefact_type,
            primitive=meta.primitive,
            usage=meta.usage,
            parser_key=parser,
            kind_label=kind_label,
            curve=meta.curve,
        ))
    return findings


# ── Per-family parsers ──────────────────────────────────────────────────────

# Match a directive on its own line, allowing leading whitespace and optional
# semicolon terminator. The value regex is deliberately broad — the emitter
# handles tokenisation.

_NGINX_PROTOCOLS = re.compile(r"^\s*ssl_protocols\s+([^;#]+);?", re.IGNORECASE | re.MULTILINE)
_NGINX_CIPHERS   = re.compile(r"^\s*ssl_ciphers\s+([^;#]+);?", re.IGNORECASE | re.MULTILINE)

_APACHE_PROTOCOLS = re.compile(r"^\s*SSLProtocol\s+(.+)$", re.IGNORECASE | re.MULTILINE)
_APACHE_CIPHERS   = re.compile(r"^\s*SSLCipherSuite\s+(.+)$", re.IGNORECASE | re.MULTILINE)

_SSHD_CIPHERS   = re.compile(r"^\s*Ciphers\s+(.+)$", re.IGNORECASE | re.MULTILINE)
_SSHD_KEX       = re.compile(r"^\s*KexAlgorithms\s+(.+)$", re.IGNORECASE | re.MULTILINE)
_SSHD_MACS      = re.compile(r"^\s*MACs\s+(.+)$", re.IGNORECASE | re.MULTILINE)
_SSHD_HOSTKEYS  = re.compile(r"^\s*(?:HostKeyAlgorithms|PubkeyAcceptedKeyTypes|PubkeyAcceptedAlgorithms)\s+(.+)$", re.IGNORECASE | re.MULTILINE)

_OPENSSL_MINPROTO = re.compile(r"^\s*MinProtocol\s*=\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_OPENSSL_MAXPROTO = re.compile(r"^\s*MaxProtocol\s*=\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_OPENSSL_CIPHERS  = re.compile(r"^\s*CipherString\s*=\s*(.+)$", re.IGNORECASE | re.MULTILINE)

_JAVA_DISABLED_TLS  = re.compile(r"^\s*jdk\.tls\.disabledAlgorithms\s*=\s*(.+?)$",  re.IGNORECASE | re.MULTILINE)
_JAVA_DISABLED_CERT = re.compile(r"^\s*jdk\.certpath\.disabledAlgorithms\s*=\s*(.+?)$",  re.IGNORECASE | re.MULTILINE)
_JAVA_LEGACY        = re.compile(r"^\s*jdk\.tls\.legacyAlgorithms\s*=\s*(.+?)$",  re.IGNORECASE | re.MULTILINE)

_PG_CIPHERS      = re.compile(r"^\s*ssl_ciphers\s*=\s*'([^']+)'", re.IGNORECASE | re.MULTILINE)
_PG_MIN_PROTO    = re.compile(r"^\s*ssl_min_protocol_version\s*=\s*'([^']+)'", re.IGNORECASE | re.MULTILINE)
_PG_ECDH_CURVE   = re.compile(r"^\s*ssl_ecdh_curve\s*=\s*'([^']+)'", re.IGNORECASE | re.MULTILINE)

# .NET web.config — attributes on XML elements. Simple regex is enough here;
# a full XML parser is overkill for the two directives we care about.
_WEBCONFIG_SSLPROTOCOLS = re.compile(r'sslProtocols\s*=\s*"([^"]+)"', re.IGNORECASE)
_WEBCONFIG_VALIDATION   = re.compile(r'validation\s*=\s*"([^"]+)"', re.IGNORECASE)
_WEBCONFIG_DECRYPTION   = re.compile(r'decryption\s*=\s*"([^"]+)"', re.IGNORECASE)


def _parse_nginx(text: str, rel: str, parser_key: str = "nginx") -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for m in _NGINX_PROTOCOLS.finditer(text):
        findings.extend(_emit_tls_protocols(
            m.group(1), rel, _line_number_of(text, m.start()), parser_key, m.group(0)[:180],
        ))
    for m in _NGINX_CIPHERS.finditer(text):
        findings.extend(_emit_openssl_cipher_list(
            m.group(1), rel, _line_number_of(text, m.start()), parser_key, m.group(0)[:180],
        ))
    return findings


def _parse_apache(text: str, rel: str) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for m in _APACHE_PROTOCOLS.finditer(text):
        findings.extend(_emit_tls_protocols(
            m.group(1), rel, _line_number_of(text, m.start()), "apache", m.group(0)[:180],
        ))
    for m in _APACHE_CIPHERS.finditer(text):
        findings.extend(_emit_openssl_cipher_list(
            m.group(1), rel, _line_number_of(text, m.start()), "apache", m.group(0)[:180],
        ))
    return findings


def _parse_sshd(text: str, rel: str, parser_key: str = "sshd") -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for m in _SSHD_CIPHERS.finditer(text):
        findings.extend(_emit_ssh_list(
            _SSH_CIPHERS, m.group(1), rel, _line_number_of(text, m.start()),
            parser_key, m.group(0)[:180], "cipher",
        ))
    for m in _SSHD_KEX.finditer(text):
        findings.extend(_emit_ssh_list(
            _SSH_KEX, m.group(1), rel, _line_number_of(text, m.start()),
            parser_key, m.group(0)[:180], "kex",
        ))
    for m in _SSHD_MACS.finditer(text):
        findings.extend(_emit_ssh_list(
            _SSH_MACS, m.group(1), rel, _line_number_of(text, m.start()),
            parser_key, m.group(0)[:180], "mac",
        ))
    for m in _SSHD_HOSTKEYS.finditer(text):
        findings.extend(_emit_ssh_list(
            _SSH_HOSTKEY, m.group(1), rel, _line_number_of(text, m.start()),
            parser_key, m.group(0)[:180], "hostkey",
        ))
    return findings


def _parse_openssl(text: str, rel: str) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for m in _OPENSSL_MINPROTO.finditer(text):
        findings.extend(_emit_tls_protocols(
            m.group(1), rel, _line_number_of(text, m.start()), "openssl", m.group(0)[:180],
        ))
    for m in _OPENSSL_MAXPROTO.finditer(text):
        findings.extend(_emit_tls_protocols(
            m.group(1), rel, _line_number_of(text, m.start()), "openssl", m.group(0)[:180],
        ))
    for m in _OPENSSL_CIPHERS.finditer(text):
        findings.extend(_emit_openssl_cipher_list(
            m.group(1), rel, _line_number_of(text, m.start()), "openssl", m.group(0)[:180],
        ))
    return findings


def _parse_java_security(text: str, rel: str) -> list[NormalizedFinding]:
    """java.security is a *hardening* declaration, not an in-use inventory.

    Emit one PROTOCOL finding per matched directive; the evidence snippet
    carries the actual disabled algorithms so a reviewer can see them. Never
    emit disabled algorithms as if they were in-use — that would be honesty
    exactly upside-down.
    """
    findings: list[NormalizedFinding] = []
    directives = [
        (_JAVA_DISABLED_TLS,  "TLS-Hardening-Policy"),
        (_JAVA_DISABLED_CERT, "CertPath-Hardening-Policy"),
        (_JAVA_LEGACY,        "TLS-Legacy-Policy"),
    ]
    for regex, algorithm in directives:
        for m in regex.finditer(text):
            findings.append(_make_finding(
                rel, _line_number_of(text, m.start()), m.group(0)[:180],
                algorithm=algorithm,
                parameter=None,
                artefact_type=ArtefactType.PROTOCOL,
                primitive=CryptoPrimitive.UNKNOWN,
                usage=CryptoUsage.TRANSPORT_ENCRYPTION,
                parser_key="java_security",
                kind_label="policy",
            ))
    return findings


def _parse_postgresql(text: str, rel: str) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for m in _PG_CIPHERS.finditer(text):
        findings.extend(_emit_openssl_cipher_list(
            m.group(1), rel, _line_number_of(text, m.start()), "postgresql", m.group(0)[:180],
        ))
    for m in _PG_MIN_PROTO.finditer(text):
        findings.extend(_emit_tls_protocols(
            m.group(1), rel, _line_number_of(text, m.start()), "postgresql", m.group(0)[:180],
        ))
    for m in _PG_ECDH_CURVE.finditer(text):
        curve_name = m.group(1).strip()
        findings.append(_make_finding(
            rel, _line_number_of(text, m.start()), m.group(0)[:180],
            algorithm="ECDH",
            parameter=curve_name,
            artefact_type=ArtefactType.KEY_EXCHANGE,
            primitive=CryptoPrimitive.KEY_AGREE,
            usage=CryptoUsage.KEY_ESTABLISHMENT,
            parser_key="postgresql",
            kind_label="ecdh-curve",
            curve=curve_name,
        ))
    return findings


def _parse_web_config(text: str, rel: str) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for m in _WEBCONFIG_SSLPROTOCOLS.finditer(text):
        findings.extend(_emit_tls_protocols(
            m.group(1), rel, _line_number_of(text, m.start()), "web_config", m.group(0)[:180],
        ))
    # machineKey / validation / decryption attributes — surface as declared
    # algorithms so ASP.NET server cryptography is inventoried.
    for m in _WEBCONFIG_VALIDATION.finditer(text):
        algo = m.group(1).strip()
        findings.append(_make_finding(
            rel, _line_number_of(text, m.start()), m.group(0)[:180],
            algorithm=algo, parameter=None,
            artefact_type=ArtefactType.MAC,
            primitive=CryptoPrimitive.MAC,
            usage=CryptoUsage.MESSAGE_AUTHENTICATION,
            parser_key="web_config",
            kind_label="validation",
        ))
    for m in _WEBCONFIG_DECRYPTION.finditer(text):
        algo = m.group(1).strip()
        findings.append(_make_finding(
            rel, _line_number_of(text, m.start()), m.group(0)[:180],
            algorithm=algo, parameter=None,
            artefact_type=ArtefactType.ENCRYPTION,
            primitive=CryptoPrimitive.BLOCK_CIPHER,
            usage=CryptoUsage.DATA_ENCRYPTION,
            parser_key="web_config",
            kind_label="decryption",
        ))
    return findings


# ── Parser dispatch table ───────────────────────────────────────────────────

_PARSERS: dict[str, Callable[[str, str], list[NormalizedFinding]]] = {
    "nginx":         _parse_nginx,
    "apache":        _parse_apache,
    "sshd":          _parse_sshd,
    "ssh_client":    lambda text, rel: _parse_sshd(text, rel, parser_key="ssh_client"),
    "openssl":       _parse_openssl,
    "java_security": _parse_java_security,
    "postgresql":    _parse_postgresql,
    "web_config":    _parse_web_config,
}


# ── Scanner entry point ─────────────────────────────────────────────────────

def _read_capped(path: Path, cap_bytes: int) -> str | None:
    """Read up to ``cap_bytes`` of ``path`` as text, or None on error/oversize."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size == 0 or size > cap_bytes:
        return None
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def scan_config_policy(
    target: Path, settings: Settings | None = None
) -> list[NormalizedFinding]:
    """Walk ``target`` for policy config files and emit their declared crypto.

    Deterministic: files are visited in sorted-path order; findings are
    deduplicated per ``(rel_path, algorithm, parameter, kind_label)``.
    """
    settings = settings or get_settings()
    if not settings.config_policy_scan_enabled:
        return []

    root = Path(target).resolve()
    if not root.exists():
        return []

    cap = int(settings.config_policy_max_scan_mb) * 1024 * 1024
    findings: list[NormalizedFinding] = []
    seen: set[str] = set()

    iterator = [root] if root.is_file() else sorted(root.rglob("*"))
    for path in iterator:
        try:
            if not path.is_file() or path.is_symlink():
                continue
        except OSError:
            continue

        rel = _relative(path, root)
        parser_key = _match_parser(rel)
        if parser_key is None:
            continue

        text = _read_capped(path, cap)
        if text is None:
            continue

        try:
            produced = _PARSERS[parser_key](text, rel)
        except Exception as exc:  # noqa: BLE001 — top-level guard
            logger.warning("Config policy scan failed for %s: %s", path.name, exc)
            continue

        for f in produced:
            # Dedup: same file, same algorithm, same parameter, same kind.
            # The finding id already encodes these but we keep a separate set
            # to short-circuit before object construction on repeat matches.
            key = f.id
            if key in seen:
                continue
            seen.add(key)
            findings.append(f)

    if findings:
        logger.info(
            "Config policy scan: %d finding(s) across %d file(s) under %s.",
            len(findings),
            len({f.evidence.file_path for f in findings}),
            root.name or root,
        )
    return findings
