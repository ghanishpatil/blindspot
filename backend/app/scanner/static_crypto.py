"""Static cert / key / keystore scanner — R1 in PS_ALIGNMENT_PLAN.md.

The specification names *certificates* and *keys* as artefact classes to
catalogue. The live TLS scanner (``app/scanner/tls.py``) handles the network
side. What that scanner cannot see is the enormous amount of cryptography
that lives *on disk* in real enterprises — TLS server certificates in
``/etc/ssl``, code-signing keys in a build directory, JWT signing keys
committed to a repo, PKCS#12 bundles used by CI runners, keystores under a
Java application. That is what this scanner discovers.

Two rules keep this scanner honest:

1. **The file is the evidence.** The algorithm, key size, curve, and
   signature algorithm are read directly from the DER / PEM bytes with
   :mod:`cryptography.x509` and :mod:`cryptography.hazmat.primitives`. No
   heuristic sits between the artefact and the finding, so confidence is
   high (~0.92).

2. **Encrypted keystores are declared, not guessed.** Password-protected
   PKCS#12 (.p12 / .pfx) and Java KeyStore (.jks) files exist as
   observations but their algorithm is unknown without the password. Those
   findings carry :class:`ParameterStatus.UNRESOLVED` so they route to
   INVESTIGATE via the recommender — the same discipline used by the HSM /
   KMS declaration scanner.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa, x448, x25519
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_der_public_key,
    load_pem_private_key,
    load_pem_public_key,
)

from app.config import Settings, get_settings
from app.models.asset import (
    ArtefactType,
    CryptoPrimitive,
    CryptoUsage,
    ParameterStatus,
)
from app.models.finding import DetectionMethod, Evidence, NormalizedFinding

logger = logging.getLogger(__name__)


# ── File classification ─────────────────────────────────────────────────────

# Extensions that are almost certainly cert / key artefacts. We open these
# and try to parse them directly. Ordering does not matter; matching is done
# on the lower-cased suffix.
_DIRECT_CERT_EXTS: set[str] = {".pem", ".crt", ".cer"}
_DIRECT_KEY_EXTS: set[str] = {".key"}
_DIRECT_DER_EXTS: set[str] = {".der"}
_KEYSTORE_EXTS: set[str] = {".p12", ".pfx", ".jks", ".keystore"}

# Text-y extensions where we scan the file's contents for INLINE PEM blocks —
# certificates and keys pasted into source, config, docs, or environment
# files. Kept deliberately narrow to avoid opening every file on disk twice.
_INLINE_PEM_EXTS: set[str] = {
    ".py", ".js", ".mjs", ".ts", ".tsx", ".jsx",
    ".go", ".java", ".kt", ".cs", ".rb", ".php", ".rs",
    ".sh", ".bash", ".ps1",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".example", ".template",
    ".md", ".txt", ".rst",
    ".tf", ".tf.json",
    ".xml", ".properties",
}


# ── PEM block regex ─────────────────────────────────────────────────────────

# Matches one PEM-armoured block. The label group (e.g. ``CERTIFICATE``,
# ``RSA PRIVATE KEY``, ``PRIVATE KEY``, ``PUBLIC KEY``) is used to decide how
# to parse the body. Greedy-until-END so a single file with multiple blocks
# (a "PEM bundle") yields each block as a separate match.
_PEM_BLOCK_RE = re.compile(
    rb"-----BEGIN ([A-Z0-9 ]+?)-----[\r\n]+"
    rb"(?P<body>[A-Za-z0-9+/=\r\n]+?)"
    rb"[\r\n]+-----END \1-----",
)


# ── Public-key algorithm resolution ─────────────────────────────────────────

@dataclass(frozen=True)
class _KeyMeta:
    """Resolved metadata for a public / private key."""

    algorithm: str
    parameter: str | None
    curve: str | None
    primitive: CryptoPrimitive
    usage: CryptoUsage
    artefact_type: ArtefactType


def _resolve_key(pk_obj) -> _KeyMeta:  # noqa: ANN001 — dynamic key type
    """Return :class:`_KeyMeta` for a ``cryptography`` public/private key.

    Handles the six algorithm families ``cryptography`` exposes:
    RSA, DSA, ECDSA (any named curve), Ed25519, Ed448, X25519, X448.
    Unknown types fall through to a labelled 'Unknown' with the class name.
    """
    # RSA — key size in bits is the parameter.
    if isinstance(pk_obj, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return _KeyMeta(
            algorithm="RSA",
            parameter=str(pk_obj.key_size),
            curve=None,
            primitive=CryptoPrimitive.PKE,
            usage=CryptoUsage.KEY_ESTABLISHMENT,
            artefact_type=ArtefactType.KEY_EXCHANGE,
        )
    # DSA — key size in bits is the parameter. (Discouraged today.)
    if isinstance(pk_obj, (dsa.DSAPublicKey, dsa.DSAPrivateKey)):
        return _KeyMeta(
            algorithm="DSA",
            parameter=str(pk_obj.key_size),
            curve=None,
            primitive=CryptoPrimitive.SIGNATURE,
            usage=CryptoUsage.DIGITAL_SIGNATURE,
            artefact_type=ArtefactType.SIGNATURE,
        )
    # Elliptic-curve keys — curve name is the parameter that matters.
    if isinstance(pk_obj, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        curve_name = pk_obj.curve.name
        return _KeyMeta(
            algorithm="ECDSA",
            parameter=curve_name,
            curve=curve_name,
            primitive=CryptoPrimitive.SIGNATURE,
            usage=CryptoUsage.DIGITAL_SIGNATURE,
            artefact_type=ArtefactType.SIGNATURE,
        )
    # Edwards signatures.
    if isinstance(pk_obj, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
        return _KeyMeta(
            algorithm="Ed25519",
            parameter="255",
            curve="Ed25519",
            primitive=CryptoPrimitive.SIGNATURE,
            usage=CryptoUsage.DIGITAL_SIGNATURE,
            artefact_type=ArtefactType.SIGNATURE,
        )
    if isinstance(pk_obj, (ed448.Ed448PublicKey, ed448.Ed448PrivateKey)):
        return _KeyMeta(
            algorithm="Ed448",
            parameter="448",
            curve="Ed448",
            primitive=CryptoPrimitive.SIGNATURE,
            usage=CryptoUsage.DIGITAL_SIGNATURE,
            artefact_type=ArtefactType.SIGNATURE,
        )
    # Diffie-Hellman-like key exchange primitives.
    if isinstance(pk_obj, (x25519.X25519PublicKey, x25519.X25519PrivateKey)):
        return _KeyMeta(
            algorithm="X25519",
            parameter="255",
            curve="X25519",
            primitive=CryptoPrimitive.KEY_AGREE,
            usage=CryptoUsage.KEY_ESTABLISHMENT,
            artefact_type=ArtefactType.KEY_EXCHANGE,
        )
    if isinstance(pk_obj, (x448.X448PublicKey, x448.X448PrivateKey)):
        return _KeyMeta(
            algorithm="X448",
            parameter="448",
            curve="X448",
            primitive=CryptoPrimitive.KEY_AGREE,
            usage=CryptoUsage.KEY_ESTABLISHMENT,
            artefact_type=ArtefactType.KEY_EXCHANGE,
        )
    # Fallback — record the class name so an operator can see what we saw.
    return _KeyMeta(
        algorithm=f"Unknown ({type(pk_obj).__name__})",
        parameter=None,
        curve=None,
        primitive=CryptoPrimitive.UNKNOWN,
        usage=CryptoUsage.UNKNOWN,
        artefact_type=ArtefactType.UNKNOWN,
    )


# ── Helpers ─────────────────────────────────────────────────────────────────

def _relative(path: Path, root: Path) -> str:
    """Repo-relative display path, falling back to bare filename."""
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name


def _finding_id(prefix: str, rel_path: str, discriminator: str) -> str:
    """Stable, filesystem-safe finding id."""
    safe = rel_path.replace("/", "_").replace("\\", "_")
    return f"{prefix}-{safe}-{discriminator}"


def _short_cert_summary(cert: x509.Certificate) -> str:
    """Compact one-line summary of a certificate for the evidence snippet."""
    try:
        subject = cert.subject.rfc4514_string()
    except Exception:  # noqa: BLE001 — rfc4514_string can raise on odd RDNs
        subject = "<unreadable subject>"
    try:
        issuer = cert.issuer.rfc4514_string()
    except Exception:  # noqa: BLE001
        issuer = "<unreadable issuer>"
    try:
        not_after = cert.not_valid_after_utc.isoformat()
    except Exception:  # noqa: BLE001
        not_after = "unknown"
    # Trim to keep the finding table readable.
    return (
        f"subject={subject[:80]} "
        f"issuer={issuer[:80]} "
        f"notAfter={not_after}"
    )


def _emit_cert_finding(
    cert: x509.Certificate,
    rel_path: str,
    line_number: int | None,
    detection_method: DetectionMethod,
    discriminator: str,
) -> NormalizedFinding | None:
    """Build a CERTIFICATE finding from a parsed x509 object."""
    try:
        meta = _resolve_key(cert.public_key())
    except (UnsupportedAlgorithm, Exception) as exc:  # noqa: BLE001
        logger.warning("Could not resolve public key for %s: %s", rel_path, exc)
        return None

    # Certificates are signature-bearing objects: their public key is used to
    # *verify* signatures. Override the key-resolution defaults to reflect
    # that this artefact is a certificate, not a raw signing key on disk.
    artefact_type = ArtefactType.CERTIFICATE
    usage = CryptoUsage.CERTIFICATE_SIGNING

    evidence = Evidence(
        file_path=rel_path,
        line_number=line_number,
        code_snippet=_short_cert_summary(cert),
        detection_method=detection_method,
        confidence=0.92,  # HIGH band — file is the evidence.
    )

    return NormalizedFinding(
        id=_finding_id("CERT", rel_path, discriminator),
        algorithm=meta.algorithm,
        primitive=meta.primitive,
        parameter=meta.parameter,
        parameter_status=(
            ParameterStatus.RESOLVED if meta.parameter else ParameterStatus.UNRESOLVED
        ),
        curve=meta.curve,
        usage=usage,
        artefact_type=artefact_type,
        library=None,
        evidence=evidence,
    )


def _emit_key_finding(
    pk_obj,  # noqa: ANN001 — dynamic key type
    rel_path: str,
    line_number: int | None,
    detection_method: DetectionMethod,
    discriminator: str,
    is_public: bool = False,
) -> NormalizedFinding | None:
    """Build a KEY finding from a parsed public/private key object."""
    try:
        meta = _resolve_key(pk_obj)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not resolve key at %s: %s", rel_path, exc)
        return None

    label = "public key" if is_public else "private key"
    snippet = f"{meta.algorithm}{'-' + meta.parameter if meta.parameter else ''} {label}"

    evidence = Evidence(
        file_path=rel_path,
        line_number=line_number,
        code_snippet=snippet,
        detection_method=detection_method,
        confidence=0.90,  # HIGH band — key bytes decoded, algorithm read.
    )

    return NormalizedFinding(
        id=_finding_id("KEY", rel_path, discriminator),
        algorithm=meta.algorithm,
        primitive=meta.primitive,
        parameter=meta.parameter,
        parameter_status=(
            ParameterStatus.RESOLVED if meta.parameter else ParameterStatus.UNRESOLVED
        ),
        curve=meta.curve,
        usage=meta.usage if not is_public else CryptoUsage.DIGITAL_SIGNATURE,
        artefact_type=meta.artefact_type,
        library=None,
        evidence=evidence,
    )


def _emit_keystore_finding(
    rel_path: str,
    keystore_kind: str,
) -> NormalizedFinding:
    """Emit an UNRESOLVED keystore finding — file exists, contents opaque."""
    evidence = Evidence(
        file_path=rel_path,
        line_number=None,
        code_snippet=f"{keystore_kind} keystore file",
        detection_method=DetectionMethod.STATIC_KEYSTORE,
        # File existence is high confidence; the contents are separately
        # marked UNRESOLVED so needs_verification routes them to review.
        confidence=0.90,
    )
    return NormalizedFinding(
        id=_finding_id("KS", rel_path, keystore_kind.lower()),
        algorithm=f"{keystore_kind}-Keystore",
        primitive=CryptoPrimitive.UNKNOWN,
        parameter=None,
        parameter_status=ParameterStatus.UNRESOLVED,
        usage=CryptoUsage.KEY_GENERATION,
        artefact_type=ArtefactType.CERTIFICATE,
        library=None,
        evidence=evidence,
        unresolved_parameters=["algorithm", "key_size", "curve"],
    )


# ── PEM / DER parsers with defensive error handling ─────────────────────────

def _iter_pem_blocks(
    data: bytes,
) -> Iterable[tuple[str, bytes, int]]:
    """Yield ``(label, block_bytes, byte_offset)`` for every PEM block.

    ``block_bytes`` includes the BEGIN / END armour so it can be fed straight
    into ``load_pem_*``. ``byte_offset`` is the start of the BEGIN line.
    """
    for match in _PEM_BLOCK_RE.finditer(data):
        label = match.group(1).decode("ascii", "replace").strip()
        yield label, match.group(0), match.start()


def _line_number_of(text: bytes, offset: int) -> int:
    """1-indexed line number of *offset* in *text*."""
    return text.count(b"\n", 0, offset) + 1


def _parse_pem_block(
    label: str,
    block: bytes,
    rel_path: str,
    line_number: int | None,
    block_index: int,
) -> NormalizedFinding | None:
    """Dispatch a single PEM block to the right decoder."""
    upper = label.upper()
    try:
        if "CERTIFICATE" in upper and "REQUEST" not in upper:
            cert = x509.load_pem_x509_certificate(block)
            return _emit_cert_finding(
                cert,
                rel_path,
                line_number,
                DetectionMethod.STATIC_CERT_FILE,
                discriminator=f"pem-cert-{block_index}",
            )
        if "PRIVATE KEY" in upper:
            # ``password=None`` triggers a TypeError on encrypted keys — treat
            # that as "encrypted, unresolved" rather than a scanner failure.
            try:
                pk = load_pem_private_key(block, password=None)
            except TypeError:
                # Encrypted — file exists, algorithm is opaque.
                return _emit_keystore_finding(rel_path, "Encrypted-PEM")
            return _emit_key_finding(
                pk,
                rel_path,
                line_number,
                DetectionMethod.STATIC_KEY_MATERIAL,
                discriminator=f"pem-key-{block_index}",
                is_public=False,
            )
        if "PUBLIC KEY" in upper:
            pk = load_pem_public_key(block)
            return _emit_key_finding(
                pk,
                rel_path,
                line_number,
                DetectionMethod.STATIC_KEY_MATERIAL,
                discriminator=f"pem-pubkey-{block_index}",
                is_public=True,
            )
    except (ValueError, UnsupportedAlgorithm) as exc:
        logger.debug("Malformed PEM %s in %s: %s", label, rel_path, exc)
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning("Unexpected PEM parse failure for %s: %s", rel_path, exc)
        return None
    return None


def _parse_direct_file(
    path: Path,
    rel_path: str,
    data: bytes,
) -> list[NormalizedFinding]:
    """Parse a file whose extension marks it as a cert / key artefact.

    Handles PEM (any number of blocks) and DER (single object). Every
    decoder failure is caught — a malformed cert must never fail the scan.
    """
    findings: list[NormalizedFinding] = []
    suffix = path.suffix.lower()

    # PEM path first. Any file containing at least one BEGIN block is treated
    # as PEM regardless of extension — production servers often name PEM
    # bundles ``.crt`` or ``.cer`` interchangeably.
    if b"-----BEGIN" in data:
        for idx, (label, block, offset) in enumerate(_iter_pem_blocks(data)):
            line_no = _line_number_of(data, offset)
            f = _parse_pem_block(label, block, rel_path, line_no, idx)
            if f:
                findings.append(f)
        if findings:
            return findings
        # Fall through — a file with BEGIN markers but no parseable blocks
        # is malformed, but we don't want to try DER on it either.
        return findings

    # DER path. Try cert, then private key, then public key. Order matters:
    # each parser raises on the wrong format.
    if suffix in _DIRECT_DER_EXTS or suffix in _DIRECT_CERT_EXTS or suffix in _DIRECT_KEY_EXTS:
        try:
            cert = x509.load_der_x509_certificate(data)
            f = _emit_cert_finding(
                cert,
                rel_path,
                line_number=None,
                detection_method=DetectionMethod.STATIC_CERT_FILE,
                discriminator="der-cert",
            )
            if f:
                findings.append(f)
                return findings
        except Exception:  # noqa: BLE001 — expected on non-cert DER
            pass
        try:
            pk = load_der_private_key(data, password=None)
            f = _emit_key_finding(
                pk,
                rel_path,
                line_number=None,
                detection_method=DetectionMethod.STATIC_KEY_MATERIAL,
                discriminator="der-key",
                is_public=False,
            )
            if f:
                findings.append(f)
                return findings
        except TypeError:
            # Encrypted DER private key.
            findings.append(_emit_keystore_finding(rel_path, "Encrypted-DER"))
            return findings
        except Exception:  # noqa: BLE001 — expected on non-key DER
            pass
        try:
            pk = load_der_public_key(data)
            f = _emit_key_finding(
                pk,
                rel_path,
                line_number=None,
                detection_method=DetectionMethod.STATIC_KEY_MATERIAL,
                discriminator="der-pubkey",
                is_public=True,
            )
            if f:
                findings.append(f)
        except Exception:  # noqa: BLE001 — file just isn't cert/key material
            pass

    return findings


def _parse_inline_pem(
    path: Path,
    rel_path: str,
    data: bytes,
) -> list[NormalizedFinding]:
    """Scan a text-y file for embedded PEM blocks."""
    findings: list[NormalizedFinding] = []
    for idx, (label, block, offset) in enumerate(_iter_pem_blocks(data)):
        line_no = _line_number_of(data, offset)
        f = _parse_pem_block(label, block, rel_path, line_no, idx)
        if f:
            findings.append(f)
    return findings


# ── Scanner entry point ─────────────────────────────────────────────────────

def _read_capped(path: Path, cap_bytes: int) -> bytes | None:
    """Read up to *cap_bytes* of *path*; None on error / oversize."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size == 0 or size > cap_bytes:
        return None
    try:
        with path.open("rb") as f:
            return f.read()
    except OSError:
        return None


def _classify_file(path: Path) -> str:
    """Return one of: 'direct-cert', 'direct-key', 'direct-der',
    'keystore', 'inline', or 'skip'.

    Handles two cases the plain-suffix check misses:

    * **Dotenv files** — ``Path(".env").suffix`` is ``''`` because Python
      treats the leading dot as a hidden-file marker, not an extension.
      Matched by ``name.startswith(".env")`` so ``.env``, ``.env.local``,
      ``.env.production`` all classify as inline-PEM candidates.
    * **SSH-style key basenames** — files literally named ``id_rsa``,
      ``id_ed25519`` etc. carry PEM key material without any extension.
    """
    suffix = path.suffix.lower()
    name = path.name.lower()

    # Extensionless dotenv variants: .env, .env.local, .envrc, ...
    if name.startswith(".env"):
        return "inline"

    # SSH conventional private-key filenames (no extension).
    if name in {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}:
        return "direct-key"

    if suffix in _DIRECT_CERT_EXTS:
        return "direct-cert"
    if suffix in _DIRECT_KEY_EXTS:
        return "direct-key"
    if suffix in _DIRECT_DER_EXTS:
        return "direct-der"
    if suffix in _KEYSTORE_EXTS:
        return "keystore"
    if suffix in _INLINE_PEM_EXTS:
        return "inline"
    return "skip"


def scan_static_crypto(
    target: Path, settings: Settings | None = None
) -> list[NormalizedFinding]:
    """Walk *target* for static certificate / key / keystore artefacts.

    Deterministic: files are visited in sorted-path order; findings are
    deduplicated per ``(file, algorithm, parameter, curve, kind)``.
    """
    settings = settings or get_settings()
    if not settings.static_crypto_scan_enabled:
        return []

    root = Path(target).resolve()
    if not root.exists():
        return []

    cap = int(settings.static_crypto_max_scan_mb) * 1024 * 1024
    findings: list[NormalizedFinding] = []
    seen: set[str] = set()

    iterator = [root] if root.is_file() else sorted(root.rglob("*"))
    for path in iterator:
        # Skip symlinks and non-files — matches the discipline of the other
        # scanners so a hostile repo cannot use a symlink to reach outside
        # the scanned tree.
        try:
            if not path.is_file() or path.is_symlink():
                continue
        except OSError:
            continue

        kind = _classify_file(path)
        if kind == "skip":
            continue

        rel = _relative(path, root)

        if kind == "keystore":
            # Existence is enough; do not open password-protected bundles.
            keystore_kind = {
                ".p12": "PKCS12",
                ".pfx": "PKCS12",
                ".jks": "JKS",
                ".keystore": "JKS",
            }.get(path.suffix.lower(), "Keystore")
            f = _emit_keystore_finding(rel, keystore_kind)
            key = f"{rel}|{f.algorithm}|keystore"
            if key not in seen:
                seen.add(key)
                findings.append(f)
            continue

        data = _read_capped(path, cap)
        if data is None:
            continue

        try:
            if kind == "inline":
                new_findings = _parse_inline_pem(path, rel, data)
            else:  # direct-cert / direct-key / direct-der
                new_findings = _parse_direct_file(path, rel, data)
        except Exception as exc:  # noqa: BLE001 — top-level guard
            logger.warning("Static crypto scan failed for %s: %s", path.name, exc)
            continue

        for f in new_findings:
            key = f"{rel}|{f.algorithm}|{f.parameter}|{f.curve}|{f.evidence.detection_method.value}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(f)

    if findings:
        logger.info(
            "Static crypto scan: %d finding(s) across %d file(s) under %s.",
            len(findings),
            len({f.evidence.file_path for f in findings}),
            root.name or root,
        )
    return findings
