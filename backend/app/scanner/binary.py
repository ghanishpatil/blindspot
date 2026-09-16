"""Binary scanner (lite) — fingerprint crypto in compiled files.

The source scanner sees only what compiles to source; a scanned repo or an
extracted container image often carries pre-built binaries whose crypto is
invisible to Semgrep. This scanner reads those binaries and looks for
high-signal fingerprints:

* Algorithm-defining constants baked into the code (SHA-2 initial hash values,
  the AES S-box's first row, the MD5 initial digest — these appear verbatim
  in almost every implementation).
* ASN.1 OIDs identifying algorithms (RSA encryption, ECDSA-with-SHA-256, …).
* Library brand strings ("OpenSSL 3.", "libcrypto", "wolfSSL", …) that survive
  linking and reveal which crypto library the binary carries.

Every emitted finding is deliberately **low confidence** and marked with
:class:`DetectionMethod.BINARY_SIGNATURE`. Downstream, the honesty layer
(``needs_verification``) routes them to the manual-review surface — because a
fingerprint in a binary tells you what's *linked in*, not what's *actually
used*, so a human should confirm before acting.

The scanner is deliberately narrow. Full binary analysis (control-flow
recovery, cross-references, symbol resolution) is out of scope; that is the
Phase-C "full" work called out in the roadmap.
"""

from __future__ import annotations

import logging
import re
import struct
from dataclasses import dataclass
from pathlib import Path

from app.config import Settings, get_settings
from app.models.asset import (
    ArtefactType,
    CipherMode,
    CryptoPrimitive,
    CryptoUsage,
    ParameterStatus,
)
from app.models.finding import DetectionMethod, Evidence, NormalizedFinding

logger = logging.getLogger(__name__)

# ── Binary detection ────────────────────────────────────────────────────────

# Known executable / library file extensions we always try to scan.
_BINARY_EXTS: set[str] = {
    ".exe", ".dll", ".sys", ".pyd",       # PE
    ".so", ".a",                          # ELF / archive
    ".dylib", ".bundle",                  # Mach-O
    ".o", ".obj", ".lib",                 # object / static libs
}

# Magic-number sniff for files without a recognised extension.
_MAGIC_PREFIXES: tuple[bytes, ...] = (
    b"\x7fELF",         # ELF (Linux / BSD)
    b"MZ",              # DOS/PE (Windows)
    b"\xca\xfe\xba\xbe",  # Mach-O fat / Java class — we only bother reading crypto strings
    b"\xcf\xfa\xed\xfe",  # Mach-O 64-bit little-endian
    b"\xfe\xed\xfa\xcf",  # Mach-O 64-bit big-endian
    b"\xce\xfa\xed\xfe",  # Mach-O 32-bit little-endian
    b"!<arch>",           # Unix archive (.a)
)


def _looks_binary(path: Path) -> bool:
    """True when *path* is worth scanning as a binary."""
    if path.suffix.lower() in _BINARY_EXTS:
        return True
    try:
        with path.open("rb") as f:
            head = f.read(8)
    except OSError:
        return False
    return any(head.startswith(prefix) for prefix in _MAGIC_PREFIXES)


# ── Signature definitions ───────────────────────────────────────────────────

@dataclass(frozen=True)
class _Signature:
    """One binary fingerprint the scanner looks for."""

    algorithm: str
    primitive: CryptoPrimitive
    artefact_type: ArtefactType
    usage: CryptoUsage
    label: str
    """Short human label of what was matched, e.g. 'AES S-box (bytes 0-16)'."""


def _sha2_h0_bytes(*ints: int) -> bytes:
    """Pack 32-bit words big-endian, the layout SHA-2 constants take on disk."""
    return b"".join(struct.pack(">I", v) for v in ints)


def _md5_h0_bytes(*ints: int) -> bytes:
    """MD5 stores its A/B/C/D state little-endian on disk."""
    return b"".join(struct.pack("<I", v) for v in ints)


def _sha1_h0_bytes(*ints: int) -> bytes:
    """SHA-1 stores its H0..H4 state big-endian on disk."""
    return b"".join(struct.pack(">I", v) for v in ints)


# The initial hash values from FIPS 180-4 / RFC 1321 — verbatim in almost
# every implementation. Ordering distinguishes SHA-1 (has the fifth word)
# from MD5 (shares the first four with SHA-1 but is stored little-endian).
_SHA256_H0 = _sha2_h0_bytes(
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)
_SHA512_H0 = b"".join(struct.pack(">Q", v) for v in (
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
))
_SHA1_H0 = _sha1_h0_bytes(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
_MD5_H0 = _md5_h0_bytes(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)

# First row of the AES S-box (FIPS 197) — unique, unambiguous marker.
_AES_SBOX_HEAD = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
)

# ASN.1 OID bodies (without the leading 06 <len>) for signature/hash algorithms.
# We match the DER-encoded oid *value*, which appears in x.509 tooling and TLS
# libraries even after linking. Keys are (algorithm, primitive) → OID bytes.
_OIDS: dict[tuple[str, CryptoPrimitive, ArtefactType, CryptoUsage, str], bytes] = {
    ("RSA", CryptoPrimitive.PKE, ArtefactType.KEY_EXCHANGE,
     CryptoUsage.KEY_ESTABLISHMENT, "rsaEncryption OID"):
        bytes.fromhex("2a864886f70d010101"),
    ("RSA", CryptoPrimitive.SIGNATURE, ArtefactType.SIGNATURE,
     CryptoUsage.DIGITAL_SIGNATURE, "sha256WithRSAEncryption OID"):
        bytes.fromhex("2a864886f70d01010b"),
    ("ECDSA", CryptoPrimitive.SIGNATURE, ArtefactType.SIGNATURE,
     CryptoUsage.DIGITAL_SIGNATURE, "ecdsa-with-SHA256 OID"):
        bytes.fromhex("2a8648ce3d040302"),
    ("ECDH", CryptoPrimitive.KEY_AGREE, ArtefactType.KEY_EXCHANGE,
     CryptoUsage.KEY_ESTABLISHMENT, "id-ecPublicKey OID"):
        bytes.fromhex("2a8648ce3d0201"),
    ("DH", CryptoPrimitive.KEY_AGREE, ArtefactType.KEY_EXCHANGE,
     CryptoUsage.KEY_ESTABLISHMENT, "dhpublicnumber OID"):
        bytes.fromhex("2a864886f70d0301"),
    ("DSA", CryptoPrimitive.SIGNATURE, ArtefactType.SIGNATURE,
     CryptoUsage.DIGITAL_SIGNATURE, "id-dsa OID"):
        bytes.fromhex("2a8648ce380401"),
}

# Constant → (algorithm, primitive, artefact type, usage, label).
_CONSTANT_SIGS: list[tuple[bytes, _Signature]] = [
    (_SHA256_H0, _Signature(
        "SHA-256", CryptoPrimitive.HASH, ArtefactType.HASH,
        CryptoUsage.INTEGRITY_HASH, "SHA-256 initial hash values (FIPS 180-4)",
    )),
    (_SHA512_H0, _Signature(
        "SHA-512", CryptoPrimitive.HASH, ArtefactType.HASH,
        CryptoUsage.INTEGRITY_HASH, "SHA-512 initial hash values (FIPS 180-4)",
    )),
    (_SHA1_H0, _Signature(
        "SHA-1", CryptoPrimitive.HASH, ArtefactType.HASH,
        CryptoUsage.INTEGRITY_HASH, "SHA-1 initial hash values (FIPS 180-4)",
    )),
    (_MD5_H0, _Signature(
        "MD5", CryptoPrimitive.HASH, ArtefactType.HASH,
        CryptoUsage.INTEGRITY_HASH, "MD5 initial digest (RFC 1321)",
    )),
    (_AES_SBOX_HEAD, _Signature(
        "AES", CryptoPrimitive.BLOCK_CIPHER, ArtefactType.ENCRYPTION,
        CryptoUsage.DATA_ENCRYPTION, "AES S-box (FIPS 197, bytes 0-32)",
    )),
]

# ASCII library strings — matched with a version regex so we can record it.
# Order matters: more specific / branded strings first.
_LIBRARY_STRINGS: list[tuple[re.Pattern[bytes], str, str]] = [
    (re.compile(rb"OpenSSL\s+(\d+\.\d+(?:\.\d+)?[a-z]?)"), "OpenSSL", "OpenSSL"),
    (re.compile(rb"BoringSSL"), "BoringSSL", "BoringSSL"),
    (re.compile(rb"wolfSSL\s+(\d+\.\d+(?:\.\d+)?)"), "wolfSSL", "wolfSSL"),
    (re.compile(rb"mbed\s*TLS\s+(\d+\.\d+(?:\.\d+)?)"), "mbedTLS", "mbedTLS"),
    (re.compile(rb"libsodium\s+(\d+\.\d+(?:\.\d+)?)"), "libsodium", "libsodium"),
    (re.compile(rb"libcrypto\.so"), "OpenSSL", "libcrypto"),
]


# ── Scanner ─────────────────────────────────────────────────────────────────

def _read_capped(path: Path, cap_bytes: int) -> bytes | None:
    """Read up to *cap_bytes* of *path*; return None on error / oversize."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > cap_bytes:
        logger.debug("Skipping oversized binary (%d bytes): %s", size, path.name)
        return None
    try:
        with path.open("rb") as f:
            return f.read()
    except OSError:
        return None


def _relative(path: Path, root: Path) -> str:
    """Best-effort relative-path formatter."""
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name


def _make_finding(
    fid: str,
    path: Path,
    root: Path,
    sig: _Signature,
    snippet: str,
    parameter: str | None = None,
) -> NormalizedFinding:
    """Build a low-confidence binary NormalizedFinding."""
    evidence = Evidence(
        file_path=_relative(path, root),
        line_number=None,
        code_snippet=snippet,
        detection_method=DetectionMethod.BINARY_SIGNATURE,
        # Deliberately low band (< 0.6) so `needs_verification` flags every
        # binary finding for human review. Fingerprint match is a hint, not
        # a proof of use.
        confidence=0.55,
    )
    return NormalizedFinding(
        id=fid,
        algorithm=sig.algorithm,
        primitive=sig.primitive,
        parameter=parameter,
        parameter_status=ParameterStatus.RESOLVED if parameter else ParameterStatus.NOT_APPLICABLE,
        mode=CipherMode.UNKNOWN if sig.artefact_type == ArtefactType.ENCRYPTION else None,
        usage=sig.usage,
        artefact_type=sig.artefact_type,
        evidence=evidence,
    )


def _scan_bytes(
    data: bytes, path: Path, root: Path, seen: set[str]
) -> list[NormalizedFinding]:
    """Match every known signature against *data* and emit findings.

    ``seen`` deduplicates by ``(file, algorithm, label)`` — a single binary
    that happens to embed the same constant twice yields one finding, not two.
    """
    findings: list[NormalizedFinding] = []
    rel = _relative(path, root)

    def _emit(algo: str, label: str, factory) -> None:
        key = f"{rel}|{algo}|{label}"
        if key in seen:
            return
        seen.add(key)
        findings.append(factory())

    # 1) Constants. Order matters: check SHA-1 (5 words) before MD5 (4 words)
    #    so an SHA-1 hit is never misreported as MD5.
    for needle, sig in _CONSTANT_SIGS:
        if needle in data:
            _emit(
                sig.algorithm, sig.label,
                lambda p=path, r=root, s=sig: _make_finding(
                    f"BIN-{_relative(p, r)}-{s.algorithm}".replace("/", "_").replace("\\", "_"),
                    p, r, s, snippet=s.label,
                ),
            )

    # 2) ASN.1 OID hits — high-value markers for asymmetric algorithms.
    for (algo, primitive, at, usage, label), oid_body in _OIDS.items():
        if oid_body in data:
            sig = _Signature(algo, primitive, at, usage, label)
            _emit(
                sig.algorithm, sig.label,
                lambda p=path, r=root, s=sig: _make_finding(
                    f"BIN-{_relative(p, r)}-{s.algorithm}-oid".replace("/", "_").replace("\\", "_"),
                    p, r, s, snippet=s.label,
                ),
            )

    # 3) Library strings. Emit an INFO finding (Unknown artefact) so operators
    #    know which crypto library is linked, without asserting any primitive.
    for pattern, algo_family, label in _LIBRARY_STRINGS:
        m = pattern.search(data)
        if m:
            version = m.group(1).decode("ascii", "replace") if m.lastindex else ""
            snippet = f"{label} present" + (f" (version {version})" if version else "")
            sig = _Signature(
                algorithm=f"{algo_family}-linked",
                primitive=CryptoPrimitive.UNKNOWN,
                artefact_type=ArtefactType.UNKNOWN,
                usage=CryptoUsage.UNKNOWN,
                label=snippet,
            )
            _emit(
                sig.algorithm, snippet,
                lambda p=path, r=root, s=sig, snip=snippet, v=version: _make_finding(
                    f"BIN-{_relative(p, r)}-{s.algorithm}".replace("/", "_").replace("\\", "_"),
                    p, r, s, snippet=snip, parameter=v or None,
                ),
            )

    return findings


def scan_binaries(
    target: Path, settings: Settings | None = None
) -> list[NormalizedFinding]:
    """Walk *target* for binary files and return fingerprint findings.

    Deterministic: files are visited in sorted path order; findings within a
    file are emitted in signature-table order and deduplicated per
    ``(file, algorithm, label)``.
    """
    settings = settings or get_settings()
    if not settings.binary_scan_enabled:
        return []

    root = Path(target).resolve()
    if not root.exists():
        return []

    cap = int(settings.binary_max_scan_mb) * 1024 * 1024
    findings: list[NormalizedFinding] = []
    seen: set[str] = set()

    iterator = [root] if root.is_file() else sorted(root.rglob("*"))
    for path in iterator:
        try:
            if not path.is_file() or path.is_symlink():
                continue
        except OSError:
            continue
        if not _looks_binary(path):
            continue

        data = _read_capped(path, cap)
        if data is None:
            continue
        try:
            findings.extend(_scan_bytes(data, path, root, seen))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Binary scan failed for %s: %s", path.name, exc)

    if findings:
        logger.info(
            "Binary scan: %d finding(s) across %d file(s) under %s.",
            len(findings),
            len({f.evidence.file_path for f in findings}),
            root.name or root,
        )
    return findings
