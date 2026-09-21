"""Dependency and manifest parsing.

Source scanning misses cryptography that arrives through dependencies. This
module reads manifests (``requirements.txt``, ``pom.xml``, ``package.json``,
``go.mod``) and reports the cryptographic capability those dependencies
introduce.

Findings from this source carry ``DetectionMethod.DEPENDENCY_MANIFEST`` and a
lower confidence than a direct API call: a declared dependency proves
*capability*, not *use*. That distinction is why R3 (source rules per
language) and R4 (dependency parsers per ecosystem) are separate scanners —
they close different halves of the same PS clause.

Two rules keep this scanner honest:

1. **Only crypto-providing packages surface.** The lookup tables are curated
   allowlists. A random library that happens to import ``crypto`` does not
   count; we only report packages whose stated purpose is to provide
   cryptographic primitives.
2. **Confidence is capped at the medium band.** A ``pom.xml`` entry for
   ``bcprov-jdk18on`` proves the JAR is on the classpath, not that it is
   actually invoked. Source scanning (R3) is what proves invocation.
"""

from __future__ import annotations

import json
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Curated crypto-provider tables (one per ecosystem).
#
# Each entry names the algorithms the package makes available (not necessarily
# used) and a `confidence` value in the medium band. Descriptions are kept
# short but attribution-worthy so a reviewer can see why the package landed on
# the list.
# ═══════════════════════════════════════════════════════════════════════════

# ── Python (pip) ───────────────────────────────────────────────────────────
CRYPTO_PACKAGES: dict[str, dict] = {
    "cryptography": {
        "provides": ["RSA", "ECDH", "ECDSA", "AES", "3DES", "SHA-1", "SHA-256", "MD5"],
        "description": "pyca/cryptography - primary Python crypto provider",
        "confidence": 0.7,
    },
    "pyopenssl": {
        "provides": ["RSA", "ECDH", "ECDSA", "AES", "3DES", "SHA-1", "SHA-256", "MD5"],
        "description": "Python bindings for the OpenSSL C library",
        "confidence": 0.5,
    },
    "pycryptodome": {
        "provides": ["RSA", "DES", "3DES", "AES", "MD5", "SHA-1", "SHA-256"],
        "description": "PyCryptodome - self-contained crypto library",
        "confidence": 0.65,
    },
    "pycryptodomex": {
        "provides": ["RSA", "DES", "3DES", "AES", "MD5", "SHA-1", "SHA-256"],
        "description": "PyCryptodome (non-conflicting namespace)",
        "confidence": 0.65,
    },
    "pyca": {
        "provides": ["RSA", "ECDH", "ECDSA", "AES", "3DES"],
        "description": "Alias for pyca/cryptography ecosystem",
        "confidence": 0.5,
    },
    "pynacl": {
        "provides": ["X25519", "Ed25519", "AES"],
        "description": "Python binding to libsodium",
        "confidence": 0.6,
    },
    "paramiko": {
        "provides": ["RSA", "ECDSA", "AES", "3DES"],
        "description": "SSH protocol library - bundles crypto for transport",
        "confidence": 0.45,
    },
}


# ── Maven (Java) ──────────────────────────────────────────────────────────
# Keyed by ``groupId:artifactId`` (BouncyCastle publishes several artefacts;
# each is treated independently so a project that pulls in only ``bctls`` is
# not credited with the entire BC surface).
CRYPTO_PACKAGES_MAVEN: dict[str, dict] = {
    "org.bouncycastle:bcprov-jdk18on": {
        "provides": [
            "RSA", "DSA", "ECDSA", "ECDH", "Ed25519", "X25519",
            "AES", "3DES", "DES", "ChaCha20", "MD5", "SHA-1", "SHA-256",
        ],
        "description": "BouncyCastle provider - main crypto primitives",
        "confidence": 0.65,
    },
    "org.bouncycastle:bcprov-jdk15on": {
        "provides": [
            "RSA", "DSA", "ECDSA", "ECDH", "Ed25519", "X25519",
            "AES", "3DES", "DES", "MD5", "SHA-1", "SHA-256",
        ],
        "description": "BouncyCastle provider - legacy JDK 15 artefact",
        "confidence": 0.65,
    },
    "org.bouncycastle:bcprov-ext-jdk18on": {
        "provides": ["RSA", "DSA", "ECDSA", "ECDH", "AES", "MD5", "SHA-1"],
        "description": "BouncyCastle extended provider",
        "confidence": 0.6,
    },
    "org.bouncycastle:bcpkix-jdk18on": {
        "provides": ["RSA", "ECDSA", "DSA"],
        "description": "BouncyCastle PKIX / CMS / OCSP - certificate operations",
        "confidence": 0.55,
    },
    "org.bouncycastle:bctls-jdk18on": {
        "provides": ["RSA", "ECDH", "ECDSA", "X25519", "Ed25519", "AES", "ChaCha20"],
        "description": "BouncyCastle TLS stack",
        "confidence": 0.6,
    },
    "org.bouncycastle:bcpg-jdk18on": {
        "provides": ["RSA", "DSA", "ECDSA", "AES", "3DES", "MD5", "SHA-1"],
        "description": "BouncyCastle OpenPGP",
        "confidence": 0.55,
    },
    "com.google.crypto.tink:tink": {
        "provides": ["AES", "ECDSA", "Ed25519", "SHA-256"],
        "description": "Google Tink - opinionated safe-defaults crypto",
        "confidence": 0.6,
    },
    "commons-codec:commons-codec": {
        "provides": ["MD5", "SHA-1", "SHA-256"],
        "description": "Apache Commons Codec - DigestUtils and encoders",
        "confidence": 0.45,
    },
    "org.jasypt:jasypt": {
        "provides": ["AES", "3DES", "DES", "MD5", "SHA-1"],
        "description": "Jasypt - simplified encryption for Java",
        "confidence": 0.55,
    },
}


# ── npm / yarn (JavaScript / TypeScript) ──────────────────────────────────
CRYPTO_PACKAGES_NPM: dict[str, dict] = {
    "node-forge": {
        "provides": ["RSA", "AES", "DES", "3DES", "MD5", "SHA-1", "SHA-256"],
        "description": "node-forge - pure-JS PKI + crypto toolkit",
        "confidence": 0.65,
    },
    "crypto-js": {
        "provides": ["AES", "DES", "3DES", "MD5", "SHA-1", "SHA-256"],
        "description": "crypto-js - pure-JS symmetric crypto + hashes",
        "confidence": 0.65,
    },
    "elliptic": {
        "provides": ["ECDSA", "ECDH", "Ed25519"],
        "description": "elliptic - EC / EdDSA in pure JS",
        "confidence": 0.6,
    },
    "tweetnacl": {
        "provides": ["Ed25519", "X25519"],
        "description": "TweetNaCl.js - NaCl port; Ed25519 signatures, X25519 KEX",
        "confidence": 0.6,
    },
    "jsrsasign": {
        "provides": ["RSA", "ECDSA", "DSA", "AES", "DES", "SHA-1", "SHA-256"],
        "description": "jsrsasign - RSA/DSA/EC signature toolkit",
        "confidence": 0.6,
    },
    "sshpk": {
        "provides": ["RSA", "ECDSA", "Ed25519", "DSA"],
        "description": "sshpk - SSH key parsing (uses node:crypto)",
        "confidence": 0.5,
    },
    "jose": {
        "provides": ["RSA", "ECDSA", "Ed25519", "AES"],
        "description": "jose - JOSE (JWS / JWE / JWK / JWT) toolkit",
        "confidence": 0.55,
    },
    "jsonwebtoken": {
        "provides": ["RSA", "ECDSA", "SHA-256"],
        "description": "jsonwebtoken - HS/RS/ES-signed JWTs",
        "confidence": 0.5,
    },
}


# ── Go modules ────────────────────────────────────────────────────────────
# Keyed by module path (not `import` path, since go.mod uses module paths).
CRYPTO_PACKAGES_GO: dict[str, dict] = {
    "golang.org/x/crypto": {
        "provides": ["Ed25519", "X25519", "ChaCha20", "AES", "SHA-256"],
        "description": "Extended Go crypto - Ed25519, X25519, ChaCha20-Poly1305, HKDF, argon2",
        "confidence": 0.6,
    },
    "github.com/cloudflare/circl": {
        # circl bundles both classical curves and post-quantum primitives.
        # The `provides` list stays on classical primitives only; the PQC
        # side is *capability*, not risk-worthy inventory.
        "provides": ["Ed25519", "X25519", "ECDSA", "AES"],
        "description": "Cloudflare CIRCL - classical + PQC (ML-KEM, ML-DSA)",
        "confidence": 0.55,
    },
    "filippo.io/edwards25519": {
        "provides": ["Ed25519"],
        "description": "Low-level Ed25519 primitives",
        "confidence": 0.55,
    },
    "github.com/google/tink/go": {
        "provides": ["AES", "ECDSA", "Ed25519", "SHA-256"],
        "description": "Google Tink for Go - opinionated crypto",
        "confidence": 0.6,
    },
    "github.com/miekg/pkcs11": {
        "provides": ["RSA", "ECDSA", "AES"],
        "description": "PKCS#11 bindings for Go - HSM surface",
        "confidence": 0.4,
    },
    "github.com/ProtonMail/go-crypto": {
        "provides": ["RSA", "ECDSA", "Ed25519", "AES", "SHA-256"],
        "description": "ProtonMail's OpenPGP fork for Go",
        "confidence": 0.55,
    },
}


# ═══════════════════════════════════════════════════════════════════════════
# Small helpers used by every parser
# ═══════════════════════════════════════════════════════════════════════════

def _normalize_python(name: str) -> str:
    """PEP 503 name normalisation (case-insensitive, hyphen / underscore /
    period collapsed to hyphen). Kept minimal for the tests we run."""
    return name.strip().lower().replace("-", "").replace("_", "")


def _finding_dict(
    *,
    package: str,
    version: str | None,
    file_path: Path,
    line_number: int,
    raw_line: str,
    info: dict,
) -> dict:
    """Uniform result shape consumed by ``evidence.extractor.extract_from_dependency``.

    Every ecosystem parser produces this exact schema so the extractor never
    has to branch on where the finding came from.
    """
    return {
        "package": package,
        "version": version,
        "line_number": line_number,
        "raw_line": raw_line,
        "file_path": str(file_path),
        "provides": info["provides"],
        "description": info["description"],
        "confidence": info["confidence"],
        "detection_method": "dependency_manifest",
    }


# ═══════════════════════════════════════════════════════════════════════════
# Python — requirements*.txt
# ═══════════════════════════════════════════════════════════════════════════

_REQ_LINE = re.compile(
    r"^([A-Za-z0-9][\w.\-]*)"     # package name
    r"(?:\[[\w,.\- ]*\])?"        # optional extras
    r"\s*([!=<>~]+\s*[\w.*]+)?"   # optional version spec
)


def _parse_requirements_txt(path: Path) -> list[dict]:
    """Parse a ``requirements.txt`` file and return dependency findings."""
    findings: list[dict] = []

    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        match = _REQ_LINE.match(line)
        if not match:
            continue

        package_name = _normalize_python(match.group(1))
        version_spec = (match.group(2) or "").strip()

        for known_name, info in CRYPTO_PACKAGES.items():
            if package_name == _normalize_python(known_name):
                version = version_spec.lstrip("=<>!~").strip() if version_spec else None
                findings.append(_finding_dict(
                    package=known_name,
                    version=version,
                    file_path=path,
                    line_number=line_number,
                    raw_line=raw_line.strip(),
                    info=info,
                ))
                break

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Maven — pom.xml
# ═══════════════════════════════════════════════════════════════════════════

# Maven POMs live under the ``http://maven.apache.org/POM/4.0.0`` namespace.
# Element names are always namespaced in the parsed tree, so we strip the
# namespace prefix before comparing tag names.
def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _find_child(node: ET.Element, name: str) -> ET.Element | None:
    for child in node:
        if _localname(child.tag) == name:
            return child
    return None


def _text(node: ET.Element | None) -> str | None:
    if node is None or node.text is None:
        return None
    return node.text.strip() or None


def _parse_pom_xml(path: Path) -> list[dict]:
    """Parse a Maven ``pom.xml`` and return crypto-provider dependencies.

    Only ``<dependency>`` entries in ``<dependencies>`` (and inside
    ``<dependencyManagement>``) are inspected. Plugin declarations, parent
    imports, and reporting configuration are ignored.
    """
    findings: list[dict] = []

    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        logger.warning("Malformed pom.xml at %s: %s", path, exc)
        return findings

    root = tree.getroot()

    # ``findall`` with wildcard namespace + localname is XPath-1.0 only, and
    # ElementTree doesn't implement wildcard namespaces on tag matches. Walk
    # manually.
    for dep in root.iter():
        if _localname(dep.tag) != "dependency":
            continue
        group_id = _text(_find_child(dep, "groupId"))
        artifact_id = _text(_find_child(dep, "artifactId"))
        version = _text(_find_child(dep, "version"))
        if not group_id or not artifact_id:
            continue

        coord = f"{group_id}:{artifact_id}"
        info = CRYPTO_PACKAGES_MAVEN.get(coord)
        if info is None:
            continue

        raw = f"<dependency> {coord}"
        if version:
            raw += f":{version}"

        findings.append(_finding_dict(
            package=coord,
            version=version,
            file_path=path,
            # ElementTree does not preserve source line numbers on 3.10.
            # A stable value of 1 keeps evidence pointing at the file, and
            # the raw_line carries the coordinate string for context.
            line_number=1,
            raw_line=raw,
            info=info,
        ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# npm / yarn — package.json (+ optional package-lock.json for exact versions)
# ═══════════════════════════════════════════════════════════════════════════

_NPM_DEP_SECTIONS = (
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
)


def _parse_package_json(path: Path) -> list[dict]:
    """Parse a ``package.json`` and return crypto-provider dependencies.

    Only the four dependency sections defined by npm are inspected. Fields
    like ``bundledDependencies`` and ``resolutions`` are ignored because
    they do not add capability that the primary sections did not already
    declare.
    """
    findings: list[dict] = []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Could not read/parse %s: %s", path, exc)
        return findings

    if not isinstance(data, dict):
        return findings

    seen: set[str] = set()
    for section in _NPM_DEP_SECTIONS:
        deps = data.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for pkg, version_range in deps.items():
            if not isinstance(pkg, str) or pkg in seen:
                continue
            info = CRYPTO_PACKAGES_NPM.get(pkg)
            if info is None:
                continue
            seen.add(pkg)
            # Version range as declared (e.g. "^1.2.3"). We do NOT try to
            # resolve to an installed exact version here — that would need
            # a lockfile join, and misdeclaring the version is worse than
            # reporting the declared range.
            version = version_range if isinstance(version_range, str) else None
            raw = f'"{pkg}": "{version}"' if version else f'"{pkg}"'
            findings.append(_finding_dict(
                package=pkg,
                version=version,
                file_path=path,
                line_number=1,
                raw_line=raw,
                info=info,
            ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Go — go.mod (require blocks and inline require lines)
# ═══════════════════════════════════════════════════════════════════════════

# Line inside a `require ( ... )` block or a bare `require path version`
# statement. Version tokens look like `v1.2.3`, `v0.0.0-20240315-abcdef`,
# `v1.2.3+incompatible`, so we accept `[^\s]+`.
_GO_REQUIRE_LINE = re.compile(r"^\s*([^\s/][^\s]*)\s+(v[^\s]+)")
_GO_INDIRECT_LINE = re.compile(r"//\s*indirect\s*$")


def _parse_go_mod(path: Path) -> list[dict]:
    """Parse a Go ``go.mod`` and return crypto-provider dependencies.

    Handles both forms::

        require golang.org/x/crypto v0.31.0

        require (
            golang.org/x/crypto v0.31.0
            github.com/cloudflare/circl v1.3.7
        )

    Indirect dependencies (marked with ``// indirect``) are still surfaced
    because a transitive crypto library still puts the primitives on the
    build classpath. Their confidence is the same as direct — capability
    signal is capability signal.
    """
    findings: list[dict] = []

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("Could not read %s: %s", path, exc)
        return findings

    in_block = False
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()

        # Track `require ( ... )` block boundaries.
        if stripped.startswith("require ("):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue

        # Skip comments and blank lines.
        if not stripped or stripped.startswith("//"):
            continue

        candidate = stripped
        if not in_block:
            # A bare `require` line: strip the keyword.
            if candidate.startswith("require "):
                candidate = candidate[len("require ") :].strip()
            else:
                continue

        # Drop trailing `// indirect` markers for the regex match.
        candidate_no_comment = _GO_INDIRECT_LINE.sub("", candidate).rstrip()
        match = _GO_REQUIRE_LINE.match(candidate_no_comment)
        if not match:
            continue

        module_path = match.group(1)
        version = match.group(2)

        info = CRYPTO_PACKAGES_GO.get(module_path)
        if info is None:
            continue

        findings.append(_finding_dict(
            package=module_path,
            version=version,
            file_path=path,
            line_number=line_number,
            raw_line=stripped,
            info=info,
        ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Top-level walker
# ═══════════════════════════════════════════════════════════════════════════

# One entry per (glob-pattern, parser). ``rglob`` is used against the target
# so nested modules and monorepos are covered. Order does not matter — every
# match is processed independently.
_PARSERS: list[tuple[str, "callable[[Path], list[dict]]"]] = [
    ("requirements*.txt", _parse_requirements_txt),
    ("pom.xml", _parse_pom_xml),
    ("package.json", _parse_package_json),
    ("go.mod", _parse_go_mod),
]

# Directories we never descend into — they hold installed dependencies, not
# manifests we should re-parse. Missing them dramatically speeds up scans of
# real repositories.
_SKIP_DIRS: frozenset[str] = frozenset({
    "node_modules",
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    "target",  # Maven build output
    ".idea",
    ".gradle",
})


def _walk_manifests(root: Path) -> Iterable[Path]:
    """Yield every manifest under *root*, skipping installed-dep directories."""
    if root.is_file():
        yield root
        return
    if not root.is_dir():
        return

    for candidate in root.rglob("*"):
        if not candidate.is_file():
            continue
        # Skip anything under a known noisy directory.
        rel_parts = candidate.relative_to(root).parts
        if any(part in _SKIP_DIRS for part in rel_parts[:-1]):
            continue
        name_lower = candidate.name.lower()
        if name_lower.startswith("requirements") and name_lower.endswith(".txt"):
            yield candidate
        elif name_lower in ("pom.xml", "package.json", "go.mod"):
            yield candidate


def parse_dependencies(target: Path) -> list[dict]:
    """Parse every supported manifest under *target* and return findings.

    Supported ecosystems:

    * **Python** - ``requirements*.txt``
    * **Java** - ``pom.xml`` (Maven)
    * **JavaScript / TypeScript** - ``package.json`` (npm / yarn / pnpm)
    * **Go** - ``go.mod``

    Each finding describes a package that is known to provide cryptographic
    capability. The pipeline downgrades these to medium confidence because a
    declared dependency proves capability, not use.
    """
    findings: list[dict] = []

    if target.is_file():
        search_root = target.parent
    else:
        search_root = target

    for manifest in _walk_manifests(search_root):
        name_lower = manifest.name.lower()

        if name_lower.startswith("requirements") and name_lower.endswith(".txt"):
            parser = _parse_requirements_txt
        elif name_lower == "pom.xml":
            parser = _parse_pom_xml
        elif name_lower == "package.json":
            parser = _parse_package_json
        elif name_lower == "go.mod":
            parser = _parse_go_mod
        else:
            continue

        logger.info("Parsing dependency manifest: %s", manifest)
        try:
            found = parser(manifest)
            findings.extend(found)
            logger.info("  %d crypto-providing packages in %s", len(found), manifest.name)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to parse %s: %s", manifest, exc)

    return findings
