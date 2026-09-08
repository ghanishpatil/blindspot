"""Dependency and manifest parsing.

Source scanning misses cryptography that arrives through dependencies. This
module reads manifests (``requirements.txt``) and reports the cryptographic
capability those dependencies introduce.

Findings from this source carry ``DetectionMethod.DEPENDENCY_MANIFEST`` and a
lower confidence than a direct API call: a declared dependency proves
*capability*, not *use*.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# Known crypto-providing packages and the algorithms they make available.
# This is a manual mapping — small enough for the demo, and it makes the
# provenance explicit rather than guessing from package names.
CRYPTO_PACKAGES: dict[str, dict] = {
    "cryptography": {
        "provides": ["RSA", "ECDH", "ECDSA", "AES", "3DES", "SHA-1", "SHA-256", "MD5"],
        "description": "pyca/cryptography — primary Python crypto provider",
        "confidence": 0.7,
    },
    "pyopenssl": {
        "provides": ["RSA", "ECDH", "ECDSA", "AES", "3DES", "SHA-1", "SHA-256", "MD5"],
        "description": "Python bindings for the OpenSSL C library",
        "confidence": 0.5,
    },
    "pycryptodome": {
        "provides": ["RSA", "DES", "3DES", "AES", "MD5", "SHA-1", "SHA-256"],
        "description": "PyCryptodome — self-contained crypto library",
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
        "description": "SSH protocol library — bundles crypto for transport",
        "confidence": 0.45,
    },
}

# Pattern: package_name (optional extras) ==/>=/~= version
_REQ_LINE = re.compile(
    r"^([A-Za-z0-9][\w.\-]*)"     # package name
    r"(?:\[[\w,.\- ]*\])?"        # optional extras
    r"\s*([!=<>~]+\s*[\w.*]+)?"   # optional version spec
)


def _parse_requirements_txt(path: Path) -> list[dict]:
    """Parse a requirements.txt file and return dependency findings."""
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

        package_name = match.group(1).lower().replace("-", "").replace("_", "")
        version_spec = (match.group(2) or "").strip()

        # Look up in our known-crypto-packages table.
        for known_name, info in CRYPTO_PACKAGES.items():
            normalized_known = known_name.lower().replace("-", "").replace("_", "")
            if package_name == normalized_known:
                version = version_spec.lstrip("=<>!~").strip() if version_spec else None
                findings.append({
                    "package": known_name,
                    "version": version,
                    "line_number": line_number,
                    "raw_line": raw_line.strip(),
                    "file_path": str(path),
                    "provides": info["provides"],
                    "description": info["description"],
                    "confidence": info["confidence"],
                    "detection_method": "dependency_manifest",
                })
                break

    return findings


def parse_dependencies(target: Path) -> list[dict]:
    """Parse dependency manifests under *target* and return findings.

    Currently supports ``requirements.txt``. Each finding describes a package
    that is known to provide cryptographic capability.
    """
    findings: list[dict] = []

    # Walk the target looking for manifests.
    if target.is_file():
        search_root = target.parent
    else:
        search_root = target

    for req_file in sorted(search_root.rglob("requirements*.txt")):
        logger.info("Parsing dependency manifest: %s", req_file)
        try:
            found = _parse_requirements_txt(req_file)
            findings.extend(found)
            logger.info(
                "  %d crypto-providing packages in %s",
                len(found),
                req_file.name,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to parse %s: %s", req_file, exc)

    return findings
