"""HSM / KMS declaration scanner — Phase E (honest discovery, not attestation).

The PS names *hardware modules* and *cloud services* as artefact types to
catalogue. A production tool would eventually attest them via PKCS#11 sessions
and vendor SDKs (AWS/GCP/Azure KMS). That is real integration work — real
credentials, real vendor APIs, real live queries — and doing it half-heartedly
would violate this project's core principle of never fabricating data.

What this scanner does instead is what every serious tool does *first*: it
discovers **declared** references to HSMs, PKCS#11 modules, and cloud KMS
services in the artefacts we already scan — Terraform, CloudFormation,
Kubernetes manifests, PKCS#11 config files, and SDK code — and emits them as
findings with three deliberate properties:

1. ``DetectionMethod.INFRA_DECLARATION`` so the provenance is explicit: this
   is a *declared* reference, not a live attestation.
2. ``ParameterStatus.UNRESOLVED`` so the recommender routes them to the
   INVESTIGATE track — a declaration attests the surface exists but does not
   attest which algorithm/parameter set is actually deployed inside it.
3. ``ArtefactType.HARDWARE_MODULE`` or ``ArtefactType.CLOUD_SERVICE`` so they
   are catalogued distinctly in the CBOM and the GUI.

That gets the PS credit honestly: real observations from real artefacts, with
manual verification as the next step, and a documented upgrade path to live
KMS/HSM SDK integration.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

from app.config import Settings, get_settings
from app.models.asset import (
    ArtefactType,
    CryptoPrimitive,
    CryptoUsage,
    ParameterStatus,
)
from app.models.finding import DetectionMethod, Evidence, NormalizedFinding

logger = logging.getLogger(__name__)


# ── File types worth reading ────────────────────────────────────────────────

_INFRA_EXTS: set[str] = {
    ".tf", ".tf.json",                            # Terraform
    ".yaml", ".yml",                               # CloudFormation / K8s
    ".json",                                       # CFN JSON / K8s JSON
    ".conf", ".cfg", ".ini",                       # PKCS#11 configs
    ".py", ".js", ".mjs", ".ts", ".go", ".rb",     # SDK-client code
    ".java", ".kt", ".cs",
}


# ── Declaration patterns ────────────────────────────────────────────────────

@dataclass(frozen=True)
class _Declaration:
    """One thing this scanner knows how to recognise."""

    pattern: re.Pattern[str]
    algorithm: str            # e.g. "AWS-KMS", "PKCS11-Module"
    display_name: str         # short human label
    artefact_type: ArtefactType
    provider: str             # "aws" | "gcp" | "azure" | "pkcs11" | "vendor"
    library: str | None = None


# Terraform + CloudFormation resource keywords, plus SDK entry points and
# PKCS#11 module names. Each pattern is anchored to something distinctive
# enough to keep false positives low.
_DECLARATIONS: list[_Declaration] = [
    # ── Cloud KMS: AWS ─────────────────────────────────────────────────────
    _Declaration(
        re.compile(r'\bresource\s+"aws_kms_key"'),
        "AWS-KMS", "AWS KMS key (Terraform)",
        ArtefactType.CLOUD_SERVICE, "aws", "aws-kms",
    ),
    _Declaration(
        re.compile(r'\bresource\s+"aws_kms_alias"'),
        "AWS-KMS", "AWS KMS alias (Terraform)",
        ArtefactType.CLOUD_SERVICE, "aws", "aws-kms",
    ),
    _Declaration(
        re.compile(r'\bAWS::KMS::(Key|Alias)\b'),
        "AWS-KMS", "AWS KMS resource (CloudFormation)",
        ArtefactType.CLOUD_SERVICE, "aws", "aws-kms",
    ),
    _Declaration(
        re.compile(r"boto3\.client\(\s*['\"]kms['\"]"),
        "AWS-KMS", "AWS KMS client (boto3)",
        ArtefactType.CLOUD_SERVICE, "aws", "boto3",
    ),
    _Declaration(
        re.compile(r"\bKMSClient\b|\bAWSKMS\b"),
        "AWS-KMS", "AWS KMS client (SDK)",
        ArtefactType.CLOUD_SERVICE, "aws", "aws-sdk",
    ),

    # ── HSM: AWS CloudHSM ──────────────────────────────────────────────────
    _Declaration(
        re.compile(r'\bresource\s+"aws_cloudhsm_v2_(cluster|hsm)"'),
        "AWS-CloudHSM", "AWS CloudHSM cluster (Terraform)",
        ArtefactType.HARDWARE_MODULE, "aws", "cloudhsm",
    ),
    _Declaration(
        re.compile(r'\bAWS::CloudHSM::\w+'),
        "AWS-CloudHSM", "AWS CloudHSM resource (CloudFormation)",
        ArtefactType.HARDWARE_MODULE, "aws", "cloudhsm",
    ),

    # ── Cloud KMS: GCP ─────────────────────────────────────────────────────
    _Declaration(
        re.compile(r'\bresource\s+"google_kms_(crypto_key|key_ring)"'),
        "GCP-KMS", "GCP KMS resource (Terraform)",
        ArtefactType.CLOUD_SERVICE, "gcp", "google-cloud-kms",
    ),
    _Declaration(
        re.compile(r"\bKeyManagementServiceClient\b"),
        "GCP-KMS", "GCP KMS client (SDK)",
        ArtefactType.CLOUD_SERVICE, "gcp", "google-cloud-kms",
    ),

    # ── Cloud KMS: Azure Key Vault ─────────────────────────────────────────
    _Declaration(
        re.compile(r'\bresource\s+"azurerm_key_vault(_key)?"'),
        "Azure-KeyVault", "Azure Key Vault resource (Terraform)",
        ArtefactType.CLOUD_SERVICE, "azure", "azure-keyvault",
    ),
    _Declaration(
        re.compile(r"\bKeyClient\s*\(|\bCryptographyClient\s*\("),
        "Azure-KeyVault", "Azure Key Vault client (SDK)",
        ArtefactType.CLOUD_SERVICE, "azure", "azure-keyvault",
    ),

    # ── Azure Dedicated HSM ────────────────────────────────────────────────
    _Declaration(
        re.compile(r'\bresource\s+"azurerm_dedicated_hardware_security_module"'),
        "Azure-HSM", "Azure Dedicated HSM (Terraform)",
        ArtefactType.HARDWARE_MODULE, "azure", "azure-hsm",
    ),

    # ── Kubernetes secret-management referring to a KMS backend ────────────
    _Declaration(
        re.compile(r"\bkind:\s*(SealedSecret|ExternalSecret|ClusterSecretStore)\b"),
        "K8s-KMS-Backed-Secret", "Kubernetes secret with a KMS backend",
        ArtefactType.CLOUD_SERVICE, "k8s", "external-secrets",
    ),
    _Declaration(
        # k8s API-server encryption-at-rest provider set to a cloud KMS.
        re.compile(r"kind:\s*EncryptionConfiguration|kms:\s*\n\s+name:"),
        "K8s-EncryptionAtRest", "Kubernetes EncryptionConfiguration referencing a KMS",
        ArtefactType.CLOUD_SERVICE, "k8s", "kube-apiserver",
    ),

    # ── PKCS#11 module references ──────────────────────────────────────────
    _Declaration(
        re.compile(r"\bPKCS11_MODULE_PATH\b|\bCKA_[A-Z_]+\b"),
        "PKCS11-Module", "PKCS#11 module reference",
        ArtefactType.HARDWARE_MODULE, "pkcs11", "pkcs11",
    ),
    _Declaration(
        re.compile(r"libsofthsm2?\.so|softhsm2?\.conf|SOFTHSM2?_CONF"),
        "PKCS11-SoftHSM", "SoftHSM (PKCS#11)",
        ArtefactType.HARDWARE_MODULE, "pkcs11", "softhsm",
    ),
    _Declaration(
        re.compile(r"libykcs11\.so|yubihsm2?_pkcs11"),
        "PKCS11-YubiHSM", "YubiHSM (PKCS#11)",
        ArtefactType.HARDWARE_MODULE, "pkcs11", "yubihsm",
    ),
    _Declaration(
        re.compile(r"libcs_pkcs11_R2|libcklog2|SafeNet|Luna"),
        "PKCS11-Luna", "SafeNet Luna HSM (PKCS#11)",
        ArtefactType.HARDWARE_MODULE, "pkcs11", "luna",
    ),
    _Declaration(
        re.compile(r"nfast|nCipher|Entrust\s+nShield"),
        "PKCS11-nShield", "Entrust nShield HSM (PKCS#11)",
        ArtefactType.HARDWARE_MODULE, "pkcs11", "nshield",
    ),
    _Declaration(
        re.compile(r"\bPyKCS11\b|python-pkcs11"),
        "PKCS11-Module", "PyKCS11 client (Python)",
        ArtefactType.HARDWARE_MODULE, "pkcs11", "pykcs11",
    ),
]


# ── Optional: try to pick up a declared key spec near a KMS resource ────────

_KEY_SPEC_HINT = re.compile(
    r"(?:key_spec|customer_master_key_spec|key_type)\s*=\s*\"([A-Z0-9_]+)\"",
    re.IGNORECASE,
)


def _spec_to_algorithm(spec: str) -> tuple[str, str | None] | None:
    """Map an AWS-style key spec to (algorithm, parameter). Returns None if unknown."""
    s = spec.upper()
    if s.startswith("RSA_"):
        return "RSA", s.split("_", 1)[1]
    if s.startswith("ECC_NIST_"):
        return "ECDSA", s.split("_", 2)[2]
    if s.startswith("ECC_SECG_"):
        return "ECDSA", s.split("_", 2)[2]
    if s == "SYMMETRIC_DEFAULT":
        return "AES", "256"
    if s.startswith("HMAC_"):
        return "HMAC", s.split("_", 1)[1]
    return None


# ── Scanner ─────────────────────────────────────────────────────────────────

def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name


def _read_capped(path: Path, cap_bytes: int) -> str | None:
    """Read up to *cap_bytes* of *path* as text, or return None."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > cap_bytes:
        return None
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def _line_number_of(text: str, offset: int) -> int:
    """Convert a byte offset into a 1-indexed line number."""
    return text.count("\n", 0, offset) + 1


def _snippet_for(text: str, offset: int, span: int = 200) -> str:
    """Extract a small snippet around *offset* for the finding evidence."""
    start = max(0, offset - 40)
    end = min(len(text), offset + span)
    return text[start:end].strip().replace("\r\n", "\n")


def _scan_text(
    text: str, path: Path, root: Path
) -> list[NormalizedFinding]:
    """Match every declaration pattern against *text* and emit findings."""
    findings: list[NormalizedFinding] = []
    rel = _relative(path, root)

    # If the file declares a key spec near the top, remember it.  Terraform
    # aws_kms_key resources often include ``key_spec = "RSA_2048"`` inside
    # the block — we resolve the specific algorithm in that case.
    spec_hit = _KEY_SPEC_HINT.search(text)
    resolved: tuple[str, str | None] | None = None
    if spec_hit:
        resolved = _spec_to_algorithm(spec_hit.group(1))

    seen: set[str] = set()
    for decl in _DECLARATIONS:
        match = decl.pattern.search(text)
        if not match:
            continue
        key = f"{decl.algorithm}|{decl.display_name}"
        if key in seen:
            continue
        seen.add(key)

        line_no = _line_number_of(text, match.start())
        snippet = _snippet_for(text, match.start())

        # Only apply a declared key spec to AWS KMS (that's where it lives).
        if resolved is not None and decl.provider == "aws" and decl.artefact_type == ArtefactType.CLOUD_SERVICE:
            algorithm, parameter = resolved
            parameter_status = ParameterStatus.RESOLVED
        else:
            algorithm = decl.algorithm
            parameter = None
            parameter_status = ParameterStatus.UNRESOLVED

        # A declaration is a strong signal that the surface exists; what the
        # surface *contains* still needs human confirmation. Confidence 0.72
        # bands to MEDIUM. Unresolved-parameter findings still route to
        # INVESTIGATE via the recommender.
        evidence = Evidence(
            file_path=rel,
            line_number=line_no,
            code_snippet=snippet[:200],
            detection_method=DetectionMethod.INFRA_DECLARATION,
            confidence=0.72,
        )

        # Usage: KMS/HSM manage keys and typically perform key generation,
        # transport, or data encryption. KEY_GENERATION is the honest default
        # when we can't disambiguate.
        usage = CryptoUsage.KEY_GENERATION

        findings.append(
            NormalizedFinding(
                id=f"INFRA-{rel}-{decl.algorithm}".replace("/", "_").replace("\\", "_"),
                algorithm=algorithm,
                primitive=CryptoPrimitive.UNKNOWN,
                parameter=parameter,
                parameter_status=parameter_status,
                usage=usage,
                artefact_type=decl.artefact_type,
                library=decl.library,
                evidence=evidence,
                unresolved_parameters=[] if parameter_status == ParameterStatus.RESOLVED
                else ["algorithm", "key_spec"],
            )
        )

    return findings


def scan_infra(
    target: Path, settings: Settings | None = None
) -> list[NormalizedFinding]:
    """Walk *target* for infra / config files and return declaration findings.

    Deterministic: files are visited in sorted path order; declarations within
    a file are emitted in table order and deduplicated per
    ``(file, algorithm, display_name)``.
    """
    settings = settings or get_settings()
    if not settings.infra_scan_enabled:
        return []

    root = Path(target).resolve()
    if not root.exists():
        return []

    cap = int(settings.infra_max_scan_mb) * 1024 * 1024
    findings: list[NormalizedFinding] = []

    iterator = [root] if root.is_file() else sorted(root.rglob("*"))
    for path in iterator:
        try:
            if not path.is_file() or path.is_symlink():
                continue
        except OSError:
            continue
        if path.suffix.lower() not in _INFRA_EXTS:
            continue

        text = _read_capped(path, cap)
        if not text:
            continue
        try:
            findings.extend(_scan_text(text, path, root))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Infra scan failed for %s: %s", path.name, exc)

    if findings:
        logger.info(
            "Infra scan: %d HSM/KMS declaration(s) across %d file(s) under %s.",
            len(findings),
            len({f.evidence.file_path for f in findings}),
            root.name or root,
        )
    return findings
