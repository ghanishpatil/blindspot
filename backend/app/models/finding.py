"""Finding models — the spine of the pipeline.

Every scanner, regardless of technique, must emit a :class:`NormalizedFinding`.
Downstream stages (CBOM builder, classifier, risk engine, recommender) consume
that normalized shape and never re-parse raw scanner output or re-read the
repository.

A finding must be able to answer:

* What was found?
* Where was it found?
* How was it detected?
* How certain are we?
* Which parameters were resolved, and which remain unknown?
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import Field, computed_field, field_validator

from app.models.asset import (
    ArtefactType,
    CipherMode,
    CryptoPrimitive,
    CryptoUsage,
    ParameterStatus,
    SecurityGoal,
)
from app.models.base import BlindspotModel
from app.models.recommendation import Recommendation
from app.models.risk import CurrentRisk, MoscaAssessment, QuantumRisk, RiskTier


class DetectionMethod(str, Enum):
    """How the artefact was detected. Drives the confidence band."""

    SEMGREP_API_PATTERN = "semgrep_api_pattern"
    """Direct call to a known cryptographic API. Highest confidence."""

    SEMGREP_AST_CONFIRMED = "semgrep_ast_confirmed"
    """Pattern confirmed against the syntax tree, not just text."""

    SEMGREP_STRING_MATCH = "semgrep_string_match"
    """Textual match only. Lower confidence; may be a comment or a name."""

    DEPENDENCY_MANIFEST = "dependency_manifest"
    """Declared dependency known to provide the primitive."""

    CONFIG_INFERENCE = "config_inference"
    """Inferred from configuration rather than observed in code."""

    TLS_PROBE = "tls_probe"
    """Observed live over the network from a TLS handshake / certificate."""

    BINARY_SIGNATURE = "binary_signature"
    """Fingerprint match against a compiled binary (constants, OIDs, strings).

    Heuristic by construction — never presented with the same certainty as an
    AST-confirmed source finding. Confidence is set at the low band so these
    findings automatically route to the manual-verification surface.
    """

    INFRA_DECLARATION = "infra_declaration"
    """Declared reference to an HSM / PKCS#11 module or cloud KMS in IaC /
    configuration / SDK code. Attests that a key-management surface exists —
    NOT what algorithms it actually contains. Findings are marked with an
    unresolved parameter so they route to INVESTIGATE.
    """

    STATIC_CERT_FILE = "static_cert_file"
    """A certificate parsed from a standalone file or inline PEM block.

    The file itself is the evidence — the algorithm, key size, and curve are
    read directly from the DER/PEM bytes with :mod:`cryptography.x509`. High
    confidence: no heuristic sits between the artefact and the finding.
    """

    STATIC_KEY_MATERIAL = "static_key_material"
    """Private- or public-key material parsed from a file or inline PEM block.

    Same evidence discipline as :attr:`STATIC_CERT_FILE`: the algorithm and
    parameter are read directly from the encoded key structure.
    """

    STATIC_KEYSTORE = "static_keystore"
    """A password-protected keystore file (PKCS#12 / .p12 / .pfx, or JKS).

    File existence proves the key-management surface is there, but the
    parameters inside are opaque without the password. Emitted with
    :attr:`ParameterStatus.UNRESOLVED` so it routes to INVESTIGATE, honestly
    reflecting what static observation can and cannot show.
    """

    PKCS11_ATTESTED = "pkcs11_attested"
    """A live PKCS#11 session attested this key exists on this HSM.

    Emitted by the R7 HSM scanner after opening a PKCS#11 module, reading
    ``CKA_KEY_TYPE`` / ``CKA_MODULUS_BITS`` / ``CKA_EC_PARAMS`` from real
    objects on the token. This is the strongest form of key evidence the
    tool produces short of a full cryptographic proof of possession: the
    HSM answered.
    """

    AWS_KMS_ATTESTED = "aws_kms_attested"
    """A live AWS KMS ``DescribeKey`` call attested this key's algorithm.

    Emitted by the R8 cloud-KMS scanner. AWS returns the key spec directly
    (``RSA_2048``, ``ECC_NIST_P256``, ``SYMMETRIC_DEFAULT``, ...), so no
    heuristic sits between the API response and the finding.
    """

    CONFIG_POLICY_DECLARED = "config_policy_declared"
    """A protocol / cipher / KEX / MAC / hostkey declared in a config file.

    Sources include ``nginx.conf`` (``ssl_protocols``, ``ssl_ciphers``),
    ``sshd_config`` (``Ciphers`` / ``KexAlgorithms`` / ``MACs`` /
    ``HostKeyAlgorithms``), ``httpd.conf`` (``SSLProtocol`` /
    ``SSLCipherSuite``), ``openssl.cnf`` (``MinProtocol`` / ``CipherString``),
    ``java.security`` (``jdk.tls.disabledAlgorithms``),
    ``postgresql.conf`` (``ssl_ciphers``), and .NET ``web.config``.

    Confidence sits at the medium band because a declaration is what the
    admin *asked for* — the running server may still override, ignore, or
    layer on top of it. Live probing (``TLS_PROBE``) is what proves what a
    server actually negotiates.
    """

    UNKNOWN = "unknown"


class ConfidenceLevel(str, Enum):
    """Human-readable confidence band for the UI."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Criticality(str, Enum):
    """Business criticality of the asset protected by this cryptography."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Evidence(BlindspotModel):
    """Proof of where and how a finding was detected.

    Without evidence a finding is an assertion. The dashboard shows the file,
    the line, and the actual source text so a reviewer can verify the claim.
    """

    file_path: str = Field(description="Repository-relative path to the source file.")
    line_number: int | None = Field(
        default=None, ge=1, description="1-indexed line where the artefact was detected."
    )
    end_line_number: int | None = Field(default=None, ge=1)
    code_snippet: str = Field(
        default="", description="The matched source text, e.g. 'RSA.generate(2048)'."
    )
    context_lines: list[str] = Field(
        default_factory=list,
        description="Optional surrounding lines for display context.",
    )
    detection_method: DetectionMethod = DetectionMethod.UNKNOWN
    confidence: float = Field(
        ge=0.0, le=1.0, description="Detection confidence in the range 0.0 - 1.0."
    )
    rule_id: str | None = Field(
        default=None, description="Identifier of the semgrep rule that matched."
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def confidence_level(self) -> ConfidenceLevel:
        """Banded confidence for display."""
        if self.confidence >= 0.85:
            return ConfidenceLevel.HIGH
        if self.confidence >= 0.6:
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.LOW


class Classification(BlindspotModel):
    """Classifier output: what kind of artefact this is and what it protects."""

    artefact_type: ArtefactType = ArtefactType.UNKNOWN
    security_goal: SecurityGoal = SecurityGoal.UNKNOWN
    data_lifetime_years: float = Field(
        ge=0,
        description="Mosca X: how long the protected data must remain secret.",
    )
    criticality: Criticality = Criticality.MEDIUM
    is_long_lived_trust_anchor: bool = Field(
        default=False,
        description=(
            "True for root CA, code signing, or firmware signing keys, where "
            "the lifetime of the anchored trust — not of a message — dominates."
        ),
    )
    lifetime_source: str = Field(
        default="policy_default",
        description="Where the lifetime came from: policy_default | usage_inferred | declared.",
    )
    rationale: str = Field(
        default="", description="Why the classifier reached this conclusion."
    )


class NormalizedFinding(BlindspotModel):
    """Canonical scanner output. The contract every discovery method satisfies.

    This is intentionally free of risk and recommendation data — discovery and
    analysis stay separate concerns.
    """

    id: str = Field(description="Stable identifier, e.g. 'CRYPTO-001'.")
    algorithm: str = Field(description="Detected algorithm, e.g. 'RSA'.")
    primitive: CryptoPrimitive = CryptoPrimitive.UNKNOWN
    parameter: str | None = Field(
        default=None,
        description="Key size or parameter set as a string, e.g. '2048'. None when unresolved.",
    )
    parameter_status: ParameterStatus = ParameterStatus.NOT_APPLICABLE
    mode: CipherMode | None = None
    curve: str | None = None
    usage: CryptoUsage = CryptoUsage.UNKNOWN
    artefact_type: ArtefactType = ArtefactType.UNKNOWN
    library: str | None = Field(
        default=None, description="Providing library, e.g. 'pycryptodome'."
    )
    evidence: Evidence
    unresolved_parameters: list[str] = Field(
        default_factory=list,
        description="Named parameters the scanner could not resolve.",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def file_path(self) -> str:
        """Convenience mirror of ``evidence.file_path`` for tables and queries."""
        return self.evidence.file_path

    @computed_field  # type: ignore[prop-decorator]
    @property
    def line_number(self) -> int | None:
        """Convenience mirror of ``evidence.line_number``."""
        return self.evidence.line_number

    @computed_field  # type: ignore[prop-decorator]
    @property
    def display_name(self) -> str:
        """Algorithm with its parameter when known, e.g. 'RSA-2048'."""
        if self.parameter:
            return f"{self.algorithm}-{self.parameter}"
        if self.curve:
            return f"{self.algorithm} ({self.curve})"
        return self.algorithm

    @field_validator("algorithm")
    @classmethod
    def _algorithm_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("algorithm must not be blank")
        return value


class Finding(NormalizedFinding):
    """A normalized finding enriched by classification, risk, and recommendation.

    This is what gets persisted to Firestore and returned by the API.
    Analysis fields are optional so a finding can be inspected part-way
    through the pipeline instead of only in its final form.
    """

    scan_id: str | None = None
    project_id: str | None = None

    classification: Classification | None = None
    current_risk: CurrentRisk | None = None
    quantum_risk: QuantumRisk | None = None
    mosca: MoscaAssessment | None = None
    risk_tier: RiskTier | None = None
    recommendation: Recommendation | None = None

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of when the finding was produced.",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_quantum_sensitive(self) -> bool:
        """True when a quantum computer would defeat this cryptography."""
        return bool(self.quantum_risk and self.quantum_risk.is_quantum_vulnerable)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_currently_weak(self) -> bool:
        """True when the cryptography is already broken today."""
        return bool(self.current_risk and self.current_risk.is_currently_weak)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_hndl_exposed(self) -> bool:
        """Harvest-Now-Decrypt-Later exposure.

        An attacker can record ciphertext today and decrypt it once a
        cryptographically relevant quantum computer exists. That is a genuine
        threat only when all three hold:

        1. the cryptography protects *confidentiality* — recording a signature
           or MAC to forge later gains nothing;
        2. it is *quantum-vulnerable* (Shor breaks it), so harvesting pays off;
        3. the data must stay secret *past* the quantum horizon — Mosca says
           migration is overdue — so data captured today is still sensitive
           when decryption becomes feasible.

        Derived purely from fields the pipeline already computes; it asserts
        nothing new about the finding.
        """
        if not (
            self.classification
            and self.classification.security_goal == SecurityGoal.CONFIDENTIALITY
        ):
            return False
        if not (self.quantum_risk and self.quantum_risk.is_quantum_vulnerable):
            return False
        return self.risk_tier == RiskTier.OVERDUE

    @computed_field  # type: ignore[prop-decorator]
    @property
    def needs_verification(self) -> bool:
        """True when a human should double-check this finding before acting.

        Either the detection confidence is low, or a parameter the risk model
        depends on could not be resolved. Surfacing this is a deliberate trust
        signal: the tool states what it is unsure about instead of presenting
        every finding with equal, unearned certainty.
        """
        if self.parameter_status == ParameterStatus.UNRESOLVED:
            return True
        return self.evidence.confidence_level == ConfidenceLevel.LOW

    def to_firestore_document(self) -> dict[str, Any]:
        """Flatten to the Firestore ``findings/{findingId}`` shape.

        Firestore holds queryable metadata, so nested analysis objects are kept
        but the frequently-filtered values are promoted to top level. ``evidence``
        is flattened to the code snippet, matching the specification's schema.
        """
        classification = self.classification
        recommendation = self.recommendation

        return {
            "scanId": self.scan_id,
            "projectId": self.project_id,
            "algorithm": self.algorithm,
            "displayName": self.display_name,
            "primitive": self.primitive.value,
            "parameter": self.parameter,
            "parameterStatus": self.parameter_status.value,
            "mode": self.mode.value if self.mode else None,
            "curve": self.curve,
            "usage": self.usage.value,
            "artefactType": self.artefact_type.value,
            "filePath": self.evidence.file_path,
            "lineNumber": self.evidence.line_number,
            "evidence": self.evidence.code_snippet,
            "evidenceDetail": self.evidence.serialise(),
            "detectionMethod": self.evidence.detection_method.value,
            "confidence": self.evidence.confidence,
            "unresolvedParameters": self.unresolved_parameters,
            "dataLifetimeYears": (
                classification.data_lifetime_years if classification else None
            ),
            "criticality": classification.criticality.value if classification else None,
            "classification": classification.serialise() if classification else None,
            "currentRisk": self.current_risk.serialise() if self.current_risk else None,
            "quantumRisk": self.quantum_risk.serialise() if self.quantum_risk else None,
            "mosca": self.mosca.serialise() if self.mosca else None,
            "riskTier": self.risk_tier.value if self.risk_tier else None,
            "recommendation": recommendation.serialise() if recommendation else None,
            "rationale": recommendation.rationale if recommendation else None,
            "isQuantumSensitive": self.is_quantum_sensitive,
            "isCurrentlyWeak": self.is_currently_weak,
            "isHndlExposed": self.is_hndl_exposed,
            "needsVerification": self.needs_verification,
            "confidenceLevel": self.evidence.confidence_level.value,
            "createdAt": self.created_at.isoformat(),
        }
