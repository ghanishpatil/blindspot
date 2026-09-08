"""Cryptographic asset vocabulary.

The enumerations here are deliberately aligned with the CycloneDX
``cryptoProperties`` schema so that the CBOM builder (Phase 6) can map a
normalized finding onto a CycloneDX cryptographic asset without inventing new
values at that stage.

Domain-level concepts that CycloneDX does not model — such as *usage* and the
coarser *artefact type* used by the dashboard — are defined here too, kept
separate from the CycloneDX-aligned enums.
"""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from app.models.base import BlindspotModel


class AssetType(str, Enum):
    """CycloneDX ``cryptoProperties.assetType``."""

    ALGORITHM = "algorithm"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"
    RELATED_CRYPTO_MATERIAL = "related-crypto-material"


class CryptoPrimitive(str, Enum):
    """CycloneDX ``algorithmProperties.primitive``."""

    DRBG = "drbg"
    MAC = "mac"
    BLOCK_CIPHER = "block-cipher"
    STREAM_CIPHER = "stream-cipher"
    SIGNATURE = "signature"
    HASH = "hash"
    PKE = "pke"
    XOF = "xof"
    KDF = "kdf"
    KEY_AGREE = "key-agree"
    KEM = "kem"
    AE = "ae"
    COMBINER = "combiner"
    OTHER = "other"
    UNKNOWN = "unknown"


class CryptoFunction(str, Enum):
    """CycloneDX ``algorithmProperties.cryptoFunctions``."""

    GENERATE = "generate"
    KEYGEN = "keygen"
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    DIGEST = "digest"
    TAG = "tag"
    KEYDERIVE = "keyderive"
    SIGN = "sign"
    VERIFY = "verify"
    ENCAPSULATE = "encapsulate"
    DECAPSULATE = "decapsulate"
    OTHER = "other"
    UNKNOWN = "unknown"


class CipherMode(str, Enum):
    """CycloneDX ``algorithmProperties.mode``."""

    CBC = "cbc"
    ECB = "ecb"
    CCM = "ccm"
    GCM = "gcm"
    CFB = "cfb"
    OFB = "ofb"
    CTR = "ctr"
    OTHER = "other"
    UNKNOWN = "unknown"


class Padding(str, Enum):
    """CycloneDX ``algorithmProperties.padding``."""

    PKCS5 = "pkcs5"
    PKCS1V15 = "pkcs1v15"
    PKCS7 = "pkcs7"
    PKCS12 = "pkcs12"
    OAEP = "oaep"
    RAW = "raw"
    OTHER = "other"
    UNKNOWN = "unknown"


class ArtefactType(str, Enum):
    """Coarse, judge-readable artefact category shown in the dashboard.

    Deliberately simpler than :class:`CryptoPrimitive`; this is the value the
    findings table displays.
    """

    KEY_EXCHANGE = "key-exchange"
    SIGNATURE = "signature"
    ENCRYPTION = "encryption"
    HASH = "hash"
    MAC = "mac"
    KEY_DERIVATION = "key-derivation"
    RANDOM = "random"
    CERTIFICATE = "certificate"
    UNKNOWN = "unknown"


class CryptoUsage(str, Enum):
    """How the cryptography is actually used in the scanned code.

    Usage — not algorithm name alone — drives both classification and the
    recommendation engine. RSA used for key transport and RSA used for
    signatures have different migration targets.
    """

    KEY_ESTABLISHMENT = "key_establishment"
    KEY_TRANSPORT = "key_transport"
    KEY_GENERATION = "key_generation"
    DIGITAL_SIGNATURE = "digital_signature"
    SESSION_SIGNATURE = "session_signature"
    CERTIFICATE_SIGNING = "certificate_signing"
    CODE_SIGNING = "code_signing"
    DATA_ENCRYPTION = "data_encryption"
    DATA_AT_REST_ENCRYPTION = "data_at_rest_encryption"
    TRANSPORT_ENCRYPTION = "transport_encryption"
    INTEGRITY_HASH = "integrity_hash"
    PASSWORD_HASHING = "password_hashing"
    MESSAGE_AUTHENTICATION = "message_authentication"
    KEY_DERIVATION = "key_derivation"
    RANDOM_GENERATION = "random_generation"
    UNKNOWN = "unknown"


class SecurityGoal(str, Enum):
    """Primary security property the cryptography provides.

    The distinction matters: data lifetime dominates risk for
    confidentiality-oriented cryptography (harvest-now-decrypt-later), whereas
    authenticity-oriented cryptography is judged on the lifetime of the trust
    it anchors.
    """

    CONFIDENTIALITY = "confidentiality"
    AUTHENTICITY = "authenticity"
    INTEGRITY = "integrity"
    UNKNOWN = "unknown"


class ParameterStatus(str, Enum):
    """Whether the scanner could resolve the algorithm parameter.

    ``UNRESOLVED`` is a first-class state, not an error. Case 5 of the demo
    exists specifically to show honest uncertainty rather than a guess.
    """

    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"
    NOT_APPLICABLE = "not_applicable"


class CryptographicAsset(BlindspotModel):
    """CycloneDX-shaped view of a detected cryptographic asset.

    Produced by the CBOM builder in Phase 6 from a normalized finding. Held
    here so the vocabulary lives in one place.
    """

    bom_ref: str = Field(description="Stable CycloneDX bom-ref for this asset.")
    name: str = Field(description="Human-readable asset name, e.g. 'RSA-2048'.")
    asset_type: AssetType = AssetType.ALGORITHM
    primitive: CryptoPrimitive = CryptoPrimitive.UNKNOWN
    parameter_set_identifier: str | None = Field(
        default=None,
        description="Key size or parameter set, e.g. '2048'. None when unresolved.",
    )
    crypto_functions: list[CryptoFunction] = Field(default_factory=list)
    mode: CipherMode | None = None
    padding: Padding | None = None
    curve: str | None = Field(
        default=None, description="Elliptic curve name where applicable."
    )
    classical_security_level: int | None = None
    nist_quantum_security_level: int | None = Field(
        default=None,
        ge=0,
        le=6,
        description="NIST PQC security category; 0 means no quantum security.",
    )
    oid: str | None = None
