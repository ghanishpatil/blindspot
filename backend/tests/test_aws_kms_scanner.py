"""AWS KMS attestation scanner tests -- R8.

Uses ``moto`` to stand up an in-process AWS KMS mock and exercise the
scanner against real ``boto3`` calls -- no service dependencies. Every
test creates only the keys it inspects, so the mocked account starts
empty and each test's assertions are precise.

Coverage:

1. **Gating.** Opt-in via ``aws_kms_scan_enabled``; returns empty when
   off, when boto3 is absent, or when credentials cannot be resolved.
2. **KeySpec resolution.** Every AWS-documented KeySpec (RSA_2048,
   RSA_3072, RSA_4096, ECC_NIST_P256/P384/P521, ECC_SECG_P256K1,
   SYMMETRIC_DEFAULT, HMAC_*) resolves to the expected algorithm /
   primitive / parameter.
3. **Findings shape.** Detection method is ``AWS_KMS_ATTESTED``, artefact
   type is ``CLOUD_SERVICE``, confidence lands in the HIGH band, ARN
   appears in the evidence file_path.
"""

from __future__ import annotations

from types import SimpleNamespace

import boto3
import pytest
from moto import mock_aws

from app.config import get_settings
from app.models.asset import ArtefactType, CryptoPrimitive, ParameterStatus
from app.models.finding import ConfidenceLevel, DetectionMethod
from app.scanner import aws_kms as aws_kms_module
from app.scanner.aws_kms import _resolve_key, scan_aws_kms


AWS_REGION = "us-east-1"


# ---------------------------------------------------------------------------
# Small fixture -- moto-backed KMS client
# ---------------------------------------------------------------------------

@pytest.fixture
def moto_kms(monkeypatch: pytest.MonkeyPatch):
    """Start a mocked AWS environment and yield a live KMS boto3 client."""
    # Feed boto3 dummy creds so tests do not require ~/.aws/credentials.
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", AWS_REGION)

    with mock_aws():
        client = boto3.client("kms", region_name=AWS_REGION)
        yield client


# ---------------------------------------------------------------------------
# Unit -- _resolve_key on hand-built KeyMetadata dicts
# ---------------------------------------------------------------------------

def test_resolve_symmetric_default_returns_aes_256() -> None:
    metadata = {
        "KeyId": "abc-123",
        "Arn": "arn:aws:kms:us-east-1:1234:key/abc-123",
        "KeySpec": "SYMMETRIC_DEFAULT",
        "KeyUsage": "ENCRYPT_DECRYPT",
        "KeyState": "Enabled",
        "KeyManager": "CUSTOMER",
    }
    finding = _resolve_key(metadata, region=AWS_REGION)
    assert finding is not None
    assert finding.algorithm == "AES"
    assert finding.parameter == "256"
    assert finding.primitive == CryptoPrimitive.BLOCK_CIPHER
    assert finding.artefact_type == ArtefactType.CLOUD_SERVICE
    assert finding.evidence.detection_method == DetectionMethod.AWS_KMS_ATTESTED
    assert finding.evidence.confidence_level == ConfidenceLevel.HIGH


@pytest.mark.parametrize("spec,algo,param", [
    ("RSA_2048", "RSA", "2048"),
    ("RSA_3072", "RSA", "3072"),
    ("RSA_4096", "RSA", "4096"),
    ("ECC_NIST_P256", "ECDSA", "P-256"),
    ("ECC_NIST_P384", "ECDSA", "P-384"),
    ("ECC_NIST_P521", "ECDSA", "P-521"),
    ("ECC_SECG_P256K1", "ECDSA", "secp256k1"),
])
def test_resolve_asymmetric_key_specs(spec: str, algo: str, param: str) -> None:
    metadata = {
        "KeyId": f"kms-{spec}",
        "KeySpec": spec,
        "KeyUsage": "SIGN_VERIFY" if algo == "ECDSA" else "ENCRYPT_DECRYPT",
        "KeyState": "Enabled",
        "KeyManager": "CUSTOMER",
    }
    finding = _resolve_key(metadata, region=AWS_REGION)
    assert finding is not None
    assert finding.algorithm == algo
    assert finding.parameter == param


@pytest.mark.parametrize("spec,hash_algo", [
    ("HMAC_256", "SHA-256"),
    ("HMAC_384", "SHA-384"),
    ("HMAC_512", "SHA-512"),
])
def test_resolve_hmac_specs(spec: str, hash_algo: str) -> None:
    metadata = {
        "KeyId": f"hmac-{spec}",
        "KeySpec": spec,
        "KeyUsage": "GENERATE_VERIFY_MAC",
        "KeyState": "Enabled",
    }
    finding = _resolve_key(metadata, region=AWS_REGION)
    assert finding is not None
    # HMAC keys surface as the underlying hash algorithm (which is what
    # actually determines HMAC strength).
    assert finding.algorithm == hash_algo
    assert finding.primitive == CryptoPrimitive.MAC


def test_resolve_unknown_key_spec_surfaces_verbatim() -> None:
    """An AWS spec we do not yet know about must not be dropped. It
    surfaces with ``KMS-<spec>`` and parameter_status=UNRESOLVED so the
    recommender routes it to INVESTIGATE."""
    metadata = {
        "KeyId": "future-1",
        "KeySpec": "FUTURE_PQC_KEM",
        "KeyUsage": "ENCRYPT_DECRYPT",
        "KeyState": "Enabled",
    }
    finding = _resolve_key(metadata, region=AWS_REGION)
    assert finding is not None
    assert finding.algorithm == "KMS-FUTURE_PQC_KEM"
    assert finding.parameter_status == ParameterStatus.UNRESOLVED


def test_resolve_returns_none_without_key_id() -> None:
    assert _resolve_key({"KeySpec": "RSA_2048"}, region=AWS_REGION) is None


def test_evidence_file_path_is_the_arn() -> None:
    metadata = {
        "KeyId": "abc",
        "Arn": "arn:aws:kms:us-west-2:9999:key/abc",
        "KeySpec": "RSA_2048",
        "KeyUsage": "SIGN_VERIFY",
        "KeyState": "Enabled",
    }
    finding = _resolve_key(metadata, region="us-west-2")
    assert finding is not None
    assert finding.evidence.file_path.startswith("arn:aws:kms:us-west-2:")


# ---------------------------------------------------------------------------
# Top-level scan_aws_kms -- gating + moto-driven live path
# ---------------------------------------------------------------------------

def test_scan_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AWS_KMS_SCAN_ENABLED", raising=False)
    get_settings.cache_clear()
    assert scan_aws_kms() == []


def test_scan_returns_empty_when_boto3_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_KMS_SCAN_ENABLED", "true")
    get_settings.cache_clear()
    monkeypatch.setattr(aws_kms_module, "_boto3", None)
    # No injected factory -> falls into the boto3 branch, sees None, returns [].
    assert scan_aws_kms() == []


def test_scan_finds_kms_keys(monkeypatch: pytest.MonkeyPatch, moto_kms) -> None:
    """End-to-end happy path: create a mix of AWS KMS keys under moto,
    run the scanner with an injected client, and assert every key surfaces
    as an attested finding."""
    monkeypatch.setenv("AWS_KMS_SCAN_ENABLED", "true")
    get_settings.cache_clear()

    # Create three keys with distinct specs. moto assigns the KeyId and
    # returns the full metadata; we only care that DescribeKey works.
    moto_kms.create_key(KeySpec="SYMMETRIC_DEFAULT", KeyUsage="ENCRYPT_DECRYPT",
                        Description="at-rest")
    moto_kms.create_key(KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY",
                        Description="code-sign")
    moto_kms.create_key(KeySpec="ECC_NIST_P256", KeyUsage="SIGN_VERIFY",
                        Description="jwt-sign")

    findings = scan_aws_kms(client_factory=lambda: moto_kms)

    algorithms = sorted(f.algorithm for f in findings)
    assert "AES" in algorithms
    assert "RSA" in algorithms
    assert "ECDSA" in algorithms

    # Every finding must land as AWS_KMS_ATTESTED / CLOUD_SERVICE at HIGH.
    for f in findings:
        assert f.evidence.detection_method == DetectionMethod.AWS_KMS_ATTESTED
        assert f.artefact_type == ArtefactType.CLOUD_SERVICE
        assert f.evidence.confidence_level == ConfidenceLevel.HIGH
        assert f.library == "aws-kms"


def test_scan_respects_max_keys_cap(monkeypatch: pytest.MonkeyPatch, moto_kms) -> None:
    """`aws_kms_max_keys` caps how many keys we describe, so a huge AWS
    account can never make a scan run for a very long time or emit a
    massive finding set unbounded."""
    monkeypatch.setenv("AWS_KMS_SCAN_ENABLED", "true")
    monkeypatch.setenv("AWS_KMS_MAX_KEYS", "2")
    get_settings.cache_clear()

    # Create five keys; only two should surface.
    for _ in range(5):
        moto_kms.create_key(KeySpec="SYMMETRIC_DEFAULT", KeyUsage="ENCRYPT_DECRYPT")

    findings = scan_aws_kms(client_factory=lambda: moto_kms)
    assert len(findings) == 2


def test_scan_survives_describe_error(
    monkeypatch: pytest.MonkeyPatch, moto_kms
) -> None:
    """A single DescribeKey failure must not abort the whole scan; other
    keys must still be reported."""
    monkeypatch.setenv("AWS_KMS_SCAN_ENABLED", "true")
    get_settings.cache_clear()

    moto_kms.create_key(KeySpec="SYMMETRIC_DEFAULT", KeyUsage="ENCRYPT_DECRYPT")
    moto_kms.create_key(KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY")

    real_describe = moto_kms.describe_key

    def flaky_describe(**kwargs):
        # Fail describe for the first key we hit, succeed for the rest.
        if flaky_describe._first:  # type: ignore[attr-defined]
            flaky_describe._first = False  # type: ignore[attr-defined]
            raise RuntimeError("simulated AWS transient error")
        return real_describe(**kwargs)

    flaky_describe._first = True  # type: ignore[attr-defined]

    # Wrap the client so ONLY describe_key is patched -- list_keys /
    # get_paginator stay real.
    from botocore.exceptions import ClientError
    class _Wrapper:
        def __init__(self, real):
            self._real = real
            self.meta = real.meta

        def get_paginator(self, name):
            return self._real.get_paginator(name)

        def describe_key(self, **kwargs):
            try:
                return flaky_describe(**kwargs)
            except RuntimeError as exc:
                # Convert to a ClientError-shaped exception so the scanner's
                # existing except path catches it.
                raise ClientError(
                    {"Error": {"Code": "InternalFailure", "Message": str(exc)}},
                    "DescribeKey",
                )

    findings = scan_aws_kms(client_factory=lambda: _Wrapper(moto_kms))
    # One key succeeded, one failed; scanner surfaces the survivor.
    assert len(findings) == 1


def test_client_build_failure_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """When the injected client_factory itself raises, we log and return
    empty rather than propagate the error out of the scanner."""
    monkeypatch.setenv("AWS_KMS_SCAN_ENABLED", "true")
    get_settings.cache_clear()

    def broken_factory():
        raise RuntimeError("region typo, config broken, etc.")

    assert scan_aws_kms(client_factory=broken_factory) == []


# ---------------------------------------------------------------------------
# Rotation configuration -- PS Req 2 AC 4
#
# The PS wording is "record the key algorithm, key size, AND rotation
# configuration". These tests protect that closure so the boolean flag
# stays on every symmetric customer-managed finding, and stays absent
# (honest n/a) on everything else. See _rotation_supported for the exact
# eligibility rule.
# ---------------------------------------------------------------------------

def test_rotation_snippet_says_enabled_when_key_rotates(moto_kms) -> None:
    """A customer-managed symmetric key with rotation ON must surface
    'rotation=enabled' in the evidence snippet."""
    key = moto_kms.create_key(KeySpec="SYMMETRIC_DEFAULT", KeyUsage="ENCRYPT_DECRYPT")
    key_id = key["KeyMetadata"]["KeyId"]
    moto_kms.enable_key_rotation(KeyId=key_id)

    metadata = moto_kms.describe_key(KeyId=key_id)["KeyMetadata"]
    from app.scanner.aws_kms import _read_rotation_status
    rotation = _read_rotation_status(moto_kms, metadata)
    assert rotation is True

    finding = _resolve_key(metadata, region=AWS_REGION, rotation_enabled=rotation)
    assert finding is not None
    assert "rotation=enabled" in finding.evidence.code_snippet


def test_rotation_snippet_says_disabled_when_key_does_not_rotate(moto_kms) -> None:
    """A customer-managed symmetric key with rotation OFF must surface
    'rotation=disabled'. moto keys start with rotation disabled by
    default, so no extra setup is needed."""
    key = moto_kms.create_key(KeySpec="SYMMETRIC_DEFAULT", KeyUsage="ENCRYPT_DECRYPT")
    key_id = key["KeyMetadata"]["KeyId"]

    metadata = moto_kms.describe_key(KeyId=key_id)["KeyMetadata"]
    from app.scanner.aws_kms import _read_rotation_status
    rotation = _read_rotation_status(moto_kms, metadata)
    assert rotation is False

    finding = _resolve_key(metadata, region=AWS_REGION, rotation_enabled=rotation)
    assert finding is not None
    assert "rotation=disabled" in finding.evidence.code_snippet


def test_rotation_snippet_says_na_for_asymmetric_keys(moto_kms) -> None:
    """Asymmetric keys cannot rotate. The scanner must NOT call
    GetKeyRotationStatus (moto would refuse it anyway), and the snippet
    must record 'rotation=n/a' honestly."""
    from app.scanner.aws_kms import _read_rotation_status, _rotation_supported

    key = moto_kms.create_key(KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY")
    metadata = moto_kms.describe_key(KeyId=key["KeyMetadata"]["KeyId"])["KeyMetadata"]

    # Guard: the eligibility helper must classify this as unsupported.
    assert _rotation_supported(metadata) is False

    # And the read helper must therefore return None without touching AWS.
    called = {"count": 0}

    class _CountingClient:
        def get_key_rotation_status(self, **kwargs):  # noqa: ARG002
            called["count"] += 1
            raise AssertionError("must not call GetKeyRotationStatus on asymmetric key")

    assert _read_rotation_status(_CountingClient(), metadata) is None
    assert called["count"] == 0

    finding = _resolve_key(metadata, region=AWS_REGION, rotation_enabled=None)
    assert finding is not None
    assert "rotation=n/a" in finding.evidence.code_snippet


def test_rotation_snippet_says_na_for_aws_managed_key() -> None:
    """AWS-managed keys are rotated on a schedule the customer does not
    control -- the scanner must skip the call and record 'n/a'."""
    from app.scanner.aws_kms import _read_rotation_status, _rotation_supported

    metadata = {
        "KeyId": "aws-managed-1",
        "KeySpec": "SYMMETRIC_DEFAULT",
        "KeyUsage": "ENCRYPT_DECRYPT",
        "KeyState": "Enabled",
        "KeyManager": "AWS",   # <-- the discriminator
        "Origin": "AWS_KMS",
    }
    assert _rotation_supported(metadata) is False

    class _RaisingClient:
        def get_key_rotation_status(self, **kwargs):  # noqa: ARG002
            raise AssertionError("must not call GetKeyRotationStatus on AWS-managed key")

    assert _read_rotation_status(_RaisingClient(), metadata) is None

    finding = _resolve_key(metadata, region=AWS_REGION, rotation_enabled=None)
    assert finding is not None
    assert "rotation=n/a" in finding.evidence.code_snippet


def test_rotation_snippet_says_na_for_external_origin() -> None:
    """External-origin keys ship customer-supplied material that AWS
    cannot rotate. Guard behaves the same as AWS-managed."""
    from app.scanner.aws_kms import _rotation_supported

    metadata = {
        "KeyId": "external-1",
        "KeySpec": "SYMMETRIC_DEFAULT",
        "KeyManager": "CUSTOMER",
        "Origin": "EXTERNAL",   # <-- the discriminator
    }
    assert _rotation_supported(metadata) is False


def test_rotation_read_swallows_client_error(moto_kms) -> None:
    """A GetKeyRotationStatus failure must be swallowed and folded into
    None -- NEVER propagated as an exception. Fabricating False would
    lie about the rotation state; None is the honest 'unknown'."""
    from botocore.exceptions import ClientError

    from app.scanner.aws_kms import _read_rotation_status

    key = moto_kms.create_key(KeySpec="SYMMETRIC_DEFAULT", KeyUsage="ENCRYPT_DECRYPT")
    metadata = moto_kms.describe_key(KeyId=key["KeyMetadata"]["KeyId"])["KeyMetadata"]

    class _FailingClient:
        def get_key_rotation_status(self, **kwargs):  # noqa: ARG002
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "nope"}},
                "GetKeyRotationStatus",
            )

    assert _read_rotation_status(_FailingClient(), metadata) is None


def test_scan_records_rotation_state_end_to_end(
    monkeypatch: pytest.MonkeyPatch, moto_kms
) -> None:
    """Full-pipeline smoke: create two symmetric CMKs (one with rotation
    enabled, one disabled) and assert the resulting findings carry the
    matching rotation strings in their evidence."""
    monkeypatch.setenv("AWS_KMS_SCAN_ENABLED", "true")
    get_settings.cache_clear()

    on = moto_kms.create_key(KeySpec="SYMMETRIC_DEFAULT", KeyUsage="ENCRYPT_DECRYPT",
                              Description="rotates")
    off = moto_kms.create_key(KeySpec="SYMMETRIC_DEFAULT", KeyUsage="ENCRYPT_DECRYPT",
                               Description="does-not-rotate")
    moto_kms.enable_key_rotation(KeyId=on["KeyMetadata"]["KeyId"])

    findings = scan_aws_kms(client_factory=lambda: moto_kms)
    snippets = [f.evidence.code_snippet for f in findings]

    # Exactly one 'enabled' and one 'disabled' among the two symmetric
    # keys. Anything else means the eligibility guard or the API call is
    # broken.
    assert sum("rotation=enabled" in s for s in snippets) == 1
    assert sum("rotation=disabled" in s for s in snippets) == 1
    # And no fabricated n/a for symmetric CMKs.
    assert sum("rotation=n/a" in s for s in snippets) == 0
