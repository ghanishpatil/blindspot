"""HSM / KMS declaration scanner tests.

The scanner discovers *declared* references in real artefacts (Terraform,
CloudFormation, Kubernetes manifests, PKCS#11 configs, SDK code). Tests
verify each pattern family, the algorithm-spec resolution, and the honesty
guardrails: every declaration lands under HARDWARE_MODULE or CLOUD_SERVICE
and — unless a key spec is explicit — is marked UNRESOLVED so it routes to
INVESTIGATE.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.models.asset import ArtefactType, ParameterStatus
from app.models.finding import DetectionMethod
from app.scanner.infra import scan_infra


# ── AWS KMS / CloudHSM (Terraform + CloudFormation) ────────────────────────

def test_terraform_aws_kms_key_detected(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text('''\
resource "aws_kms_key" "primary" {
  description = "primary encryption key"
}
''')
    findings = scan_infra(tmp_path)
    aws = [f for f in findings if f.algorithm == "AWS-KMS"]
    assert aws
    assert aws[0].artefact_type == ArtefactType.CLOUD_SERVICE
    assert aws[0].parameter_status == ParameterStatus.UNRESOLVED
    assert aws[0].evidence.detection_method == DetectionMethod.INFRA_DECLARATION


def test_terraform_aws_kms_key_spec_resolves_algorithm(tmp_path: Path) -> None:
    """A key_spec next to the resource resolves the algorithm honestly."""
    (tmp_path / "kms.tf").write_text('''\
resource "aws_kms_key" "signer" {
  key_spec = "RSA_2048"
}
''')
    findings = scan_infra(tmp_path)
    kms = [f for f in findings if f.algorithm != "AWS-KMS"]
    # With a resolved spec the algorithm is RSA-2048 rather than the generic label.
    assert any(f.algorithm == "RSA" and f.parameter == "2048" for f in kms)


def test_cloudformation_aws_kms_detected(tmp_path: Path) -> None:
    (tmp_path / "stack.yaml").write_text('''\
Resources:
  Key:
    Type: AWS::KMS::Key
    Properties:
      Description: cloud-side kms
''')
    findings = scan_infra(tmp_path)
    assert any(f.algorithm == "AWS-KMS" for f in findings)


def test_cloudhsm_detected(tmp_path: Path) -> None:
    (tmp_path / "hsm.tf").write_text('''\
resource "aws_cloudhsm_v2_cluster" "primary" {
  hsm_type   = "hsm1.medium"
  subnet_ids = ["subnet-xxx"]
}
''')
    findings = scan_infra(tmp_path)
    hsm = [f for f in findings if f.algorithm == "AWS-CloudHSM"]
    assert hsm and hsm[0].artefact_type == ArtefactType.HARDWARE_MODULE


# ── GCP + Azure ────────────────────────────────────────────────────────────

def test_gcp_kms_detected(tmp_path: Path) -> None:
    (tmp_path / "gcp.tf").write_text('resource "google_kms_crypto_key" "k" { name = "x" }\n')
    findings = scan_infra(tmp_path)
    assert any(f.algorithm == "GCP-KMS" for f in findings)


def test_azure_keyvault_detected(tmp_path: Path) -> None:
    (tmp_path / "az.tf").write_text('resource "azurerm_key_vault" "v" { name = "vault" }\n')
    findings = scan_infra(tmp_path)
    assert any(f.algorithm == "Azure-KeyVault" for f in findings)


# ── Kubernetes secret-management ────────────────────────────────────────────

def test_kubernetes_sealed_secret_detected(tmp_path: Path) -> None:
    (tmp_path / "secret.yaml").write_text('''\
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: example
''')
    findings = scan_infra(tmp_path)
    assert any(f.algorithm == "K8s-KMS-Backed-Secret" for f in findings)


# ── PKCS#11 ─────────────────────────────────────────────────────────────────

def test_pkcs11_softhsm_detected(tmp_path: Path) -> None:
    (tmp_path / "hsm.conf").write_text("PKCS11_MODULE_PATH=/usr/lib/softhsm/libsofthsm2.so\n")
    findings = scan_infra(tmp_path)
    algos = {f.algorithm for f in findings}
    assert "PKCS11-Module" in algos or "PKCS11-SoftHSM" in algos
    types = {f.artefact_type for f in findings}
    assert ArtefactType.HARDWARE_MODULE in types


def test_pkcs11_luna_detected(tmp_path: Path) -> None:
    (tmp_path / "note.py").write_text('# hsm library path: libcs_pkcs11_R2.so (SafeNet)\n')
    findings = scan_infra(tmp_path)
    assert any(f.algorithm == "PKCS11-Luna" for f in findings)


def test_yubihsm_detected(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text('import ctypes\nlib=ctypes.CDLL("libykcs11.so")\n')
    findings = scan_infra(tmp_path)
    assert any(f.algorithm == "PKCS11-YubiHSM" for f in findings)


# ── SDK client instantiation in real code ───────────────────────────────────

def test_boto3_kms_client_detected(tmp_path: Path) -> None:
    (tmp_path / "svc.py").write_text('import boto3\nkms = boto3.client("kms")\n')
    findings = scan_infra(tmp_path)
    assert any(
        f.algorithm == "AWS-KMS" and "boto3" in (f.evidence.code_snippet or "")
        for f in findings
    )


def test_gcp_kms_sdk_client_detected(tmp_path: Path) -> None:
    (tmp_path / "svc.py").write_text('from google.cloud import kms\nc = kms.KeyManagementServiceClient()\n')
    findings = scan_infra(tmp_path)
    assert any(f.algorithm == "GCP-KMS" for f in findings)


# ── Honesty guardrails ──────────────────────────────────────────────────────

def test_findings_are_medium_confidence(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_kms_key" "k" { }\n')
    findings = scan_infra(tmp_path)
    assert findings
    for f in findings:
        assert f.evidence.detection_method == DetectionMethod.INFRA_DECLARATION
        assert f.evidence.confidence_level.value == "medium"


def test_declarations_default_unresolved_to_route_to_investigate(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_kms_key" "k" { }\n')
    findings = scan_infra(tmp_path)
    kms = next(f for f in findings if f.algorithm == "AWS-KMS")
    assert kms.parameter_status == ParameterStatus.UNRESOLVED
    assert "algorithm" in kms.unresolved_parameters


def test_multiple_declarations_in_one_file_dedup_per_kind(tmp_path: Path) -> None:
    (tmp_path / "big.tf").write_text('''\
resource "aws_kms_key" "one" {}
resource "aws_kms_key" "two" {}
resource "aws_cloudhsm_v2_cluster" "c" {}
''')
    findings = scan_infra(tmp_path)
    # Two aws_kms_key resources should dedup to one "AWS KMS key (Terraform)"
    # per file, but CloudHSM is a separate declaration.
    algos = [f.algorithm for f in findings]
    assert algos.count("AWS-KMS") == 1
    assert algos.count("AWS-CloudHSM") == 1


def test_disabled_by_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.config import get_settings

    monkeypatch.setenv("INFRA_SCAN_ENABLED", "false")
    get_settings.cache_clear()

    (tmp_path / "main.tf").write_text('resource "aws_kms_key" "k" { }\n')
    assert scan_infra(tmp_path) == []
