"""CBOM builder and validator tests.

These run the real pipeline: scan → normalize → CBOM → validate.
No mocks. If the CBOM breaks, these tests catch it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.cbom.builder import build_cbom, build_cbom_json
from app.cbom.validator import validate_cbom
from app.evidence.extractor import normalize
from app.models.finding import NormalizedFinding
from app.scanner.dependency_parser import parse_dependencies
from app.scanner.semgrep import run_semgrep

DEMO_REPO = Path(__file__).resolve().parent.parent.parent / "demo-repo"

pytestmark = pytest.mark.skipif(
    not DEMO_REPO.is_dir(),
    reason="demo-repo not present",
)


@pytest.fixture(scope="module")
def source_findings() -> list[NormalizedFinding]:
    matches = run_semgrep(DEMO_REPO)
    deps = parse_dependencies(DEMO_REPO)
    all_findings = normalize(matches, deps, DEMO_REPO)
    return [
        f for f in all_findings
        if f.evidence.detection_method.value != "dependency_manifest"
    ]


@pytest.fixture(scope="module")
def cbom_document(source_findings: list[NormalizedFinding]) -> dict:
    return build_cbom(source_findings, project_name="Test CBOM")


@pytest.fixture(scope="module")
def cbom_json_str(source_findings: list[NormalizedFinding]) -> str:
    return build_cbom_json(source_findings, project_name="Test CBOM")


# ── Structure ────────────────────────────────────────────────────────────

def test_cbom_is_cyclonedx_1_6(cbom_document: dict) -> None:
    assert cbom_document["bomFormat"] == "CycloneDX"
    assert cbom_document["specVersion"] == "1.6"


def test_cbom_has_serial_number_and_timestamp(cbom_document: dict) -> None:
    assert "serialNumber" in cbom_document
    assert "timestamp" in cbom_document.get("metadata", {})


def test_every_finding_produces_a_component(
    source_findings: list[NormalizedFinding], cbom_document: dict
) -> None:
    components = cbom_document.get("components", [])
    assert len(components) == len(source_findings)


# ── Schema validation ────────────────────────────────────────────────────

def test_cbom_passes_schema_validation(cbom_document: dict) -> None:
    """Acceptance criterion: CycloneDX export validates against the schema."""
    valid, errors = validate_cbom(cbom_document)
    assert valid, f"CBOM validation failed:\n" + "\n".join(errors)


# ── Required fields per spec §12 ─────────────────────────────────────────

def test_every_component_has_bom_ref(cbom_document: dict) -> None:
    for comp in cbom_document["components"]:
        assert comp.get("bom-ref"), f"Component {comp.get('name')} missing bom-ref"


def test_every_component_is_cryptographic_asset(cbom_document: dict) -> None:
    for comp in cbom_document["components"]:
        assert comp["type"] == "cryptographic-asset"


def test_every_component_has_crypto_properties(cbom_document: dict) -> None:
    for comp in cbom_document["components"]:
        crypto = comp.get("cryptoProperties", {})
        assert crypto.get("assetType"), f"{comp['name']} missing assetType"
        algo = crypto.get("algorithmProperties", {})
        assert algo.get("primitive"), f"{comp['name']} missing primitive"


def test_every_component_has_evidence_occurrence(cbom_document: dict) -> None:
    """Spec §12: evidence.occurrences with source file and line."""
    for comp in cbom_document["components"]:
        evidence = comp.get("evidence", {})
        occurrences = evidence.get("occurrences", [])
        assert occurrences, f"{comp['name']} has no evidence.occurrences"
        occ = occurrences[0]
        assert occ.get("location"), f"{comp['name']} occurrence missing location"
        assert occ.get("line"), f"{comp['name']} occurrence missing line"


# ── Algorithm representation ─────────────────────────────────────────────

def test_rsa_2048_represented(cbom_document: dict) -> None:
    rsa_comps = [
        c for c in cbom_document["components"]
        if "RSA-2048" in c.get("name", "")
    ]
    assert rsa_comps, "RSA-2048 not found in CBOM"
    algo = rsa_comps[0]["cryptoProperties"]["algorithmProperties"]
    assert algo["parameterSetIdentifier"] == "2048"
    assert algo["primitive"] == "pke"


def test_ecdh_represented_with_curve(cbom_document: dict) -> None:
    ecdh = [
        c for c in cbom_document["components"]
        if c.get("name", "").startswith("ECDH")
    ]
    assert ecdh, "ECDH not found in CBOM"
    algo = ecdh[0]["cryptoProperties"]["algorithmProperties"]
    assert algo.get("curve") == "secp256r1" or algo.get("parameterSetIdentifier") == "P-256"


def test_md5_represented(cbom_document: dict) -> None:
    md5 = [c for c in cbom_document["components"] if "MD5" in c.get("name", "")]
    assert md5, "MD5 not found in CBOM"
    assert md5[0]["cryptoProperties"]["algorithmProperties"]["primitive"] == "hash"


def test_des_ecb_represented(cbom_document: dict) -> None:
    des = [
        c for c in cbom_document["components"]
        if c.get("name", "") == "DES" and "legacy_pin_des" in c.get("description", "")
    ]
    assert des, "DES not found in CBOM"
    mode = des[0]["cryptoProperties"]["algorithmProperties"].get("mode")
    assert mode == "ecb", f"Expected ECB mode, got {mode}"


# ── JSON output ──────────────────────────────────────────────────────────

def test_cbom_json_is_valid_json(cbom_json_str: str) -> None:
    doc = json.loads(cbom_json_str)
    assert doc["bomFormat"] == "CycloneDX"


def test_cbom_json_is_formatted(cbom_json_str: str) -> None:
    """The exported JSON should be human-readable (indented)."""
    assert "\n  " in cbom_json_str


# ── Validator catches bad input ──────────────────────────────────────────

def test_validator_rejects_empty_document() -> None:
    valid, errors = validate_cbom({})
    assert not valid
    assert any("bomFormat" in e for e in errors)


def test_validator_rejects_missing_components() -> None:
    valid, errors = validate_cbom({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [],
    })
    assert not valid
    assert any("no components" in e.lower() for e in errors)
