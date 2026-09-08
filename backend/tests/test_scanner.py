"""Scanner integration tests.

These tests run the REAL scanner pipeline against the REAL demo repo.
No mocks, no fixtures. If the seed, the rules, or the extractor change,
these tests catch it.

The expected values come from artefact_metadata.json — the test oracle.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.evidence.extractor import normalize
from app.models.finding import NormalizedFinding
from app.scanner.dependency_parser import parse_dependencies
from app.scanner.semgrep import run_semgrep

DEMO_REPO = Path(__file__).resolve().parent.parent.parent / "demo-repo"
METADATA = json.loads((DEMO_REPO / "artefact_metadata.json").read_text(encoding="utf-8"))

# Skip the entire module if the demo repo doesn't exist.
pytestmark = pytest.mark.skipif(
    not DEMO_REPO.is_dir(),
    reason="demo-repo not present",
)


@pytest.fixture(scope="module")
def scan_results() -> list[dict]:
    """Raw semgrep matches — run once per test module."""
    return run_semgrep(DEMO_REPO)


@pytest.fixture(scope="module")
def dep_results() -> list[dict]:
    """Dependency parser output — run once per test module."""
    return parse_dependencies(DEMO_REPO)


@pytest.fixture(scope="module")
def all_findings(scan_results: list[dict], dep_results: list[dict]) -> list[NormalizedFinding]:
    """Normalized findings from both sources."""
    return normalize(scan_results, dep_results, DEMO_REPO)


@pytest.fixture(scope="module")
def source_findings(all_findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
    """Findings from source code only (not dependencies)."""
    return [f for f in all_findings if f.evidence.detection_method.value != "dependency_manifest"]


# ── Algorithm coverage (spec §9) ──────────────────────────────────────────

REQUIRED_ALGORITHMS = ["RSA", "ECDH", "ECDSA", "AES", "3DES", "DES", "MD5", "SHA-1"]


@pytest.mark.parametrize("algorithm", REQUIRED_ALGORITHMS)
def test_required_algorithm_is_detected(
    source_findings: list[NormalizedFinding], algorithm: str
) -> None:
    """Build spec §9: every required algorithm must be found in the seed."""
    found = [f for f in source_findings if f.algorithm == algorithm]
    assert found, f"{algorithm} was not detected in the demo repo"


# ── Case 1: Overdue RSA-2048 ─────────────────────────────────────────────

def test_case1_rsa_keygen_resolves_to_2048(source_findings: list[NormalizedFinding]) -> None:
    rsa_keygen = [
        f for f in source_findings
        if f.algorithm == "RSA"
        and f.evidence.file_path.endswith("high_risk_rsa.py")
        and f.usage.value == "key_generation"
    ]
    assert rsa_keygen, "RSA keygen not found in high_risk_rsa.py"
    finding = rsa_keygen[0]

    assert finding.parameter == "2048"
    assert finding.parameter_status.value == "resolved"
    assert finding.evidence.confidence >= 0.9


# ── Case 2: Transitional ECDH ────────────────────────────────────────────

def test_case2_ecdh_detected_with_curve(source_findings: list[NormalizedFinding]) -> None:
    ecdh = [
        f for f in source_findings
        if f.algorithm == "ECDH"
        and f.evidence.file_path.endswith("transitional_tls.py")
    ]
    assert ecdh, "ECDH not found in transitional_tls.py"
    finding = ecdh[0]

    assert finding.primitive.value == "key-agree"
    assert finding.usage.value == "key_establishment"
    assert finding.curve == "secp256r1"
    assert finding.parameter == "P-256"


# ── Case 3: Low-risk ECDSA ───────────────────────────────────────────────

def test_case3_ecdsa_signature_detected(source_findings: list[NormalizedFinding]) -> None:
    ecdsa = [
        f for f in source_findings
        if f.algorithm == "ECDSA"
        and f.evidence.file_path.endswith("low_risk_token.py")
    ]
    assert ecdsa, "ECDSA not found in low_risk_token.py"
    finding = ecdsa[0]

    assert finding.primitive.value == "signature"
    assert finding.usage.value == "digital_signature"
    assert finding.parameter == "P-256"


# ── Case 4: Weak crypto MD5 ──────────────────────────────────────────────

def test_case4_md5_detected(source_findings: list[NormalizedFinding]) -> None:
    md5 = [
        f for f in source_findings
        if f.algorithm == "MD5"
        and f.evidence.file_path.endswith("weak_crypto_md5.py")
    ]
    assert md5, "MD5 not found in weak_crypto_md5.py"
    finding = md5[0]

    assert finding.primitive.value == "hash"
    assert finding.usage.value == "integrity_hash"
    assert finding.evidence.confidence >= 0.85


# ── Case 5: Unresolvable RSA keygen ──────────────────────────────────────

def test_case5_unresolvable_parameter(source_findings: list[NormalizedFinding]) -> None:
    """The scanner MUST NOT resolve the key size by following the import."""
    rsa_unresolved = [
        f for f in source_findings
        if f.algorithm == "RSA"
        and f.evidence.file_path.endswith("unresolvable_keygen.py")
    ]
    assert rsa_unresolved, "RSA keygen not found in unresolvable_keygen.py"
    finding = rsa_unresolved[0]

    assert finding.parameter is None, "key_size must NOT be resolved"
    assert finding.parameter_status.value == "unresolved"
    assert "ARCHIVE_KEY_SIZE" in finding.unresolved_parameters
    assert finding.evidence.confidence <= 0.75, "confidence must be reduced for unresolved params"


# ── Case 6: AES with modes ───────────────────────────────────────────────

def test_case6_aes_gcm_and_cbc_detected(source_findings: list[NormalizedFinding]) -> None:
    aes_findings = [
        f for f in source_findings
        if f.algorithm == "AES"
        and f.evidence.file_path.endswith("field_encryption_aes.py")
    ]
    assert len(aes_findings) >= 2, "Expected multiple AES findings"

    modes_found = {f.mode.value for f in aes_findings if f.mode}
    assert "gcm" in modes_found, "AES-GCM not detected"
    assert "cbc" in modes_found, "AES-CBC not detected"


def test_case6_aes_key_size_resolved(source_findings: list[NormalizedFinding]) -> None:
    aes_keygen = [
        f for f in source_findings
        if f.algorithm == "AES"
        and f.evidence.file_path.endswith("field_encryption_aes.py")
        and f.parameter == "256"
    ]
    assert aes_keygen, "AES-256 key size not resolved"


# ── Case 7: 3DES ─────────────────────────────────────────────────────────

def test_case7_3des_detected_with_cbc(source_findings: list[NormalizedFinding]) -> None:
    tdes = [
        f for f in source_findings
        if f.algorithm == "3DES"
        and f.evidence.file_path.endswith("legacy_tape_3des.py")
    ]
    assert tdes, "3DES not found in legacy_tape_3des.py"
    assert any(f.mode and f.mode.value == "cbc" for f in tdes), "3DES CBC not detected"


# ── Case 8: DES ──────────────────────────────────────────────────────────

def test_case8_des_detected_with_ecb(source_findings: list[NormalizedFinding]) -> None:
    des = [
        f for f in source_findings
        if f.algorithm == "DES"
        and f.evidence.file_path.endswith("legacy_pin_des.py")
    ]
    assert des, "DES not found in legacy_pin_des.py"
    assert any(f.mode and f.mode.value == "ecb" for f in des), "DES ECB not detected"


# ── Case 9: SHA-1 ────────────────────────────────────────────────────────

def test_case9_sha1_detected(source_findings: list[NormalizedFinding]) -> None:
    sha1 = [
        f for f in source_findings
        if f.algorithm == "SHA-1"
        and f.evidence.file_path.endswith("partner_manifest_sha1.py")
    ]
    assert len(sha1) >= 2, "Expected SHA-1 from both hashlib and cryptography APIs"


# ── Evidence quality ──────────────────────────────────────────────────────

def test_every_finding_has_evidence(all_findings: list[NormalizedFinding]) -> None:
    """Every finding must answer: what, where, how, how certain."""
    for f in all_findings:
        assert f.evidence, f"Finding {f.id} has no evidence"
        assert f.evidence.file_path, f"Finding {f.id} has no file path"
        assert f.evidence.confidence > 0, f"Finding {f.id} has zero confidence"
        assert f.algorithm, f"Finding {f.id} has no algorithm"


def test_source_findings_have_line_numbers(source_findings: list[NormalizedFinding]) -> None:
    for f in source_findings:
        assert f.evidence.line_number is not None, (
            f"Source finding {f.id} ({f.algorithm} in {f.evidence.file_path}) has no line number"
        )
        assert f.evidence.line_number > 0


def test_source_findings_have_code_snippets(source_findings: list[NormalizedFinding]) -> None:
    for f in source_findings:
        assert f.evidence.code_snippet, (
            f"Source finding {f.id} ({f.algorithm} in {f.evidence.file_path}) has no snippet"
        )


# ── Dependency findings ──────────────────────────────────────────────────

def test_dependency_manifest_parsed(dep_results: list[dict]) -> None:
    packages = {d["package"] for d in dep_results}
    assert "cryptography" in packages
    assert "pyOpenSSL" in packages or "pyopenssl" in packages
    assert "pycryptodome" in packages


def test_dependency_confidence_below_source(
    all_findings: list[NormalizedFinding],
) -> None:
    """Dependency findings prove capability, not use. Confidence must be lower
    than fully-resolved source findings. Case 5 (unresolved parameter) is
    excluded because its reduced confidence is intentional — it doesn't know
    its own key size, which is a different kind of uncertainty than "declared
    but not observed in source."
    """
    resolved_source_confs = [
        f.evidence.confidence for f in all_findings
        if f.evidence.detection_method.value != "dependency_manifest"
        and f.parameter_status.value != "unresolved"
    ]
    dep_confs = [
        f.evidence.confidence for f in all_findings
        if f.evidence.detection_method.value == "dependency_manifest"
    ]

    if resolved_source_confs and dep_confs:
        assert max(dep_confs) < min(resolved_source_confs), (
            f"Dependency confidence ({max(dep_confs)}) must be below "
            f"resolved source confidence ({min(resolved_source_confs)})"
        )


# ── Determinism ──────────────────────────────────────────────────────────

def test_repeated_scans_produce_identical_results(
    scan_results: list[dict], dep_results: list[dict]
) -> None:
    """Acceptance criterion: re-running the same scan produces identical results."""
    matches2 = run_semgrep(DEMO_REPO)
    deps2 = parse_dependencies(DEMO_REPO)
    findings1 = normalize(scan_results, dep_results, DEMO_REPO)
    findings2 = normalize(matches2, deps2, DEMO_REPO)

    ids1 = sorted(f.id for f in findings1)
    ids2 = sorted(f.id for f in findings2)
    assert ids1 == ids2, "Scan results are not deterministic"

    for f1, f2 in zip(
        sorted(findings1, key=lambda f: f.id),
        sorted(findings2, key=lambda f: f.id),
    ):
        assert f1.algorithm == f2.algorithm
        assert f1.parameter == f2.parameter
        assert f1.parameter_status == f2.parameter_status
        assert f1.evidence.file_path == f2.evidence.file_path
        assert f1.evidence.line_number == f2.evidence.line_number
