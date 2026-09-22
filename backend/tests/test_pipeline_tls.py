"""Pipeline-level tests for live TLS scanning inside ``run_pipeline``.

The design contract these tests protect:

1. ``run_pipeline`` accepts an optional ``tls_targets`` list.
2. When empty / None, the pipeline never invokes ``scan_tls`` (so no
   network calls happen on repository-only scans).
3. When populated, every reachable target contributes findings that flow
   through the SAME classifier + risk engine + recommender as source
   findings -- i.e. they arrive as fully enriched ``Finding`` objects
   with a ``risk_tier`` and ``recommendation`` (or None if analysis
   couldn't resolve them).
4. Unreachable / invalid targets are logged and skipped; the scan
   completes with the reachable targets' findings intact. This satisfies
   PS Req 2 AC 5 ("record unreachable, continue scanning remaining
   targets").
5. When ``settings.tls_scan_enabled`` is False, the pipeline ignores any
   requested targets even if the caller passes them.
6. Malformed target specs (URLs, invalid ports) are skipped with a
   warning, never crash the pipeline.

Every scanner other than TLS is monkeypatched to an empty list so these
tests are fast and deterministic on any host.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app import pipeline as pipeline_module
from app.config import get_settings
from app.models.asset import ArtefactType, CryptoPrimitive, CryptoUsage, ParameterStatus
from app.models.finding import DetectionMethod, Evidence, NormalizedFinding
from app.pipeline import _parse_tls_target, run_pipeline
from app.scanner import tls as tls_module
from app.scanner.tls import TlsConnectionError, TlsScanError


# ---------------------------------------------------------------------------
# _parse_tls_target -- host / host:port normalisation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "spec, expected",
    [
        ("example.com", ("example.com", 443)),
        ("example.com:8443", ("example.com", 8443)),
        ("  example.com  ", ("example.com", 443)),
        ("example.com:1", ("example.com", 1)),
        ("example.com:65535", ("example.com", 65535)),
    ],
)
def test_parse_tls_target_accepts_bare_hosts_and_host_port(
    spec: str, expected: tuple[str, int]
) -> None:
    assert _parse_tls_target(spec) == expected


@pytest.mark.parametrize(
    "spec",
    [
        "",
        "   ",
        "https://example.com",       # scheme rejected
        "example.com/path",          # path rejected
        "example.com:abc",           # non-numeric port
        "example.com:0",             # out of range
        "example.com:70000",         # out of range
        "example.com:-1",            # negative
    ],
)
def test_parse_tls_target_rejects_bad_specs(spec: str) -> None:
    assert _parse_tls_target(spec) is None


# ---------------------------------------------------------------------------
# Pipeline integration -- monkeypatch every other scanner to isolate TLS
# ---------------------------------------------------------------------------

def _tls_finding(host: str, port: int) -> NormalizedFinding:
    """Build a plausible normalised TLS finding for a fake scan_tls."""
    return NormalizedFinding(
        id=f"TLS-{host}-{port}",
        algorithm="ECDSA",
        primitive=CryptoPrimitive.SIGNATURE,
        parameter="256",
        parameter_status=ParameterStatus.RESOLVED,
        curve="secp256r1",
        usage=CryptoUsage.CERTIFICATE_SIGNING,
        artefact_type=ArtefactType.CERTIFICATE,
        evidence=Evidence(
            file_path=f"{host}:{port}",
            line_number=None,
            code_snippet=f"ECDSA 256-bit certificate; TLSv1.3",
            detection_method=DetectionMethod.TLS_PROBE,
            confidence=0.95,
        ),
    )


@pytest.fixture
def isolated_pipeline(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Neutralise every non-TLS discovery source so tests are hermetic."""
    monkeypatch.setattr(pipeline_module, "run_semgrep", lambda *a, **k: [])
    monkeypatch.setattr(pipeline_module, "parse_dependencies", lambda *a, **k: [])
    monkeypatch.setattr(pipeline_module, "scan_binaries", lambda *a, **k: [])
    monkeypatch.setattr(pipeline_module, "scan_infra", lambda *a, **k: [])
    monkeypatch.setattr(pipeline_module, "scan_static_crypto", lambda *a, **k: [])
    monkeypatch.setattr(pipeline_module, "scan_config_policy", lambda *a, **k: [])
    monkeypatch.setattr(pipeline_module, "scan_pkcs11", lambda *a, **k: [])
    monkeypatch.setattr(pipeline_module, "scan_aws_kms", lambda *a, **k: [])
    return tmp_path


def test_pipeline_without_tls_targets_never_calls_scan_tls(
    isolated_pipeline: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A repository-only scan must never touch the network."""
    calls: list[tuple[str, int]] = []

    def _record(host: str, port: int, settings=None):
        calls.append((host, port))
        return {}, [_tls_finding(host, port)]

    monkeypatch.setattr(pipeline_module, "scan_tls", _record)

    scan, findings, _ = run_pipeline(isolated_pipeline, project_id="test-noop")

    assert calls == []
    assert findings == []
    assert scan.finding_count == 0


def test_pipeline_folds_tls_findings_into_enriched_result(
    isolated_pipeline: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every reachable TLS target contributes an enriched Finding that has
    passed through classifier + risk + recommender."""
    def _fake_scan_tls(host: str, port: int, settings=None):
        return {}, [_tls_finding(host, port)]

    monkeypatch.setattr(pipeline_module, "scan_tls", _fake_scan_tls)

    scan, findings, _ = run_pipeline(
        isolated_pipeline,
        project_id="test-tls",
        tls_targets=["example.com", "api.example.com:8443"],
    )

    # Two reachable targets -> two enriched findings.
    assert len(findings) == 2
    ids = sorted(f.id for f in findings)
    assert ids == ["TLS-api.example.com-8443", "TLS-example.com-443"]

    # Each finding must have gone through the enrichment pipeline. The two
    # observable proofs of that are (a) risk_tier is assigned, and (b) the
    # classification block is populated. Either being None here means the
    # TLS findings were not folded in before enrichment.
    for f in findings:
        assert f.risk_tier is not None, (
            f"TLS finding {f.id} was not run through the risk engine"
        )
        assert f.classification is not None, (
            f"TLS finding {f.id} was not classified"
        )
        assert f.evidence.detection_method == DetectionMethod.TLS_PROBE


def test_pipeline_skips_unreachable_target_and_keeps_reachable_one(
    isolated_pipeline: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A single unreachable target must not sink the whole scan.

    Guards PS Req 2 AC 5: an unreachable live target is recorded (log
    warning) and the scan continues with the remaining targets.
    """
    def _selective_scan_tls(host: str, port: int, settings=None):
        if host == "unreachable.example.com":
            raise TlsConnectionError("connection refused")
        return {}, [_tls_finding(host, port)]

    monkeypatch.setattr(pipeline_module, "scan_tls", _selective_scan_tls)

    scan, findings, _ = run_pipeline(
        isolated_pipeline,
        project_id="test-partial",
        tls_targets=["good.example.com", "unreachable.example.com"],
    )

    assert len(findings) == 1
    assert findings[0].id == "TLS-good.example.com-443"


def test_pipeline_skips_malformed_target_specs(
    isolated_pipeline: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Malformed specs (URLs, bad ports) are skipped, never raised."""
    seen_hosts: list[str] = []

    def _fake_scan_tls(host: str, port: int, settings=None):
        seen_hosts.append(host)
        return {}, [_tls_finding(host, port)]

    monkeypatch.setattr(pipeline_module, "scan_tls", _fake_scan_tls)

    scan, findings, _ = run_pipeline(
        isolated_pipeline,
        project_id="test-malformed",
        tls_targets=[
            "https://example.com",   # scheme -> rejected pre-scan
            "example.com/oops",       # path -> rejected pre-scan
            "example.com:not-a-port", # bad port -> rejected pre-scan
            "example.com",            # OK
        ],
    )

    # Only the well-formed spec reached scan_tls.
    assert seen_hosts == ["example.com"]
    assert len(findings) == 1


def test_pipeline_ignores_tls_targets_when_scanning_disabled(
    isolated_pipeline: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """settings.tls_scan_enabled = False must short-circuit even if targets
    are supplied, so operators can hard-disable outbound TLS probing."""
    called = False

    def _should_not_run(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("scan_tls must not run when tls_scan_enabled=False")

    monkeypatch.setattr(pipeline_module, "scan_tls", _should_not_run)
    monkeypatch.setenv("TLS_SCAN_ENABLED", "false")
    get_settings.cache_clear()

    scan, findings, _ = run_pipeline(
        isolated_pipeline,
        project_id="test-disabled",
        tls_targets=["example.com"],
    )

    get_settings.cache_clear()  # restore for other tests
    assert called is False
    assert findings == []


def test_pipeline_swallows_generic_tls_exceptions(
    isolated_pipeline: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Any unexpected exception from scan_tls must not fail the pipeline."""
    def _boom(host: str, port: int, settings=None):
        raise RuntimeError("kernel panic")

    monkeypatch.setattr(pipeline_module, "scan_tls", _boom)

    scan, findings, _ = run_pipeline(
        isolated_pipeline,
        project_id="test-boom",
        tls_targets=["example.com"],
    )

    assert findings == []
    assert scan.finding_count == 0
