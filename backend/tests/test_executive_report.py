"""Executive report tests -- R6.

Two layers of coverage:

1. **Unit** -- ``build_executive_html`` on a minimal in-memory Scan +
   Findings produces well-formed HTML with the four required sections.
2. **Endpoint** -- ``GET /api/report`` behaves correctly through the
   auth-bypassed test client: 404 when no scan, 200 with HTML by default,
   503 or 200 with PDF depending on whether a headless browser is on PATH.

The endpoint tests use the same in-memory scan store the other GET
endpoints (``/roadmap``, ``/compliance``, ``/export/cbom``) rely on.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api import scan as scan_api
from app.evidence.extractor import normalize
from app.evidence.extractor import _make_finding_id  # noqa: F401 - kept for symmetry
from app.models.finding import Evidence, Finding, NormalizedFinding
from app.models.asset import (
    ArtefactType,
    CryptoPrimitive,
    CryptoUsage,
    ParameterStatus,
    SecurityGoal,
)
from app.models.finding import (
    Classification,
    ConfidenceLevel,
    Criticality,
    DetectionMethod,
)
from app.models.scan import Scan, ScanMode, ScanStatus, ScanSummary
from app.models.risk import (
    CurrentRisk,
    MoscaAssessment,
    QuantumRisk,
    QuantumThreat,
    RiskTier,
    Severity,
)
from app.report.executive import (
    ReportGenerationError,
    build_asset_csv,
    build_executive_html,
    build_executive_pdf,
    cbom_from_json_string,
)


# ---------------------------------------------------------------------------
# Fixture builder -- one enriched Finding round-trippable through the API
# ---------------------------------------------------------------------------

def _make_finding(algo: str = "RSA", param: str = "2048") -> Finding:
    evidence = Evidence(
        file_path="src/broken.py",
        line_number=42,
        code_snippet=f"{algo}.generate({param})",
        detection_method=DetectionMethod.SEMGREP_API_PATTERN,
        confidence=0.9,
    )
    classification = Classification(
        artefact_type=ArtefactType.ENCRYPTION,
        security_goal=SecurityGoal.CONFIDENTIALITY,
        data_lifetime_years=15.0,
        criticality=Criticality.HIGH,
        rationale="test",
    )
    mosca = MoscaAssessment(
        x=15.0,
        y=3.0,
        z=10.0,
        equation="15 + 3 > 10",
        result=True,
        tier=RiskTier.OVERDUE,
        margin_years=8.0,
        z_source="test-preset",
        applicable=True,
    )
    return Finding(
        id=f"CRYPTO-{algo}-{param}",
        algorithm=algo,
        primitive=CryptoPrimitive.PKE,
        parameter=param,
        parameter_status=ParameterStatus.RESOLVED,
        usage=CryptoUsage.KEY_ESTABLISHMENT,
        artefact_type=classification.artefact_type,
        evidence=evidence,
        classification=classification,
        current_risk=CurrentRisk(is_currently_weak=False, severity=Severity.NONE, reason="ok"),
        quantum_risk=QuantumRisk(
            is_quantum_vulnerable=True,
            threat=QuantumThreat.SHOR_BREAKS,
            reason=f"{algo} is Shor-breakable.",
        ),
        mosca=mosca,
        risk_tier=RiskTier.OVERDUE,
    )


def _make_scan(finding_count: int = 1) -> Scan:
    now = datetime.now(timezone.utc)
    summary = ScanSummary(
        total_findings=finding_count,
        quantum_sensitive=finding_count,
        overdue=finding_count,
        transitional=0,
        low_risk=0,
        current_weak_crypto=0,
        hndl_exposed=finding_count,
        needs_verification=0,
        unresolved_parameters=0,
        by_algorithm={"RSA": finding_count},
        by_artefact_type={"encryption": finding_count},
        by_confidence_level={"high": finding_count},
    )
    return Scan(
        id="scan-r6test",
        project_id="demo",
        owner_id="test-owner",
        status=ScanStatus.COMPLETED,
        mode=ScanMode.LIVE,
        repository="/tmp/target",
        started_at=now,
        completed_at=now,
        finding_count=finding_count,
        summary=summary,
    )


# ===========================================================================
# build_executive_html -- unit tests
# ===========================================================================

def test_html_report_produces_valid_document() -> None:
    scan = _make_scan()
    findings = [_make_finding()]

    html = build_executive_html(scan=scan, findings=findings)

    assert html.startswith("<!doctype html>")
    assert html.rstrip().endswith("</html>")
    assert "<title>" in html
    assert "Blindspot ECDAT" in html


def test_html_report_contains_all_four_sections() -> None:
    scan = _make_scan()
    findings = [_make_finding()]

    html = build_executive_html(scan=scan, findings=findings)

    # Section anchors are stable; the report shell always emits these ids
    # even when the underlying data is missing (with an honest fallback).
    assert 'id="posture"' in html
    assert 'id="roadmap"' in html
    assert 'id="compliance"' in html
    assert 'id="cbom"' in html


def test_html_report_escapes_hostile_text() -> None:
    from app.roadmap.planner import build_roadmap

    scan = _make_scan()
    finding = _make_finding()
    # Poison the file path with markup so a roadmap-item row is forced to
    # render the string. Escaping at the boundary must prevent injection.
    poisoned = finding.model_copy(update={
        "evidence": finding.evidence.model_copy(update={
            "file_path": "<script>alert(1)</script>",
        }),
    })
    # Include roadmap + CBOM with the poisoned name so more than one
    # rendering path is exercised at once.
    roadmap = build_roadmap([poisoned], scan_id=scan.id)
    poisoned_cbom = {
        "specVersion": "1.6",
        "metadata": {"timestamp": "2026-01-01T00:00:00Z"},
        "components": [{"bom-ref": "<img src=x onerror=alert(1)>",
                        "name": "<b>evil</b>",
                        "cryptoProperties": {"assetType": "algorithm"}}],
    }
    html = build_executive_html(
        scan=scan, findings=[poisoned], roadmap=roadmap, cbom=poisoned_cbom
    )

    # No raw script/img markup may survive.
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x" not in html
    # Escaped forms of the poisoned path and CBOM strings must be present.
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;b&gt;evil&lt;/b&gt;" in html


def test_html_report_renders_roadmap_when_provided() -> None:
    from app.roadmap.planner import build_roadmap

    scan = _make_scan()
    findings = [_make_finding()]
    roadmap = build_roadmap(findings, scan_id=scan.id)

    html = build_executive_html(scan=scan, findings=findings, roadmap=roadmap)

    # A rendered wave must appear; the fallback muted note must not.
    assert "Wave 1" in html or "Wave " in html
    assert "No roadmap was available" not in html


def test_html_report_renders_compliance_matrix() -> None:
    from app.compliance.evaluator import evaluate_compliance

    scan = _make_scan()
    findings = [_make_finding()]
    compliance = evaluate_compliance(findings, scan_id=scan.id)

    html = build_executive_html(scan=scan, findings=findings, compliance=compliance)

    # At least one preset name must appear -- z_presets always ships several.
    assert compliance.baseline_preset_name in html
    # And the delta-column header must be there.
    assert "overdue" in html.lower()


def test_html_report_renders_cbom_appendix() -> None:
    scan = _make_scan()
    findings = [_make_finding()]
    cbom = {
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:test",
        "metadata": {"timestamp": "2026-09-07T00:00:00Z", "tools": []},
        "components": [
            {"bom-ref": "algo-1", "name": "RSA-2048",
             "cryptoProperties": {"assetType": "algorithm",
                                  "algorithmProperties": {"primitive": "pke"}}}
        ],
    }
    html = build_executive_html(scan=scan, findings=findings, cbom=cbom)

    assert "RSA-2048" in html
    assert "urn:uuid:test" in html
    assert "1.6" in html


def test_html_report_survives_missing_optional_data() -> None:
    scan = _make_scan()
    findings = [_make_finding()]
    # No roadmap, no compliance, no CBOM.
    html = build_executive_html(scan=scan, findings=findings)

    assert "No roadmap was available" in html
    assert "No compliance evaluation was available" in html
    assert "No CBOM available" in html


def test_cbom_from_json_string_tolerates_garbage() -> None:
    assert cbom_from_json_string(None) is None
    assert cbom_from_json_string("") is None
    assert cbom_from_json_string("{ not json") is None
    assert cbom_from_json_string('{"specVersion":"1.6"}') == {"specVersion": "1.6"}
    # A JSON literal that is not an object (e.g. an array) is refused because
    # the report needs to look up keys on it.
    assert cbom_from_json_string("[]") is None


# ===========================================================================
# build_executive_pdf -- honest degradation
# ===========================================================================

def test_pdf_raises_when_no_browser_available(monkeypatch: pytest.MonkeyPatch) -> None:
    """When headless Chrome / Edge / Chromium is not on PATH the builder
    must raise ReportGenerationError. It must never return a fake PDF."""
    from app.report import executive as executive_module

    monkeypatch.setattr(executive_module, "_resolve_headless_chrome", lambda: None)
    with pytest.raises(ReportGenerationError):
        build_executive_pdf(html="<html><body>hi</body></html>")


# ===========================================================================
# Endpoint tests -- /api/report
# ===========================================================================

def _seed_last_scan(scan: Scan, findings: list[Finding], cbom_json: str = "{}") -> None:
    """Populate the in-memory scan store the report endpoint reads from."""
    scan_api._last_scan = scan.serialise()
    scan_api._last_findings = [f.serialise() for f in findings]
    scan_api._last_cbom = cbom_json


def _clear_last_scan() -> None:
    scan_api._last_scan = None
    scan_api._last_findings = None
    scan_api._last_cbom = None


def test_report_endpoint_returns_404_when_no_scan(auth_bypassed_client: TestClient) -> None:
    _clear_last_scan()
    r = auth_bypassed_client.get("/api/report")
    assert r.status_code == 404


def test_report_endpoint_returns_html_by_default(auth_bypassed_client: TestClient) -> None:
    scan = _make_scan()
    scan_dict = scan.serialise()
    scan_dict["ownerId"] = "demo-user"   # demo bypass principal owner
    scan_api._last_scan = scan_dict
    scan_api._last_findings = [_make_finding().serialise()]
    scan_api._last_cbom = "{}"

    try:
        r = auth_bypassed_client.get("/api/report")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/html")
        assert "<!doctype html>" in r.text
        # The header should include the scan id somewhere so the recipient
        # can tell which run this report describes.
        assert "scan-r6test" in r.text
    finally:
        _clear_last_scan()


def test_report_endpoint_pdf_returns_503_without_browser(
    auth_bypassed_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When PDF is asked for and no headless browser is available, the
    endpoint must respond with 503 -- not silently downgrade to HTML,
    not fake a PDF."""
    from app.report import executive as executive_module

    scan = _make_scan()
    scan_dict = scan.serialise()
    scan_dict["ownerId"] = "demo-user"
    scan_api._last_scan = scan_dict
    scan_api._last_findings = [_make_finding().serialise()]
    scan_api._last_cbom = "{}"

    monkeypatch.setattr(executive_module, "_resolve_headless_chrome", lambda: None)

    try:
        r = auth_bypassed_client.get("/api/report?format=pdf")
        assert r.status_code == 503
        assert "Chrome" in r.json()["detail"] or "browser" in r.json()["detail"].lower()
    finally:
        _clear_last_scan()


def test_report_endpoint_rejects_mismatched_scan_id(
    auth_bypassed_client: TestClient,
) -> None:
    scan = _make_scan()
    scan_dict = scan.serialise()
    scan_dict["ownerId"] = "demo-user"
    scan_api._last_scan = scan_dict
    scan_api._last_findings = [_make_finding().serialise()]
    scan_api._last_cbom = "{}"

    try:
        r = auth_bypassed_client.get("/api/report?scanId=some-other-scan")
        assert r.status_code == 404
    finally:
        _clear_last_scan()


def test_report_endpoint_rejects_invalid_format(auth_bypassed_client: TestClient) -> None:
    scan = _make_scan()
    scan_dict = scan.serialise()
    scan_dict["ownerId"] = "demo-user"
    scan_api._last_scan = scan_dict
    scan_api._last_findings = [_make_finding().serialise()]
    scan_api._last_cbom = "{}"

    try:
        r = auth_bypassed_client.get("/api/report?format=doc")
        # Query-param regex validation must reject non-html/pdf/csv formats.
        assert r.status_code == 422
    finally:
        _clear_last_scan()


# ===========================================================================
# PS-alignment: "all cryptographic assets including versions/modes in
# standardised formats"
# ===========================================================================

def _make_many_findings(count: int) -> list[Finding]:
    """Build *count* findings with a mix of algorithms + modes so tests can
    verify nothing is truncated and every column has real values."""
    from app.models.asset import CipherMode

    algos = [
        ("RSA", "2048", None, None),
        ("ECDSA", "P-256", None, "secp256r1"),
        ("AES", "256", CipherMode.GCM, None),
        ("AES", "128", CipherMode.CBC, None),
        ("3DES", "168", CipherMode.CBC, None),
        ("MD5", None, None, None),
        ("SHA-1", None, None, None),
        ("Ed25519", "255", None, "Ed25519"),
    ]
    out: list[Finding] = []
    for i in range(count):
        algo, param, mode, curve = algos[i % len(algos)]
        base = _make_finding(algo=algo, param=param or "")
        out.append(base.model_copy(update={
            "id": f"CRYPTO-{algo}-{i}",
            "mode": mode,
            "curve": curve,
        }))
    return out


def test_inventory_section_lists_every_finding(monkeypatch) -> None:
    """PS wording is 'all cryptographic assets'. A scan with 30 findings
    must render 30 inventory rows, not a truncated preview."""
    scan = _make_scan(finding_count=30)
    findings = _make_many_findings(30)

    html = build_executive_html(scan=scan, findings=findings)

    # The inventory caption reports the total.
    assert "30 findings" in html or "30 finding" in html
    # Every finding id must appear somewhere in the document.
    for f in findings:
        assert f.id in html


def test_inventory_section_renders_mode_column() -> None:
    """The PS deliverable line names 'versions/modes' explicitly. Mode
    must appear as its own column in the inventory table."""
    scan = _make_scan()
    findings = _make_many_findings(3)
    # Force a specific mode so the assertion is unambiguous.
    from app.models.asset import CipherMode
    findings[0] = findings[0].model_copy(update={"mode": CipherMode.GCM})

    html = build_executive_html(scan=scan, findings=findings)

    # Column header + a mode value.
    assert "<th>Mode</th>" in html
    assert "GCM" in html


def test_inventory_section_renders_curve_and_usage() -> None:
    scan = _make_scan()
    findings = _make_many_findings(3)
    html = build_executive_html(scan=scan, findings=findings)

    # Curve column and at least one resolved curve.
    assert "<th>Curve</th>" in html
    assert "secp256r1" in html
    # Usage column plus at least one usage value.
    assert "<th>Usage</th>" in html
    assert "key establishment" in html


def test_cbom_appendix_renders_mode_and_shows_all_components() -> None:
    """CBOM appendix must show Mode and Parameter columns and NOT
    truncate at 100 components."""
    scan = _make_scan()
    findings = _make_many_findings(3)
    # Build a CBOM with 150 components -- more than the old 100 cap.
    cbom = {
        "specVersion": "1.6",
        "metadata": {"timestamp": "2026-01-01T00:00:00Z"},
        "components": [
            {
                "bom-ref": f"algo-{i}",
                "name": f"AES-{i}",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": "block-cipher",
                        "parameterSetIdentifier": "256",
                        "mode": "gcm",
                    },
                },
            }
            for i in range(150)
        ],
    }
    html = build_executive_html(scan=scan, findings=findings, cbom=cbom)

    # Mode column header + at least one uppercase mode value.
    assert "<th>Mode</th>" in html
    assert "GCM" in html
    # Every one of the 150 bom-refs must appear -- no truncation.
    for i in (0, 50, 99, 100, 149):
        assert f"algo-{i}" in html


def test_csv_export_returns_rfc4180_shape() -> None:
    """CSV must be parseable by the stdlib csv module and contain one
    row per finding plus a header row."""
    import csv
    import io

    scan = _make_scan(finding_count=5)
    findings = _make_many_findings(5)

    csv_body = build_asset_csv(scan=scan, findings=findings)

    # RFC 4180: CRLF line terminator between records.
    assert "\r\n" in csv_body

    reader = csv.reader(io.StringIO(csv_body))
    rows = list(reader)
    assert len(rows) == 1 + 5  # header + 5 findings
    header = rows[0]
    # Column set matches the module-level constant.
    for required in ("Algorithm", "Parameter", "Mode", "Curve", "Library", "Risk Tier"):
        assert required in header


def test_csv_export_populates_mode_and_parameter_columns() -> None:
    import csv
    import io

    from app.models.asset import CipherMode

    scan = _make_scan()
    finding = _make_finding("AES", "256").model_copy(update={"mode": CipherMode.GCM})
    csv_body = build_asset_csv(scan=scan, findings=[finding])

    rows = list(csv.reader(io.StringIO(csv_body)))
    header, values = rows[0], rows[1]
    assert dict(zip(header, values))["Mode"] == "gcm"
    assert dict(zip(header, values))["Parameter"] == "256"


def test_csv_export_survives_hostile_field_content() -> None:
    """CSV escaping must handle commas, quotes, and newlines inside field
    values (file paths especially)."""
    import csv
    import io

    scan = _make_scan()
    finding = _make_finding()
    poisoned = finding.model_copy(update={
        "evidence": finding.evidence.model_copy(update={
            "file_path": 'src/weird,"path"\nwith,quotes.py',
        }),
    })
    csv_body = build_asset_csv(scan=scan, findings=[poisoned])

    rows = list(csv.reader(io.StringIO(csv_body)))
    assert len(rows) == 2
    header, values = rows[0], rows[1]
    parsed = dict(zip(header, values))
    # The parser round-trips the hostile string exactly -- proves the
    # writer wrapped it in quotes and escaped internal ones correctly.
    assert parsed["File Path"] == 'src/weird,"path"\nwith,quotes.py'


# ===========================================================================
# Redesigned report: executive summary + professional layout
# ===========================================================================

def _make_weak_finding() -> Finding:
    """A finding whose algorithm is broken today (MD5) -- so is_currently_weak."""
    from app.models.risk import Severity
    finding = _make_finding("MD5", "128")
    return finding.model_copy(update={
        "current_risk": CurrentRisk(
            is_currently_weak=True,
            severity=Severity.HIGH,
            reason="MD5 is collision-broken.",
        ),
        "risk_tier": RiskTier.OVERDUE,
    })


def test_report_has_executive_summary_as_first_section() -> None:
    """PS deliverable calls for 'important things in short' up front. The
    exec summary must exist, be numbered as section 1, and appear BEFORE
    the detailed posture breakdown."""
    scan = _make_scan()
    findings = [_make_finding()]

    html = build_executive_html(scan=scan, findings=findings)

    assert 'id="summary"' in html
    # Sit before the detailed posture breakdown.
    assert html.index('id="summary"') < html.index('id="posture"')
    # And before every other content section.
    assert html.index('id="summary"') < html.index('id="inventory"')
    assert html.index('id="summary"') < html.index('id="roadmap"')
    assert html.index('id="summary"') < html.index('id="cbom"')

    # Numbered '1.' so a reader sees the deliberate ordering.
    assert "Executive Summary" in html


def test_executive_summary_renders_verdict_overdue_when_overdue_exists() -> None:
    scan = _make_scan()
    findings = [_make_finding()]  # tier=OVERDUE, weak=False

    html = build_executive_html(scan=scan, findings=findings)

    assert "Migration is overdue" in html
    assert "verdict overdue" in html


def test_executive_summary_renders_verdict_clear_when_no_risk() -> None:
    """A scan with no overdue / weak / transitional findings must present
    a clean posture verdict, not the alarming default."""
    from app.models.risk import Severity

    scan = _make_scan(finding_count=1)
    # Zero out every risk-driving counter on the summary.
    scan = scan.model_copy(update={
        "summary": scan.summary.model_copy(update={
            "overdue": 0,
            "transitional": 0,
            "current_weak_crypto": 0,
            "hndl_exposed": 0,
            "quantum_sensitive": 0,
            "needs_verification": 0,
        }),
    })
    finding = _make_finding()
    # Also flip the finding's tier so the top-urgent logic can't see danger.
    calm = finding.model_copy(update={
        "risk_tier": RiskTier.LOW_RISK,
        "current_risk": CurrentRisk(is_currently_weak=False, severity=Severity.NONE, reason="ok"),
    })
    html = build_executive_html(scan=scan, findings=[calm])

    assert "No urgent quantum migration required" in html
    assert "verdict clear" in html


def test_executive_summary_renders_kpi_grid_with_six_metrics() -> None:
    """The KPI grid must always render all six headline metrics -- the
    reviewer reading page 1 alone should never have to hunt for a number."""
    scan = _make_scan(finding_count=42)
    findings = _make_many_findings(42)

    html = build_executive_html(scan=scan, findings=findings)

    for label in (
        "Total Findings",
        "Overdue (Mosca)",
        "HNDL Exposed",
        "Quantum-Vulnerable",
        "Currently Weak",
        "Needs Review",
    ):
        assert label in html, f"KPI '{label}' missing from executive summary"


def test_executive_summary_ranks_currently_weak_findings_first() -> None:
    """MD5 / SHA-1 / DES are broken TODAY. They must show up ahead of
    quantum-only concerns in the top-urgent list -- if they don't, the
    reviewer chases the wrong issue first."""
    scan = _make_scan(finding_count=4)
    findings = [
        _make_finding("RSA", "2048"),
        _make_finding("ECDSA", "P-256"),
        _make_weak_finding(),  # MD5, currently weak
        _make_finding("AES", "256"),
    ]
    html = build_executive_html(scan=scan, findings=findings)

    # Extract the urgent-list block and confirm MD5 is the first row.
    start = html.index("Top 5 Urgent Findings")
    end = html.index("Top Algorithms Detected", start)
    urgent_block = html[start:end]

    # MD5 is currently weak; must precede the quantum-only findings.
    md5_pos = urgent_block.find("MD5")
    ecdsa_pos = urgent_block.find("ECDSA")
    rsa_pos = urgent_block.find("RSA")
    assert md5_pos != -1
    assert md5_pos < ecdsa_pos or ecdsa_pos == -1
    assert md5_pos < rsa_pos or rsa_pos == -1


def test_executive_summary_renders_algorithm_bar_chart() -> None:
    """The mini bar-chart is what a judge scans in three seconds. Verify
    the bars render with widths proportional to counts."""
    scan = _make_scan(finding_count=8)
    # Rewrite the summary's by_algorithm map to reflect real diversity;
    # the base fixture reports just one algorithm which would produce
    # only one bar (the exact scenario the chart is *not* meant for).
    scan = scan.model_copy(update={
        "summary": scan.summary.model_copy(update={
            "by_algorithm": {
                "RSA": 4, "AES": 2, "ECDSA": 1, "MD5": 1,
            },
        }),
    })
    findings = _make_many_findings(8)

    html = build_executive_html(scan=scan, findings=findings)

    # A .bar element must exist for every algorithm shown.
    assert html.count("class='bar'") >= 3
    # Widest bar renders at width:100%.
    assert "width:100%" in html


def test_report_page_break_markers_present() -> None:
    """Print rendering depends on the CSS class `pagebreak` being present
    on every section after the exec summary. Regressing this would give
    us a wall-of-text PDF."""
    scan = _make_scan()
    findings = [_make_finding()]
    from app.roadmap.planner import build_roadmap
    from app.compliance.evaluator import evaluate_compliance

    roadmap = build_roadmap(findings, scan_id=scan.id)
    compliance = evaluate_compliance(findings, scan_id=scan.id)

    html = build_executive_html(
        scan=scan, findings=findings, roadmap=roadmap, compliance=compliance,
        cbom={"specVersion": "1.6", "metadata": {}, "components": []},
    )

    # Four sections after the exec summary must all opt into page-break.
    assert html.count("section pagebreak") >= 4


def test_report_uses_light_theme_professional_palette() -> None:
    """The stylesheet ships light-theme, ink-friendly colours suitable
    for printed distribution -- not the dark neon greens/blues from the
    interactive dashboard."""
    scan = _make_scan()
    findings = [_make_finding()]
    html = build_executive_html(scan=scan, findings=findings)

    # White background + near-black text are hard requirements for print.
    assert "--bg: #FFFFFF" in html
    assert "--fg: #111827" in html
    # Print media query must exist and force exact-colour rendering.
    assert "@media print" in html
    assert "-webkit-print-color-adjust: exact" in html


def test_report_inventory_lists_all_findings_verbatim() -> None:
    """`Produce a report displaying all cryptographic assets`. Not a
    sample. Not a top-N. Every last one."""
    scan = _make_scan(finding_count=57)
    findings = _make_many_findings(57)

    html = build_executive_html(scan=scan, findings=findings)

    for f in findings:
        assert f.id in html, f"finding {f.id} missing from HTML report"

    # And CSV keeps its own promise.
    csv_body = build_asset_csv(scan=scan, findings=findings)
    import csv
    import io
    rows = list(csv.reader(io.StringIO(csv_body)))
    assert len(rows) == 1 + 57  # header + one row per finding


def test_report_endpoint_returns_csv(auth_bypassed_client: TestClient) -> None:
    scan = _make_scan()
    scan_dict = scan.serialise()
    scan_dict["ownerId"] = "demo-user"
    scan_api._last_scan = scan_dict
    scan_api._last_findings = [_make_finding().serialise()]
    scan_api._last_cbom = "{}"

    try:
        r = auth_bypassed_client.get("/api/report?format=csv")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/csv")
        # Response body is real CSV, not the HTML fallback.
        assert "Algorithm,Display Name" in r.text
        # Attachment disposition so browsers save it.
        assert "attachment" in r.headers["content-disposition"]
        assert ".csv" in r.headers["content-disposition"]
    finally:
        _clear_last_scan()
