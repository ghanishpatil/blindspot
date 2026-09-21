"""Ad-hoc preview script -- writes a rich sample report to disk so you can
open it in a browser and eyeball the redesign.

Not a test, not shipped -- just a one-shot renderer with realistic data.
Delete after use.
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Reuse the exact fixture builders from the test module so the preview
# renders on the same shapes the pipeline hands to the report in prod.
sys.path.insert(0, str(Path(__file__).parent))

from tests.test_executive_report import (  # noqa: E402
    _make_finding, _make_many_findings, _make_scan, _make_weak_finding,
)
from app.compliance.evaluator import evaluate_compliance  # noqa: E402
from app.report.executive import build_executive_html  # noqa: E402
from app.roadmap.planner import build_roadmap  # noqa: E402


def main() -> None:
    # Mix: 40 findings, several algorithms, one MD5 to exercise the
    # currently-weak branch of the verdict + top-urgent list.
    findings = _make_many_findings(40) + [_make_weak_finding()]

    scan = _make_scan(finding_count=len(findings))
    # Give the scan realistic timestamps so the cover header looks right.
    scan = scan.model_copy(update={
        "started_at": datetime(2026, 9, 7, 10, 23, tzinfo=timezone.utc),
        "completed_at": datetime(2026, 9, 7, 10, 31, tzinfo=timezone.utc),
        # Multi-algorithm breakdown so the bar chart is not a single bar.
        "summary": scan.summary.model_copy(update={
            "by_algorithm": {
                "RSA": 12, "AES": 8, "ECDSA": 6, "3DES": 4,
                "MD5": 3, "SHA-1": 3, "Ed25519": 3, "ChaCha20": 2,
            },
            "by_artefact_type": {
                "encryption": 20, "signature": 12, "hash": 6, "key-exchange": 3,
            },
            "overdue": 8,
            "transitional": 12,
            "low_risk": 21,
            "current_weak_crypto": 3,
            "hndl_exposed": 5,
            "needs_verification": 2,
            "quantum_sensitive": 18,
        }),
    })

    roadmap = build_roadmap(findings, scan_id=scan.id)
    compliance = evaluate_compliance(findings, scan_id=scan.id)
    cbom = {
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:preview",
        "metadata": {
            "timestamp": scan.completed_at.isoformat(),
            "tools": [{"name": "Blindspot ECDAT", "version": "1.0.0"}],
        },
        "components": [
            {
                "bom-ref": f"algo-{i}",
                "name": f"Sample-{i}",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": "pke" if i % 3 == 0 else "block-cipher",
                        "parameterSetIdentifier": "2048" if i % 3 == 0 else "256",
                        "mode": "gcm" if i % 3 == 1 else None,
                    },
                },
            }
            for i in range(24)
        ],
    }

    html = build_executive_html(
        scan=scan, findings=findings, roadmap=roadmap,
        compliance=compliance, cbom=cbom, app_version="1.0.0",
    )

    out = Path(__file__).parent / "artifacts" / "preview-report.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    print(f"Wrote preview report to {out}")
    print(f"Size: {len(html):,} chars")


if __name__ == "__main__":
    main()
