"""Full scan pipeline orchestrator.

Wires every stage together in one function call:

    scan → normalize → CBOM → classify → risk → recommend → persist

This is what ``POST /scan`` invokes. Each stage is a pure function call on
in-memory data — no queues, no async workers, no inter-process communication.
The entire pipeline runs synchronously inside the FastAPI request, which is
fine because the seeded repo scans in seconds.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.cbom.builder import build_cbom, build_cbom_json
from app.cbom.validator import validate_cbom
from app.classifier.classifier import classify
from app.config import Settings, get_settings
from app.evidence.extractor import normalize
from app.models.finding import Finding, NormalizedFinding
from app.models.risk import RiskTier
from app.models.scan import Scan, ScanMode, ScanResponse, ScanStatus, ScanSummary
from app.recommend.recommender import recommend
from app.risk.mosca import assess, assess_current_risk, assess_quantum_risk
from app.scanner.binary import scan_binaries
from app.scanner.dependency_parser import parse_dependencies
from app.scanner.infra import scan_infra
from app.scanner.semgrep import run_semgrep

logger = logging.getLogger(__name__)


def _enrich_finding(
    nf: NormalizedFinding,
    scan_id: str,
    project_id: str,
    settings: Settings,
) -> Finding:
    """Run one NormalizedFinding through classify → risk → recommend."""
    classification = classify(nf)
    current_risk = assess_current_risk(nf.algorithm)
    quantum_risk = assess_quantum_risk(nf.algorithm)

    mosca_result = assess(
        x=classification.data_lifetime_years,
        y=settings.migration_time_years,
        z=settings.quantum_horizon_years,
        z_source=settings.quantum_horizon_source,
        quantum_vulnerable=quantum_risk.is_quantum_vulnerable,
    )

    risk_tier = mosca_result.tier

    finding = Finding(
        **nf.model_dump(),
        scan_id=scan_id,
        project_id=project_id,
        classification=classification,
        current_risk=current_risk,
        quantum_risk=quantum_risk,
        mosca=mosca_result,
        risk_tier=risk_tier,
    )

    rec = recommend(finding)
    finding = finding.model_copy(update={"recommendation": rec})

    return finding


def _build_summary(findings: list[Finding]) -> ScanSummary:
    """Aggregate findings into dashboard summary counts."""
    from collections import Counter

    algo_counter: Counter[str] = Counter()
    type_counter: Counter[str] = Counter()
    conf_counter: Counter[str] = Counter()

    total = 0
    quantum_sensitive = 0
    overdue = 0
    transitional = 0
    low_risk = 0
    current_weak = 0
    hndl = 0
    needs_verif = 0
    unresolved = 0

    for f in findings:
        total += 1
        algo_counter[f.algorithm] += 1
        type_counter[f.artefact_type.value] += 1
        conf_counter[f.evidence.confidence_level.value] += 1

        if f.is_quantum_sensitive:
            quantum_sensitive += 1
        if f.is_currently_weak:
            current_weak += 1
        if f.is_hndl_exposed:
            hndl += 1
        if f.needs_verification:
            needs_verif += 1
        if f.parameter_status.value == "unresolved":
            unresolved += 1
        if f.risk_tier == RiskTier.OVERDUE:
            overdue += 1
        elif f.risk_tier == RiskTier.TRANSITIONAL:
            transitional += 1
        elif f.risk_tier == RiskTier.LOW_RISK:
            low_risk += 1

    return ScanSummary(
        total_findings=total,
        quantum_sensitive=quantum_sensitive,
        overdue=overdue,
        transitional=transitional,
        low_risk=low_risk,
        current_weak_crypto=current_weak,
        hndl_exposed=hndl,
        needs_verification=needs_verif,
        unresolved_parameters=unresolved,
        by_algorithm=dict(algo_counter),
        by_artefact_type=dict(type_counter),
        by_confidence_level=dict(conf_counter),
    )


def run_pipeline(
    target: Path,
    *,
    project_id: str = "demo",
    owner_id: str | None = None,
    settings: Settings | None = None,
) -> tuple[Scan, list[Finding], str]:
    """Run the full pipeline and return (scan, findings, cbom_json).

    Does NOT persist — the caller decides where to store.
    """
    settings = settings or get_settings()
    scan_id = f"scan-{uuid.uuid4().hex[:12]}"
    started = datetime.now(timezone.utc)

    logger.info("Pipeline started: scan=%s target=%s", scan_id, target)
    t0 = time.monotonic()

    # Stage 1: Discovery — source (semgrep), deps (manifests), binaries
    # (fingerprint match, Phase C), and HSM/KMS declarations (Phase E).
    # Each new discovery source produces NormalizedFinding objects on the
    # same contract, so nothing downstream changes.
    #
    # Each source is *independently resilient*: if source scanning times out
    # (semgrep can hang on hostile antivirus interactions with binary files)
    # we still return the findings the other scanners produced, rather than
    # failing the whole request. Losing real binary + IaC + dependency
    # findings because the source scanner had a bad day is worse than a
    # partial result.
    source_scan_error: str | None = None
    try:
        semgrep_matches = run_semgrep(target, settings)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Source scan (semgrep) failed, continuing without it: %s", exc)
        source_scan_error = str(exc)
        semgrep_matches = []

    try:
        dep_findings = parse_dependencies(target)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Dependency scan failed, continuing without it: %s", exc)
        dep_findings = []

    normalized = normalize(semgrep_matches, dep_findings, target)

    try:
        binary_findings = scan_binaries(target, settings)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Binary scan failed, continuing without it: %s", exc)
        binary_findings = []

    try:
        infra_findings = scan_infra(target, settings)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Infra (HSM/KMS) scan failed, continuing without it: %s", exc)
        infra_findings = []

    # Filter to source findings for the main pipeline.
    # Dependency findings are informational; they don't go through classify/risk.
    source_findings: list[NormalizedFinding] = [
        f for f in normalized
        if f.evidence.detection_method.value != "dependency_manifest"
    ]
    # Binary + infra findings flow through the same classify/risk/recommend
    # analysis — the pipeline's whole point is that new discovery sources plug
    # in at this boundary, not later.
    source_findings.extend(binary_findings)
    source_findings.extend(infra_findings)

    # Stage 2: CBOM
    cbom_json = build_cbom_json(source_findings, project_name=project_id)

    # Validate CBOM
    cbom_doc = json.loads(cbom_json)
    valid, errors = validate_cbom(cbom_doc)
    if not valid:
        logger.warning("CBOM validation issues: %s", errors)

    # Stages 3-5: Classify → Risk → Recommend
    enriched: list[Finding] = []
    for nf in source_findings:
        try:
            finding = _enrich_finding(nf, scan_id, project_id, settings)
            enriched.append(finding)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to enrich finding %s: %s", nf.id, exc)

    elapsed = time.monotonic() - t0
    completed = datetime.now(timezone.utc)

    summary = _build_summary(enriched)

    scan = Scan(
        id=scan_id,
        project_id=project_id,
        owner_id=owner_id,
        status=ScanStatus.COMPLETED,
        mode=ScanMode.LIVE,
        repository=str(target),
        started_at=started,
        completed_at=completed,
        finding_count=len(enriched),
        summary=summary,
    )

    logger.info(
        "Pipeline complete: scan=%s findings=%d elapsed=%.2fs",
        scan_id, len(enriched), elapsed,
    )

    return scan, enriched, cbom_json


def load_cached_result(settings: Settings | None = None) -> tuple[Scan, list[Finding], str] | None:
    """Load the last successful scan from the fallback cache.

    Returns None if no cache exists.
    """
    settings = settings or get_settings()
    cache_path = settings.fallback_cache

    if not cache_path.is_file():
        return None

    try:
        data = json.loads(cache_path.read_text(encoding="utf-8"))
        scan = Scan.model_validate(data["scan"])
        scan = scan.model_copy(update={"mode": ScanMode.CACHED})
        findings = [Finding.model_validate(f) for f in data["findings"]]
        cbom_json = data.get("cbom", "{}")
        return scan, findings, cbom_json
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to load cached result: %s", exc)
        return None


def save_cache(
    scan: Scan,
    findings: list[Finding],
    cbom_json: str,
    settings: Settings | None = None,
) -> None:
    """Save a successful scan result as the fallback cache."""
    settings = settings or get_settings()
    cache_path = settings.fallback_cache
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "scan": scan.serialise(),
        "findings": [f.serialise() for f in findings],
        "cbom": cbom_json,
    }
    cache_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    logger.info("Cached scan result to %s", cache_path)
