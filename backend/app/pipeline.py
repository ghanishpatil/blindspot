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
from app.scanner.aws_kms import scan_aws_kms
from app.scanner.azure_kv import scan_azure_kv
from app.scanner.binary import scan_binaries
from app.scanner.gcp_kms import scan_gcp_kms
from app.scanner.config_policy import scan_config_policy
from app.scanner.dependency_parser import parse_dependencies
from app.scanner.infra import scan_infra
from app.scanner.pkcs11_scanner import scan_pkcs11
from app.scanner.semgrep import run_semgrep
from app.scanner.static_crypto import scan_static_crypto
from app.scanner.tls import TlsScanError, scan_tls

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


def _parse_tls_target(spec: str) -> tuple[str, int] | None:
    """Split a ``"host"`` or ``"host:port"`` string into ``(host, port)``.

    Returns ``None`` when the spec is unparseable. Port defaults to 443.
    Rejects entries containing schemes or paths so callers cannot smuggle a
    full URL through the field — that would confuse the SSRF guard inside
    ``scan_tls`` which validates a bare hostname.
    """
    if not spec or not spec.strip():
        return None
    cleaned = spec.strip()
    if "://" in cleaned or "/" in cleaned:
        return None
    if ":" in cleaned:
        host, _, port_str = cleaned.rpartition(":")
        try:
            port = int(port_str)
        except ValueError:
            return None
        if not (1 <= port <= 65535):
            return None
        return host, port
    return cleaned, 443


def run_pipeline(
    target: Path,
    *,
    project_id: str = "demo",
    owner_id: str | None = None,
    settings: Settings | None = None,
    tls_targets: list[str] | None = None,
) -> tuple[Scan, list[Finding], str]:
    """Run the full pipeline and return (scan, findings, cbom_json).

    ``tls_targets`` is an optional list of ``"host"`` / ``"host:port"`` strings
    to probe alongside the code scan. Every TLS finding flows through the same
    classify / risk / recommend pipeline as a source finding — a live ECDSA
    certificate is treated identically to ECDSA in a source file. Errors on
    individual targets are logged and the scan continues.

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

    try:
        static_crypto_findings = scan_static_crypto(target, settings)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Static crypto scan failed, continuing without it: %s", exc)
        static_crypto_findings = []

    try:
        config_policy_findings = scan_config_policy(target, settings)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Config policy scan failed, continuing without it: %s", exc)
        config_policy_findings = []

    # PKCS#11 HSM attestation (R7). Opt-in and infrastructure-scoped: the
    # target repository is irrelevant here, but running it as a pipeline
    # stage keeps every attested-key finding on the same code path as
    # source and dependency findings.
    try:
        pkcs11_findings = scan_pkcs11(settings)
    except Exception as exc:  # noqa: BLE001
        logger.warning("PKCS#11 scan failed, continuing without it: %s", exc)
        pkcs11_findings = []

    # AWS KMS attestation (R8). Same discipline as PKCS#11 -- infrastructure
    # scoped, opt-in via config, gracefully empty when disabled.
    try:
        aws_kms_findings = scan_aws_kms(settings)
    except Exception as exc:  # noqa: BLE001
        logger.warning("AWS KMS scan failed, continuing without it: %s", exc)
        aws_kms_findings = []

    # Azure Key Vault attestation. Opt-in, optional deps.
    try:
        azure_kv_findings = scan_azure_kv(settings)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Azure Key Vault scan failed, continuing without it: %s", exc)
        azure_kv_findings = []

    # GCP KMS attestation. Same discipline: opt-in + optional deps.
    try:
        gcp_kms_findings = scan_gcp_kms(settings)
    except Exception as exc:  # noqa: BLE001
        logger.warning("GCP KMS scan failed, continuing without it: %s", exc)
        gcp_kms_findings = []

    # Live TLS / certificate scans -- one probe per requested target. TLS
    # findings share the risk pipeline with source findings by design: a
    # certificate using ECDSA is treated identically to ECDSA in a source
    # file. Individual target failures never fail the whole scan.
    tls_findings: list[NormalizedFinding] = []
    if tls_targets and settings.tls_scan_enabled:
        for raw_spec in tls_targets:
            parsed = _parse_tls_target(raw_spec)
            if parsed is None:
                logger.warning(
                    "Skipping unparseable TLS target %r (expected 'host' or 'host:port').",
                    raw_spec,
                )
                continue
            host, port = parsed
            try:
                _, findings_for_target = scan_tls(host, port, settings)
            except TlsScanError as exc:
                # Covers both validation refusals (private IP, bad hostname)
                # and connection failures (timeout, TLS error). PS Req 2 AC 5
                # says: an unreachable live target must be recorded and the
                # scan continues — this satisfies that contract.
                logger.warning("TLS scan skipped for %s:%d: %s", host, port, exc)
                continue
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "TLS scan raised for %s:%d, continuing without it: %s",
                    host, port, exc,
                )
                continue
            tls_findings.extend(findings_for_target)
    elif tls_targets and not settings.tls_scan_enabled:
        logger.info(
            "TLS scan disabled by configuration; ignoring %d requested target(s).",
            len(tls_targets),
        )

    # Filter to source findings for the main pipeline.
    # Dependency findings are informational; they don't go through classify/risk.
    source_findings: list[NormalizedFinding] = [
        f for f in normalized
        if f.evidence.detection_method.value != "dependency_manifest"
    ]
    # Binary + infra + static-crypto + config-policy findings flow through
    # the same classify/risk/recommend analysis — the pipeline's whole point
    # is that new discovery sources plug in at this boundary, not later.
    source_findings.extend(binary_findings)
    source_findings.extend(infra_findings)
    source_findings.extend(static_crypto_findings)
    source_findings.extend(config_policy_findings)
    source_findings.extend(pkcs11_findings)
    source_findings.extend(aws_kms_findings)
    source_findings.extend(azure_kv_findings)
    source_findings.extend(gcp_kms_findings)
    source_findings.extend(tls_findings)

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
