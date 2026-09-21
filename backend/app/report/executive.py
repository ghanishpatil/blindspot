"""Executive-report builder (R6).

Turns a completed scan into a branded, self-contained HTML document a
non-engineer can read. A PDF variant is available when a headless Chrome or
Chromium / Edge is on PATH -- purely optional, gracefully degrades.

Rules that keep the report honest:

1. **Nothing is computed here.** Every number, every rationale, every risk
   tier is read verbatim from ``Scan`` / ``Finding`` / ``MigrationRoadmap`` /
   ``ComplianceEvaluation`` produced by the rest of the pipeline. The report
   is a *presentation* layer, not a second opinion.
2. **Pure Python string templating.** No external template engine. Every
   value is HTML-escaped with :func:`html.escape` at the boundary so a
   pathological file path or algorithm string can never inject markup.
3. **PDF rendering is optional.** ``build_executive_pdf`` looks for
   ``chrome``, ``chromium``, ``msedge``, or ``google-chrome`` on PATH. If
   none is available it raises :class:`ReportGenerationError` with the
   exact reason -- the caller then serves the HTML variant and tells the
   user why. We never invent a PDF.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape as _e
from pathlib import Path
from typing import Any, Iterable

from app.models.compliance import ComplianceEvaluation
from app.models.finding import Finding
from app.models.roadmap import MigrationRoadmap
from app.models.scan import Scan

logger = logging.getLogger(__name__)


class ReportGenerationError(RuntimeError):
    """Raised when a report cannot be produced (missing tool, bad data, ...)."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _iso(value: datetime | str | None) -> str:
    """Format an ISO date-time for the header without a timezone suffix."""
    if value is None:
        return "-"
    if isinstance(value, str):
        return _e(value.replace("T", " ").split(".")[0])
    return _e(value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))


def _pct(numerator: int, denominator: int) -> str:
    if denominator <= 0:
        return "0%"
    return f"{(numerator / denominator) * 100:.0f}%"


def _fmt_int(value: int | None) -> str:
    return "-" if value is None else f"{value:,}"


# ---------------------------------------------------------------------------
# Report data envelope
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _ReportContext:
    """Read-only bundle passed through the section renderers.

    The executive report deliberately renders whatever subset of these is
    available. A scan without a roadmap (older cached result) still produces
    a valid report; the roadmap section is simply replaced with an honest
    "not available" note. Same for the compliance matrix and the CBOM.
    """

    scan: Scan
    findings: list[Finding]
    roadmap: MigrationRoadmap | None
    compliance: ComplianceEvaluation | None
    cbom: dict[str, Any] | None
    generated_at: datetime
    app_version: str


# ---------------------------------------------------------------------------
# Section builders -- each returns an HTML string, never raises on missing data
# ---------------------------------------------------------------------------

def _render_header(ctx: _ReportContext) -> str:
    """Cover header -- brand tag, document title, and scan metadata grid.

    Rendered as a full-bleed banner across the top of page 1. The
    metadata block below the title is a four-column grid so every value
    (project / scan id / dates / tool version) aligns cleanly whether
    viewed on screen or printed.
    """
    scan = ctx.scan
    return f"""
    <header class="cover">
      <div class="cover-top">
        <span class="brand-tag">BLINDSPOT ECDAT</span>
        <span class="doc-kind">Cryptographic Assets Report</span>
      </div>

      <h1>Post-Quantum Cryptographic Posture</h1>
      <p class="lede">
        A complete inventory of every cryptographic asset the pipeline
        discovered on this scan, classified against Mosca's inequality
        and mapped to a migration plan.
      </p>

      <dl class="cover-meta">
        <div>
          <dt>Project</dt>
          <dd>{_e(scan.project_id or 'demo')}</dd>
        </div>
        <div>
          <dt>Scan Identifier</dt>
          <dd class="mono">{_e(scan.id or 'unknown')}</dd>
        </div>
        <div>
          <dt>Scan Started</dt>
          <dd>{_iso(scan.started_at)}</dd>
        </div>
        <div>
          <dt>Scan Completed</dt>
          <dd>{_iso(scan.completed_at)}</dd>
        </div>
        <div>
          <dt>Report Generated</dt>
          <dd>{_iso(ctx.generated_at)}</dd>
        </div>
        <div>
          <dt>Tool Version</dt>
          <dd>Blindspot ECDAT v{_e(ctx.app_version)}</dd>
        </div>
        <div>
          <dt>Total Findings</dt>
          <dd>{_fmt_int(scan.finding_count)}</dd>
        </div>
        <div>
          <dt>Scan Mode</dt>
          <dd>{_e(scan.mode.value.upper() if hasattr(scan.mode, 'value') else str(scan.mode).upper())}</dd>
        </div>
      </dl>
    </header>
    """


def _render_executive_summary(ctx: _ReportContext) -> str:
    """Page-1 executive summary -- the single most important page.

    Layout:

    1. Verdict banner (colour-graded by overall risk)
    2. 6-KPI grid (Total / Overdue / HNDL / Quantum-vulnerable /
       Currently-weak / Needs-verification)
    3. Two-column detail row:
       - Top 5 most urgent findings (left)
       - Top 8 algorithms mini bar-chart (right)

    The whole section is engineered to fit on a single A4 page next to
    the cover header, so a reviewer who reads only page 1 still leaves
    with an accurate summary of the posture.
    """
    scan = ctx.scan
    summary = scan.summary
    findings = ctx.findings

    total = summary.total_findings if summary else len(findings)

    # ---- Verdict banner ----------------------------------------------
    overdue = summary.overdue if summary else 0
    weak = summary.current_weak_crypto if summary else 0
    transitional = summary.transitional if summary else 0
    hndl = summary.hndl_exposed if summary else 0
    needs_verif = summary.needs_verification if summary else 0
    qsens = summary.quantum_sensitive if summary else 0

    if overdue > 0 or weak > 0:
        verdict_class = "overdue"
        verdict_title = "Migration is overdue"
        verdict_summary = (
            f"{_fmt_int(overdue)} finding{'s' if overdue != 1 else ''} exceed "
            f"the Mosca threshold and "
            f"{_fmt_int(weak)} use{'s' if weak == 1 else ''} algorithms that "
            f"are already broken today. Immediate action is required."
        )
    elif transitional > 0:
        verdict_class = "transitional"
        verdict_title = "Migration window is open"
        verdict_summary = (
            f"{_fmt_int(transitional)} finding{'s' if transitional != 1 else ''} "
            f"sit in the transitional window under the active quantum horizon. "
            f"Plan hybrid transitions now to stay ahead of the schedule."
        )
    else:
        verdict_class = "clear"
        verdict_title = "No urgent quantum migration required"
        verdict_summary = (
            "No findings exceed the Mosca threshold under the active quantum "
            "horizon. Continue monitoring the cryptographic surface as it "
            "evolves."
        )

    verdict_html = f"""
    <div class="verdict {verdict_class}">
      <div>
        <span class="verdict-label">Overall posture</span>
        <p class="verdict-title">{_e(verdict_title)}</p>
        <p class="verdict-summary">{_e(verdict_summary)}</p>
      </div>
    </div>
    """

    # ---- KPI grid ----------------------------------------------------
    def _kpi(label: str, value: int, share: str, tone: str) -> str:
        return f"""
        <div class="kpi {tone}">
          <div class="kpi-label">{_e(label)}</div>
          <div class="kpi-value">{_fmt_int(value)}</div>
          <div class="kpi-share">{_e(share)}</div>
        </div>
        """

    kpi_html = "".join([
        _kpi("Total Findings", total, "across every discovery source", ""),
        _kpi("Overdue (Mosca)", overdue, _pct(overdue, total) + " of total", "danger"),
        _kpi("HNDL Exposed", hndl, _pct(hndl, total) + " of total", "danger"),
        _kpi("Quantum-Vulnerable", qsens, _pct(qsens, total) + " of total", "warn"),
        _kpi("Currently Weak", weak, _pct(weak, total) + " of total", "danger" if weak else ""),
        _kpi("Needs Review", needs_verif, _pct(needs_verif, total) + " of total", "warn"),
    ])

    # ---- Top urgent findings -----------------------------------------
    _TIER_WEIGHT = {"overdue": 0, "transitional": 1, "low-risk": 2}

    def _urgent_key(f: Finding) -> tuple:
        tier = f.risk_tier.value if f.risk_tier else "zzz"
        # 1) Currently-weak first (they are broken today, tier is irrelevant)
        weak_first = 0 if f.is_currently_weak else 1
        # 2) Then by Mosca tier
        tier_ord = _TIER_WEIGHT.get(tier, 99)
        # 3) HNDL-exposed before non-HNDL within the same tier
        hndl_ord = 0 if f.is_hndl_exposed else 1
        return (weak_first, tier_ord, hndl_ord, f.algorithm, f.evidence.file_path)

    urgent = sorted(findings, key=_urgent_key)[:5]
    urgent_items: list[str] = []
    for idx, f in enumerate(urgent, start=1):
        # Prefer the roadmap-derived target algorithm; fall back to the
        # generic strategy label so the pill still communicates something
        # actionable (e.g. "PQC", "Hybrid") instead of showing "-".
        target_val = None
        if f.recommendation:
            if f.recommendation.algorithm:
                target_val = f.recommendation.algorithm
            elif f.recommendation.strategy:
                strat = f.recommendation.strategy
                target_val = strat.value if hasattr(strat, "value") else str(strat)
        # Last-resort defaults so the eye still gets a hint.
        if not target_val:
            if f.is_currently_weak:
                target_val = "Replace"
            elif f.is_hndl_exposed or (f.risk_tier and f.risk_tier.value == "overdue"):
                target_val = "Migrate to PQC"

        location = _e(f.evidence.file_path or "-")
        if f.evidence.line_number:
            location += f":{f.evidence.line_number}"

        # Tag the row with the most-important reason it made the list.
        reason = ""
        if f.is_currently_weak:
            reason = " · currently weak"
        elif f.is_hndl_exposed:
            reason = " · HNDL"
        elif f.risk_tier and f.risk_tier.value == "overdue":
            reason = " · overdue"

        target_html = (
            f"<span class='urgent-target'>{_e(target_val)}</span>"
            if target_val
            else ""
        )

        urgent_items.append(
            "<li>"
            f"<span class='urgent-rank'>{idx}</span>"
            "<div>"
            f"<div class='urgent-title'>{_e(f.display_name)}"
            f"<span class='muted small'>{_e(reason)}</span></div>"
            f"<span class='urgent-location'>{location}</span>"
            "</div>"
            f"{target_html}"
            "</li>"
        )

    urgent_html = (
        "<ol class='urgent-list'>" + "".join(urgent_items) + "</ol>"
        if urgent_items
        else "<p class='muted small'>No findings.</p>"
    )

    # ---- Top algorithms mini-chart -----------------------------------
    algo_totals: list[tuple[str, int]]
    if summary and summary.by_algorithm:
        algo_totals = sorted(
            summary.by_algorithm.items(), key=lambda kv: (-kv[1], kv[0])
        )
    else:
        # Fallback: aggregate from findings themselves if the summary is
        # missing (older cached scans).
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.algorithm] = counts.get(f.algorithm, 0) + 1
        algo_totals = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))

    top_algos = algo_totals[:8]
    max_count = max((c for _, c in top_algos), default=1)

    algo_rows: list[str] = []
    for name, count in top_algos:
        width = int(round((count / max_count) * 100)) if max_count else 0
        algo_rows.append(
            f"<span class='algo-name'>{_e(name)}</span>"
            f"<span class='bar'><span style='width:{width}%'></span></span>"
            f"<span class='algo-count'>{_fmt_int(count)}</span>"
        )

    algo_html = (
        "<div class='algo-chart'>" + "".join(algo_rows) + "</div>"
        if algo_rows
        else "<p class='muted small'>No algorithms recorded.</p>"
    )

    return f"""
    <section class="section" id="summary">
      <h2><span class="section-num">1.</span>Executive Summary</h2>
      <p class="section-lede">
        The one-page view. Verdict, headline counts, most urgent items,
        and the algorithm mix -- everything a reviewer needs before
        deciding whether to keep reading.
      </p>

      {verdict_html}

      <div class="kpi-grid">{kpi_html}</div>

      <div class="two-col">
        <div>
          <h3>Top 5 Urgent Findings</h3>
          {urgent_html}
        </div>
        <div>
          <h3>Top Algorithms Detected</h3>
          {algo_html}
        </div>
      </div>

      <nav class="contents-strip" aria-label="Contents">
        <span class="contents-strip-label">In this report</span>
        <a href="#posture">2. Detailed Posture</a>
        <span class="sep">·</span>
        <a href="#inventory">3. Asset Inventory</a>
        <span class="sep">·</span>
        <a href="#roadmap">4. Migration Plan</a>
        <span class="sep">·</span>
        <a href="#compliance">5. Compliance</a>
        <span class="sep">·</span>
        <a href="#cbom">A. CBOM Appendix</a>
      </nav>
    </section>
    """


def _render_posture_summary(ctx: _ReportContext) -> str:
    summary = ctx.scan.summary
    if summary is None:
        return '<section class="section"><h2>Posture summary</h2><p class="muted">No summary available.</p></section>'

    total = summary.total_findings
    overdue_pct = _pct(summary.overdue, total)
    hndl_pct = _pct(summary.hndl_exposed, total)
    weak_pct = _pct(summary.current_weak_crypto, total)

    # Stats table -- one row per counter so a black-and-white printout stays
    # readable. Coloured pills are decorative on top of the number.
    stat_rows = [
        ("Total findings", summary.total_findings, "", "muted"),
        ("Quantum-sensitive", summary.quantum_sensitive, _pct(summary.quantum_sensitive, total), "warn"),
        ("Overdue (Mosca)", summary.overdue, overdue_pct, "danger"),
        ("Transitional (Mosca)", summary.transitional, _pct(summary.transitional, total), "warn"),
        ("Low-risk (Mosca)", summary.low_risk, _pct(summary.low_risk, total), "ok"),
        ("Currently weak", summary.current_weak_crypto, weak_pct, "danger"),
        ("HNDL exposed", summary.hndl_exposed, hndl_pct, "danger"),
        ("Needs verification", summary.needs_verification, _pct(summary.needs_verification, total), "warn"),
        ("Unresolved parameters", summary.unresolved_parameters, _pct(summary.unresolved_parameters, total), "muted"),
    ]

    rows_html = "".join(
        f'<tr><th>{_e(name)}</th>'
        f'<td class="num">{_fmt_int(count)}</td>'
        f'<td class="pct {tone}">{_e(pct)}</td></tr>'
        for name, count, pct, tone in stat_rows
    )

    # Distribution table -- every algorithm the scan saw, no truncation.
    # PS wording is "all cryptographic assets", so the summary respects that
    # even at the algorithm-family aggregation level.
    algo_rows = "".join(
        f"<tr><th>{_e(algo)}</th><td class='num'>{_fmt_int(count)}</td></tr>"
        for algo, count in sorted(summary.by_algorithm.items(), key=lambda kv: (-kv[1], kv[0]))
    ) or "<tr><td colspan='2' class='muted'>No algorithm breakdown available.</td></tr>"

    artefact_rows = "".join(
        f"<tr><th>{_e(artefact)}</th><td class='num'>{_fmt_int(count)}</td></tr>"
        for artefact, count in sorted(summary.by_artefact_type.items(), key=lambda kv: (-kv[1], kv[0]))
    ) or "<tr><td colspan='2' class='muted'>No artefact breakdown available.</td></tr>"

    return f"""
    <section class="section pagebreak" id="posture">
      <h2><span class="section-num">2.</span>Detailed Posture Breakdown</h2>
      <p class="section-lede">
        Every counter surfaced on the dashboard, expanded so the report is
        self-contained. All numbers are straight aggregations over the
        scan's findings -- no recomputation.
      </p>

      <table class="table">
        <caption>Headline Counts</caption>
        <thead>
          <tr>
            <th>Metric</th>
            <th class="num">Count</th>
            <th class="pct">Share</th>
          </tr>
        </thead>
        <tbody>{rows_html}</tbody>
      </table>

      <div class="two-col" style="margin-top:16px">
        <table class="table">
          <caption>Algorithms Detected</caption>
          <thead><tr><th>Algorithm</th><th class="num">Findings</th></tr></thead>
          <tbody>{algo_rows}</tbody>
        </table>
        <table class="table">
          <caption>Artefact Type</caption>
          <thead><tr><th>Type</th><th class="num">Findings</th></tr></thead>
          <tbody>{artefact_rows}</tbody>
        </table>
      </div>
    </section>
    """


def _render_roadmap(ctx: _ReportContext) -> str:
    roadmap = ctx.roadmap
    if roadmap is None or not roadmap.waves:
        return """
        <section class="section" id="roadmap">
          <h2>Wave-by-wave migration plan</h2>
          <p class="muted">
            No roadmap was available at report-generation time. Run
            <span class="mono">GET /api/roadmap</span> against the same
            scan and regenerate the report to include it.
          </p>
        </section>
        """

    # Some wave.title values from the planner already start with a
    # "Wave <N> — " or "Wave <N>:" prefix. We render our own "Wave N:"
    # header, so strip any such prefix from the title to avoid the
    # "Wave 2: Wave 1 — Urgent PQC Migration" duplication.
    _WAVE_PREFIX = re.compile(r"^\s*wave\s+\d+\s*[—\-:·]\s*", re.IGNORECASE)

    wave_blocks: list[str] = []
    for wave in roadmap.waves:
        item_rows = "".join(
            f"<tr>"
            f"<td>{_e(item.display_name)}</td>"
            f"<td>{_e(item.target_algorithm)}</td>"
            f"<td>{_e(item.risk_tier or '-')}</td>"
            f"<td>{_e(item.effort)}</td>"
            f"<td>{_e(item.cost_band)}</td>"
            f"<td class='mono small'>{_e(item.file_path)}"
            f"{':' + str(item.line_number) if item.line_number else ''}</td>"
            f"</tr>"
            for item in wave.items   # PS: display all cryptographic assets
        )
        clean_title = _WAVE_PREFIX.sub("", wave.title).strip() or wave.title
        wave_blocks.append(f"""
        <div class="wave">
          <h3>Wave {wave.order}: {_e(clean_title)}
            <span class="pill">{_e(wave.strategy.value)}</span>
            <span class="count">{wave.item_count} item{'s' if wave.item_count != 1 else ''}</span>
          </h3>
          <p class="prose">{_e(wave.description)}</p>
          {'<table class="table"><thead><tr><th>Finding</th><th>Target</th><th>Tier</th><th>Effort</th><th>Cost</th><th>Location</th></tr></thead><tbody>' + item_rows + '</tbody></table>' if item_rows else '<p class="muted">No items in this wave.</p>'}
        </div>
        """)

    return f"""
    <section class="section pagebreak" id="roadmap">
      <h2><span class="section-num">4.</span>Wave-by-Wave Migration Plan</h2>
      <p class="section-lede">
        Findings grouped into ordered waves by migration strategy
        (REMEDIATE_NOW, PQC, HYBRID, INVESTIGATE, DEFER). Ordering is set
        by Mosca risk tier, criticality, and blast radius -- the same
        values the dashboard uses.
      </p>
      {''.join(wave_blocks)}
    </section>
    """


def _render_compliance(ctx: _ReportContext) -> str:
    comp = ctx.compliance
    if comp is None or not comp.presets:
        return """
        <section class="section" id="compliance">
          <h2>Compliance sensitivity</h2>
          <p class="muted">
            No compliance evaluation was available at report-generation time.
            Run <span class="mono">GET /api/compliance</span> against the same
            scan and regenerate the report to include it.
          </p>
        </section>
        """

    header_cells = "".join(
        f"<th class='num'>{_e(preset.name)}<br><span class='small muted'>Z={preset.z}</span></th>"
        for preset in comp.presets
    )

    body_rows: list[str] = []
    for preset in comp.presets:
        summary = comp.summary_by_preset.get(preset.name)
        if summary is None:
            continue
        delta_class = "danger" if summary.overdue_delta > 0 else ("ok" if summary.overdue_delta < 0 else "muted")
        delta_str = (
            f"+{summary.overdue_delta}" if summary.overdue_delta > 0
            else str(summary.overdue_delta)
        )
        body_rows.append(f"""
        <tr>
          <th>{_e(preset.name)}</th>
          <td class="num danger">{summary.overdue}</td>
          <td class="num warn">{summary.transitional}</td>
          <td class="num ok">{summary.low_risk}</td>
          <td class="num muted">{summary.not_applicable}</td>
          <td class="num {delta_class}">{delta_str}</td>
          <td class="small muted">{_e(preset.source)}</td>
        </tr>
        """)

    return f"""
    <section class="section pagebreak" id="compliance">
      <h2><span class="section-num">5.</span>Compliance Sensitivity</h2>
      <p class="section-lede">
        The <em>same</em> Mosca inequality re-evaluated under each named
        regulatory horizon (India CII deadlines, NIST IR 8547 dates,
        mid-range CRQC estimate). Shows how the tier distribution shifts
        against different policy Z values. Baseline preset:
        <span class="mono">{_e(comp.baseline_preset_name)}</span>.
      </p>
      <table class="table">
        <thead>
          <tr>
            <th>Preset</th>
            <th class="num">Overdue</th>
            <th class="num">Transitional</th>
            <th class="num">Low-risk</th>
            <th class="num">N/A</th>
            <th class="num">&Delta; overdue</th>
            <th>Source</th>
          </tr>
        </thead>
        <tbody>{''.join(body_rows)}</tbody>
      </table>
    </section>
    """


def _render_cbom_appendix(ctx: _ReportContext) -> str:
    cbom = ctx.cbom
    if cbom is None:
        return """
        <section class="section" id="cbom">
          <h2>Appendix A: CBOM</h2>
          <p class="muted">
            No CBOM available. The report was generated without the CycloneDX
            document that normally accompanies a scan.
          </p>
        </section>
        """

    meta = cbom.get("metadata", {})
    components = cbom.get("components", []) or []
    tools = meta.get("tools", {})
    tool_entries: Iterable[dict] = (
        tools.get("components", []) if isinstance(tools, dict) else tools or []
    )

    tool_rows = "".join(
        f"<tr><td>{_e(t.get('name', '-'))}</td>"
        f"<td>{_e(t.get('version', '-'))}</td>"
        f"<td class='small muted'>{_e(t.get('vendor', ''))}</td></tr>"
        for t in tool_entries
        if isinstance(t, dict)
    )

    # PS deliverable: "all cryptographic assets including versions/modes".
    # Every component is rendered -- no truncation. Every CycloneDX
    # component with algorithmProperties surfaces its Mode, primitive,
    # and parameter set alongside the bom-ref and name.
    component_rows_parts: list[str] = []
    for c in components:
        if not isinstance(c, dict):
            continue
        crypto = c.get("cryptoProperties") or {}
        algo_props = crypto.get("algorithmProperties") or {}
        component_rows_parts.append(
            "<tr>"
            f"<td class='mono small'>{_e(str(c.get('bom-ref', '-')))}</td>"
            f"<td>{_e(c.get('name', '-'))}</td>"
            f"<td>{_e(crypto.get('assetType', '-'))}</td>"
            f"<td>{_e(algo_props.get('primitive', '-'))}</td>"
            f"<td class='mono'>{_e(algo_props.get('parameterSetIdentifier') or '-')}</td>"
            f"<td class='mono'>{_e((algo_props.get('mode') or '-').upper() if algo_props.get('mode') else '-')}</td>"
            f"<td>{_e(algo_props.get('curve') or '-')}</td>"
            "</tr>"
        )
    component_rows = "".join(component_rows_parts)
    overflow = ""  # nothing is truncated any more

    return f"""
    <section class="section pagebreak" id="cbom">
      <h2><span class="section-num">A.</span>Appendix &mdash; CycloneDX CBOM</h2>
      <p class="section-lede">
        Cryptographic Bill of Materials in CycloneDX 1.6 format &mdash;
        the same document served at
        <span class="mono">GET /api/export/cbom</span> and validated
        against the CycloneDX JSON schema.
      </p>
      <div class="two-col">
        <table class="table">
          <caption>CBOM metadata</caption>
          <tbody>
            <tr><th>Spec version</th><td>{_e(cbom.get('specVersion', '-'))}</td></tr>
            <tr><th>Serial number</th><td class="mono small">{_e(cbom.get('serialNumber', '-'))}</td></tr>
            <tr><th>Timestamp</th><td>{_e(meta.get('timestamp', '-'))}</td></tr>
            <tr><th>Components</th><td>{_fmt_int(len(components))}</td></tr>
          </tbody>
        </table>
        <table class="table">
          <caption>Tools</caption>
          <thead><tr><th>Tool</th><th>Version</th><th>Vendor</th></tr></thead>
          <tbody>{tool_rows or '<tr><td colspan="3" class="muted">Not declared.</td></tr>'}</tbody>
        </table>
      </div>
      <table class="table wide" style="margin-top:16px">
        <caption>Components ({len(components)} total, all shown)</caption>
        <thead>
          <tr>
            <th>bom-ref</th>
            <th>Name</th>
            <th>Asset type</th>
            <th>Primitive</th>
            <th>Parameter set</th>
            <th>Mode</th>
            <th>Curve</th>
          </tr>
        </thead>
        <tbody>{component_rows or '<tr><td colspan="7" class="muted">No components.</td></tr>'}</tbody>
      </table>
      {overflow}
    </section>
    """


def _render_asset_inventory(ctx: _ReportContext) -> str:
    """Full un-truncated crypto-asset inventory section.

    This is the section that satisfies the PS deliverable line "produce a
    report displaying all cryptographic assets including versions/modes in
    standardised formats." Every finding lands here with its algorithm,
    parameter (key size / curve), mode (CBC/GCM/ECB/...), library, usage,
    file location, detection method, confidence, and risk tier.

    Nothing is truncated. If a scan produces 5 000 findings the table has
    5 000 rows -- the whole point is to be complete.
    """
    findings = ctx.findings
    if not findings:
        return """
        <section class="section" id="inventory">
          <h2>Cryptographic asset inventory</h2>
          <p class="muted">
            No findings on this scan. Nothing to inventory.
          </p>
        </section>
        """

    # Stable sort: overdue first, then transitional, then low-risk, then
    # anything without a tier. Within a tier, algorithm name then file path.
    _TIER_ORDER = {"overdue": 0, "transitional": 1, "low-risk": 2}

    def _sort_key(f: Finding) -> tuple:
        tier = f.risk_tier.value if f.risk_tier else "zzz"
        return (
            _TIER_ORDER.get(tier, 99),
            f.algorithm,
            f.evidence.file_path,
            f.evidence.line_number or 0,
        )

    ordered = sorted(findings, key=_sort_key)

    rows: list[str] = []
    for f in ordered:
        # Compose "version/mode" per the PS wording:
        #   parameter -> "2048", "P-256", "^1.3.1" for deps
        #   mode      -> CBC/GCM/ECB/... on symmetric primitives
        parameter = f.parameter or ("-" if f.parameter_status.value == "not_applicable" else "unresolved")
        mode = f.mode.value.upper() if f.mode else "-"
        library_version = _library_version(f)
        library_display = _e(f.library or "-")
        if library_version:
            library_display = f"{library_display} <span class='small muted'>{_e(library_version)}</span>"

        tier = f.risk_tier.value if f.risk_tier else "-"
        tier_class = {
            "overdue": "danger",
            "transitional": "warn",
            "low-risk": "ok",
        }.get(tier, "muted")

        location = _e(f.evidence.file_path)
        if f.evidence.line_number:
            location += f"<span class='muted small'>:{f.evidence.line_number}</span>"

        confidence_pct = f"{f.evidence.confidence * 100:.0f}%"
        confidence_class = {
            "high": "ok",
            "medium": "warn",
            "low": "danger",
        }.get(f.evidence.confidence_level.value, "muted")

        rows.append(
            "<tr>"
            f"<td class='mono small'>{_e(f.id)}</td>"
            f"<td>{_e(f.algorithm)}</td>"
            f"<td class='mono'>{_e(str(parameter))}</td>"
            f"<td class='mono'>{_e(mode)}</td>"
            f"<td>{_e(f.curve or '-')}</td>"
            f"<td>{_e(f.usage.value.replace('_', ' '))}</td>"
            f"<td>{_e(f.artefact_type.value.replace('-', ' '))}</td>"
            f"<td>{library_display}</td>"
            f"<td class='mono small'>{location}</td>"
            f"<td class='small'>{_e(f.evidence.detection_method.value)}</td>"
            f"<td class='num {confidence_class}'>{confidence_pct}</td>"
            f"<td class='{tier_class}'>{_e(tier)}</td>"
            "</tr>"
        )

    return f"""
    <section class="section pagebreak" id="inventory">
      <h2><span class="section-num">3.</span>Cryptographic Asset Inventory</h2>
      <p class="section-lede">
        Every cryptographic asset the scan discovered, in a single
        un-truncated table. Columns cover algorithm, parameter or
        declared version, cipher mode, curve, usage, artefact type,
        providing library, source location, detection method, confidence,
        and Mosca risk tier. The same inventory is available as CSV
        (<span class="mono">GET /api/report?format=csv</span>) and as
        CycloneDX 1.6 JSON
        (<span class="mono">GET /api/export/cbom</span>).
      </p>
      <table class="table inventory">
        <caption>{len(ordered)} finding{'s' if len(ordered) != 1 else ''} &mdash; all shown, none truncated</caption>
        <thead>
          <tr>
            <th>Finding ID</th>
            <th>Algorithm</th>
            <th>Parameter / Version</th>
            <th>Mode</th>
            <th>Curve</th>
            <th>Usage</th>
            <th>Artefact type</th>
            <th>Library</th>
            <th>Location</th>
            <th>Detection</th>
            <th class="num">Conf.</th>
            <th>Risk tier</th>
          </tr>
        </thead>
        <tbody>{''.join(rows)}</tbody>
      </table>
    </section>
    """


def _library_version(finding: Finding) -> str | None:
    """Best-effort library-version string for the inventory table.

    Dependency-manifest findings carry the version in the evidence snippet
    (``package==1.2.3`` for pip, ``"node-forge": "^1.3.1"`` for npm,
    ``golang.org/x/crypto v0.31.0`` for Go, ``org.bouncycastle:bcprov-jdk18on:1.78``
    for Maven). We extract a short token so the inventory table shows the
    version without stealing a column just for the raw line.
    """
    snippet = finding.evidence.code_snippet or ""
    if finding.evidence.detection_method.value != "dependency_manifest":
        return None
    # A few narrow, well-shaped patterns rather than one greedy regex --
    # keeps false-positive extraction impossible.
    if "==" in snippet:
        # pip requirements: cryptography==42.0.0
        after = snippet.split("==", 1)[1].split(";", 1)[0].strip()
        return after or None
    if '":' in snippet and snippet.count('"') >= 4:
        # package.json: "node-forge": "^1.3.1"
        parts = snippet.split(":", 1)
        if len(parts) == 2:
            value = parts[1].strip().strip(',').strip().strip('"')
            return value or None
    if " v" in snippet and finding.library and finding.library.startswith(("golang.org", "github.com", "filippo.io")):
        # go.mod: golang.org/x/crypto v0.31.0
        tokens = snippet.split()
        for token in tokens:
            if token.startswith("v"):
                return token
    if ":" in snippet and "<dependency>" in snippet:
        # Maven: <dependency> groupId:artifactId:version
        parts = snippet.split(":")
        if len(parts) >= 3:
            return parts[-1].strip() or None
    return None


def _render_footer(ctx: _ReportContext) -> str:
    return f"""
    <footer class="footer">
      <p>
        <strong>Blindspot ECDAT v{_e(ctx.app_version)}</strong> &middot;
        generated {_iso(ctx.generated_at)}.
      </p>
      <p>
        Every value in this report is a straight aggregation of the
        scan's findings. No runtime latency was measured on the reporting
        host and no risk score was recomputed outside the pipeline.
      </p>
      <p class="tagline">&ldquo;You cannot migrate cryptography you cannot find.&rdquo;</p>
    </footer>
    """


# ---------------------------------------------------------------------------
# CSS -- embedded so the HTML is self-contained (no external resources)
# ---------------------------------------------------------------------------

_CSS = """
/*
 * Blindspot ECDAT -- executive report stylesheet.
 *
 * The design brief is enterprise-print-friendly:
 *   - white page, near-black text, professional accent blue
 *   - tabular figures on every number so columns align across rows
 *   - page-1 executive summary that fits on a single Letter/A4 page
 *   - page-break-before on every subsequent section
 *   - tables never split mid-row across page boundaries
 *   - identical result whether opened on-screen or printed to PDF
 */

@page {
  size: A4;
  margin: 18mm 16mm 22mm 16mm;

  @bottom-left {
    content: "Blindspot ECDAT  ·  Cryptographic Assets Report";
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Inter",
                 Roboto, "Helvetica Neue", Arial, sans-serif;
    font-size: 8.5pt;
    color: #6B7280;
    letter-spacing: 0.3px;
  }

  @bottom-right {
    content: "Page " counter(page) " of " counter(pages);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Inter",
                 Roboto, "Helvetica Neue", Arial, sans-serif;
    font-size: 8.5pt;
    color: #6B7280;
    font-variant-numeric: tabular-nums;
  }
}

/* First page: suppress the running caption so it doesn't clash with the
 * cover block. Page numbers stay on so the reviewer still sees "1 of N". */
@page :first {
  @bottom-left { content: ""; }
}

:root {
  --fg: #111827;
  --fg-strong: #030712;
  --fg-muted: #4B5563;
  --fg-subtle: #6B7280;
  --bg: #FFFFFF;
  --bg-panel: #F9FAFB;
  --bg-alt: #F3F4F6;
  --border: #E5E7EB;
  --border-strong: #D1D5DB;
  --accent: #1E40AF;
  --accent-soft: #DBEAFE;
  --ok: #15803D;
  --ok-soft: #DCFCE7;
  --warn: #B45309;
  --warn-soft: #FEF3C7;
  --danger: #B91C1C;
  --danger-soft: #FEE2E2;
  --shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
}

* { box-sizing: border-box; }

html {
  -webkit-print-color-adjust: exact;
  print-color-adjust: exact;
}

body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Inter",
               Roboto, "Helvetica Neue", Arial, sans-serif;
  background: var(--bg);
  color: var(--fg);
  font-size: 13.5px;
  line-height: 1.55;
  font-variant-numeric: tabular-nums;
  -webkit-font-smoothing: antialiased;
}

.container {
  max-width: 900px;
  margin: 0 auto;
  padding: 36px 48px 56px;
}

/* --- Cover header ---------------------------------------------------- */

.cover {
  padding-bottom: 20px;
  margin-bottom: 24px;
  border-bottom: 2px solid var(--fg-strong);
}

.cover-top {
  display: flex;
  flex-wrap: wrap;
  gap: 12px 24px;
  align-items: flex-start;
  justify-content: space-between;
  font-size: 11px;
  letter-spacing: 2.5px;
  text-transform: uppercase;
  color: var(--fg-muted);
}

.brand-tag {
  display: inline-block;
  font-weight: 700;
  color: var(--accent);
  letter-spacing: 3px;
}

.doc-kind {
  font-weight: 600;
}

.cover h1 {
  font-size: 30px;
  line-height: 1.15;
  margin: 12px 0 4px;
  color: var(--fg-strong);
  font-weight: 700;
  letter-spacing: -0.01em;
}

.cover .lede {
  color: var(--fg-muted);
  font-size: 14px;
  margin: 8px 0 0;
  max-width: 60ch;
}

.cover-meta {
  margin-top: 16px;
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px 24px;
}

.cover-meta dt {
  color: var(--fg-subtle);
  font-size: 10.5px;
  letter-spacing: 1.5px;
  text-transform: uppercase;
  margin-bottom: 2px;
}

.cover-meta dd {
  margin: 0;
  font-size: 13px;
  color: var(--fg-strong);
  font-weight: 500;
}

/* --- Section shell --------------------------------------------------- */

.section {
  margin: 0 0 32px;
}

.section + .section.pagebreak {
  page-break-before: always;
  break-before: page;
}

h2 {
  font-size: 18px;
  font-weight: 700;
  color: var(--fg-strong);
  margin: 0 0 4px;
  padding: 0 0 4px;
  border-bottom: 1px solid var(--border-strong);
  letter-spacing: -0.005em;
}

h2 .section-num {
  color: var(--accent);
  font-weight: 700;
  margin-right: 8px;
}

.section-lede {
  color: var(--fg-muted);
  font-size: 12.5px;
  margin: 6px 0 16px;
  max-width: 78ch;
}

h3 {
  font-size: 14px;
  font-weight: 600;
  color: var(--fg-strong);
  margin: 20px 0 8px;
}

.prose {
  color: var(--fg);
  font-size: 13px;
  margin: 8px 0;
}

.muted { color: var(--fg-muted); }
.subtle { color: var(--fg-subtle); }
.small { font-size: 11.5px; }
.mono  { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; }

/* --- Executive summary ---------------------------------------------- */

.verdict {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
  align-items: center;
  justify-content: space-between;
  padding: 14px 18px;
  margin: 4px 0 20px;
  border: 1px solid var(--border);
  border-left: 4px solid var(--verdict-accent, var(--accent));
  border-radius: 4px;
  background: var(--bg-panel);
}

.verdict.overdue     { --verdict-accent: var(--danger); background: var(--danger-soft); }
.verdict.transitional{ --verdict-accent: var(--warn);   background: var(--warn-soft); }
.verdict.clear       { --verdict-accent: var(--ok);     background: var(--ok-soft); }

.verdict-label {
  font-size: 10.5px;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--fg-subtle);
  margin-bottom: 4px;
  display: block;
}

.verdict-title {
  font-size: 17px;
  font-weight: 700;
  color: var(--fg-strong);
  margin: 0;
}

.verdict-summary {
  color: var(--fg);
  font-size: 12.5px;
  margin: 4px 0 0;
  max-width: 62ch;
}

.kpi-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px;
  margin: 0 0 20px;
}

.kpi {
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 10px 12px;
  background: var(--bg);
  box-shadow: var(--shadow);
}

.kpi-label {
  color: var(--fg-subtle);
  font-size: 10.5px;
  letter-spacing: 1.5px;
  text-transform: uppercase;
  margin-bottom: 4px;
}

.kpi-value {
  font-size: 22px;
  font-weight: 700;
  color: var(--fg-strong);
  line-height: 1.1;
}

.kpi-share {
  color: var(--fg-subtle);
  font-size: 11px;
  margin-top: 2px;
}

.kpi.danger .kpi-value { color: var(--danger); }
.kpi.warn   .kpi-value { color: var(--warn); }
.kpi.ok     .kpi-value { color: var(--ok); }

.two-col {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

/* --- Top urgent list ------------------------------------------------ */

.urgent-list {
  list-style: none;
  padding: 0;
  margin: 0;
  border: 1px solid var(--border);
  border-radius: 4px;
  overflow: hidden;
}

.urgent-list li {
  display: grid;
  grid-template-columns: 28px 1fr auto;
  gap: 10px;
  align-items: center;
  padding: 8px 12px;
  border-bottom: 1px solid var(--border);
  font-size: 12.5px;
}

.urgent-list li:last-child { border-bottom: none; }

.urgent-rank {
  font-weight: 700;
  font-variant-numeric: tabular-nums;
  color: var(--fg-subtle);
}

.urgent-title {
  color: var(--fg-strong);
  font-weight: 500;
}

.urgent-location {
  display: block;
  color: var(--fg-subtle);
  font-size: 11px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  margin-top: 2px;
}

.urgent-target {
  font-size: 11px;
  font-weight: 600;
  padding: 3px 8px;
  border-radius: 999px;
  background: var(--accent-soft);
  color: var(--accent);
  white-space: nowrap;
}

/* --- Algorithm mini-chart ------------------------------------------- */

.algo-chart {
  display: grid;
  grid-template-columns: minmax(90px, max-content) 1fr max-content;
  gap: 6px 12px;
  align-items: center;
  font-size: 12.5px;
}

.algo-chart .algo-name { font-weight: 500; color: var(--fg-strong); }
.algo-chart .algo-count { color: var(--fg-subtle); font-variant-numeric: tabular-nums; text-align: right; }

.bar {
  height: 8px;
  background: var(--bg-alt);
  border-radius: 2px;
  overflow: hidden;
}

.bar > span {
  display: block;
  height: 100%;
  background: var(--accent);
  border-radius: 2px;
}

/* --- Contents strip (executive summary footer) ---------------------- */

.contents-strip {
  margin-top: 22px;
  padding: 10px 14px;
  border: 1px solid var(--border);
  border-left: 3px solid var(--accent);
  border-radius: 4px;
  background: var(--bg-panel);
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 6px 14px;
  font-size: 11.5px;
  color: var(--fg-muted);
  page-break-inside: avoid;
  break-inside: avoid;
}

.contents-strip-label {
  font-size: 10px;
  letter-spacing: 1.8px;
  text-transform: uppercase;
  font-weight: 700;
  color: var(--fg-subtle);
  margin-right: 4px;
}

.contents-strip a {
  color: var(--fg-strong);
  text-decoration: none;
  font-weight: 500;
}

.contents-strip a:hover { color: var(--accent); }

.contents-strip .sep {
  color: var(--border-strong);
  user-select: none;
}

/* --- Tables --------------------------------------------------------- */

.table {
  width: 100%;
  border-collapse: collapse;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 4px;
  overflow: hidden;
  font-size: 12px;
}

.table caption {
  text-align: left;
  padding: 8px 12px;
  color: var(--fg-subtle);
  font-size: 10.5px;
  letter-spacing: 1.5px;
  text-transform: uppercase;
  background: var(--bg-panel);
  border-bottom: 1px solid var(--border);
  caption-side: top;
  font-weight: 600;
}

.table th, .table td {
  padding: 7px 10px;
  text-align: left;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}

.table thead th {
  background: var(--bg-panel);
  color: var(--fg-muted);
  font-weight: 600;
  font-size: 11px;
  letter-spacing: 0.5px;
  text-transform: uppercase;
}

.table tbody tr:nth-child(even) td,
.table tbody tr:nth-child(even) th { background: var(--bg-panel); }

.table tbody tr:last-child th, .table tbody tr:last-child td { border-bottom: none; }

.table tbody tr { page-break-inside: avoid; break-inside: avoid; }

.num { text-align: right; font-variant-numeric: tabular-nums; }
.pct { text-align: right; font-variant-numeric: tabular-nums; }
.ok       { color: var(--ok); }
.warn     { color: var(--warn); }
.danger   { color: var(--danger); }
.accent   { color: var(--accent); }

/* Tighter inventory table -- lots of columns, keep it dense but readable */
.table.inventory { font-size: 11px; }
.table.inventory th, .table.inventory td { padding: 5px 8px; }

/* --- Waves ---------------------------------------------------------- */

.wave {
  margin: 14px 0 0;
  padding: 14px 16px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--bg);
  page-break-inside: avoid;
  break-inside: avoid;
}

.wave h3 { margin: 0 0 4px; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.wave .pill {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 999px;
  background: var(--accent-soft);
  color: var(--accent);
  font-size: 10.5px;
  letter-spacing: 1.2px;
  font-weight: 600;
  text-transform: uppercase;
}
.wave .count {
  color: var(--fg-subtle);
  font-size: 11px;
  font-weight: 500;
}

/* --- Footer --------------------------------------------------------- */

.footer {
  margin-top: 40px;
  padding-top: 16px;
  border-top: 1px solid var(--border);
  color: var(--fg-subtle);
  font-size: 11px;
}

.footer p { margin: 4px 0; }

.tagline {
  font-style: italic;
  color: var(--fg-subtle);
}

/* --- Print behaviour ------------------------------------------------ */

@media print {
  body { font-size: 10.5pt; }
  .container { max-width: none; padding: 0; }
  .section.pagebreak { page-break-before: always; break-before: page; }
  .verdict, .kpi, .wave, .urgent-list, .table { box-shadow: none; }
  a { color: inherit; text-decoration: none; }
  thead { display: table-header-group; }
  tr, td, th { page-break-inside: avoid; break-inside: avoid; }
}
"""


# ---------------------------------------------------------------------------
# Public builders
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# CSV builder -- RFC 4180 flat inventory of every finding
# ---------------------------------------------------------------------------

# The CSV column order is stable: any external tool (Excel, LibreOffice,
# GRC importers, python-pandas) that consumes this file will see the same
# schema across releases. Column names use spaces + Title Case for
# spreadsheet readability rather than snake_case.
_CSV_COLUMNS: tuple[str, ...] = (
    "Scan Id",
    "Finding Id",
    "Algorithm",
    "Display Name",
    "Parameter",
    "Parameter Status",
    "Mode",
    "Curve",
    "Primitive",
    "Usage",
    "Artefact Type",
    "Library",
    "Library Version",
    "File Path",
    "Line Number",
    "Detection Method",
    "Confidence",
    "Confidence Level",
    "Risk Tier",
    "Is Quantum Vulnerable",
    "Is Currently Weak",
    "Is HNDL Exposed",
    "Needs Verification",
    "Data Lifetime Years",
    "Criticality",
    "Mosca Equation",
    "Mosca Applicable",
    "Recommendation Strategy",
    "Recommendation Algorithm",
    "Recommendation Rationale",
)


def build_asset_csv(
    *,
    scan: Scan | None,
    findings: list[Finding],
) -> str:
    """Return the full crypto-asset inventory as an RFC 4180 CSV string.

    Every finding contributes exactly one row. Column set is fixed and
    covers algorithm + parameter (version) + mode + curve + usage +
    artefact type + library + version + location + detection method +
    confidence + risk tier + Mosca fields + recommendation summary.

    RFC 4180 compliance:

    * Fields are separated by commas.
    * Fields containing commas / quotes / newlines are wrapped in double
      quotes with internal quotes escaped as ``""``.
    * Line terminator is ``\\r\\n``.

    We use the stdlib :mod:`csv` module so we do not maintain a hand-
    rolled escaper.
    """
    import csv
    import io

    scan_id = scan.id if scan is not None else ""

    buf = io.StringIO(newline="")
    writer = csv.writer(buf, dialect="excel", lineterminator="\r\n")
    writer.writerow(_CSV_COLUMNS)

    for f in findings:
        classification = f.classification
        recommendation = f.recommendation
        mosca = f.mosca

        writer.writerow([
            scan_id,
            f.id,
            f.algorithm,
            f.display_name,
            f.parameter or "",
            f.parameter_status.value,
            f.mode.value if f.mode else "",
            f.curve or "",
            f.primitive.value,
            f.usage.value,
            f.artefact_type.value,
            f.library or "",
            _library_version(f) or "",
            f.evidence.file_path,
            f.evidence.line_number if f.evidence.line_number is not None else "",
            f.evidence.detection_method.value,
            f"{f.evidence.confidence:.2f}",
            f.evidence.confidence_level.value,
            f.risk_tier.value if f.risk_tier else "",
            "true" if f.is_quantum_sensitive else "false",
            "true" if f.is_currently_weak else "false",
            "true" if f.is_hndl_exposed else "false",
            "true" if f.needs_verification else "false",
            (
                f"{classification.data_lifetime_years:g}"
                if classification is not None else ""
            ),
            classification.criticality.value if classification is not None else "",
            mosca.equation if mosca is not None else "",
            "true" if (mosca is not None and mosca.applicable) else "false",
            recommendation.strategy.value if recommendation is not None else "",
            recommendation.algorithm if recommendation is not None else "",
            recommendation.rationale if recommendation is not None else "",
        ])

    return buf.getvalue()


def build_executive_html(
    *,
    scan: Scan,
    findings: list[Finding],
    roadmap: MigrationRoadmap | None = None,
    compliance: ComplianceEvaluation | None = None,
    cbom: dict[str, Any] | None = None,
    app_version: str = "0.1.0",
    now: datetime | None = None,
) -> str:
    """Return the full executive report as an HTML document.

    The document is self-contained -- no external CSS, no external JS, no
    remote images. That makes it suitable for archiving, emailing, or
    printing to PDF outside the demo environment.
    """
    if not scan:
        raise ReportGenerationError("scan is required")

    ctx = _ReportContext(
        scan=scan,
        findings=findings,
        roadmap=roadmap,
        compliance=compliance,
        cbom=cbom,
        generated_at=(now or datetime.now(timezone.utc)),
        app_version=app_version,
    )

    # Ordering matches how a reviewer reads a professional report:
    #   1. Cover header (project + scan metadata)
    #   2. Executive summary  <- page 1 landing
    #   3. Detailed posture breakdown  (page-break)
    #   4. Full asset inventory        (page-break)
    #   5. Wave-by-wave roadmap        (page-break)
    #   6. Compliance sensitivity      (page-break)
    #   A. CBOM appendix               (page-break)
    #   Footer (in-flow, no page break)
    body = "\n".join([
        _render_header(ctx),
        _render_executive_summary(ctx),
        _render_posture_summary(ctx),
        _render_asset_inventory(ctx),
        _render_roadmap(ctx),
        _render_compliance(ctx),
        _render_cbom_appendix(ctx),
        _render_footer(ctx),
    ])

    title = f"Blindspot ECDAT - {_e(scan.project_id or 'demo')} - {_e(scan.id or '')}"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<meta name="generator" content="Blindspot ECDAT v{_e(app_version)}">
<style>{_CSS}</style>
</head>
<body>
<div class="container">
{body}
</div>
</body>
</html>
"""


# --- PDF variant (optional) ------------------------------------------------

# Executable names we try in order. Matches how Chrome / Chromium / Edge are
# usually named across Windows, macOS, and Linux distributions.
_CHROME_CANDIDATES = (
    "chrome",
    "google-chrome",
    "chromium",
    "chromium-browser",
    "msedge",
    "microsoft-edge",
)


def _resolve_headless_chrome() -> str | None:
    """Return the first Chrome/Chromium/Edge binary on PATH, or None."""
    for name in _CHROME_CANDIDATES:
        found = shutil.which(name)
        if found:
            return found
    # Windows-specific install locations that are not on PATH by default.
    windows_defaults = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ]
    for candidate in windows_defaults:
        if os.path.isfile(candidate):
            return candidate
    return None


def build_executive_pdf(
    *,
    html: str,
    timeout_seconds: int = 60,
) -> bytes:
    """Render *html* to a PDF via headless Chrome/Chromium/Edge.

    Raises :class:`ReportGenerationError` when no compatible browser is on
    PATH. The caller is expected to fall back to serving the HTML variant
    with an honest explanation rather than inventing a PDF.
    """
    chrome = _resolve_headless_chrome()
    if chrome is None:
        raise ReportGenerationError(
            "No Chrome, Chromium, or Edge binary was found on PATH. PDF "
            "rendering is optional; call the HTML endpoint instead, or "
            "install a Chromium-family browser."
        )

    with tempfile.TemporaryDirectory(prefix="blindspot-report-") as tmp_dir:
        html_path = Path(tmp_dir) / "report.html"
        pdf_path = Path(tmp_dir) / "report.pdf"
        html_path.write_text(html, encoding="utf-8")

        # `file://` URI so headless Chrome opens the local document. Every
        # flag below is chosen to keep the run deterministic and quiet:
        # no network, no first-run animations, no sandboxes that require
        # supplemental user setup.
        cmd = [
            chrome,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--no-first-run",
            "--no-default-browser-check",
            "--hide-scrollbars",
            "--virtual-time-budget=5000",
            f"--print-to-pdf={pdf_path}",
            "--print-to-pdf-no-header",
            html_path.as_uri(),
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                encoding="utf-8",
                errors="replace",
            )
        except subprocess.TimeoutExpired as exc:
            raise ReportGenerationError(
                f"Headless Chrome timed out after {timeout_seconds}s while "
                f"rendering the report to PDF."
            ) from exc

        if proc.returncode != 0 or not pdf_path.is_file():
            stderr = (proc.stderr or "")[:400]
            raise ReportGenerationError(
                f"Headless Chrome exited with code {proc.returncode}. "
                f"stderr: {stderr}"
            )

        return pdf_path.read_bytes()


def cbom_from_json_string(cbom_json: str | None) -> dict[str, Any] | None:
    """Convenience: parse a CBOM JSON string, returning None on failure.

    The report tolerates a missing or malformed CBOM -- the appendix
    reports it truthfully rather than hiding the failure.
    """
    if not cbom_json:
        return None
    try:
        parsed = json.loads(cbom_json)
    except json.JSONDecodeError as exc:
        logger.warning("Cannot include CBOM in report -- malformed JSON: %s", exc)
        return None
    return parsed if isinstance(parsed, dict) else None
