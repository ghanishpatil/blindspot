import React, { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

import { Icon } from '@/components/Icon';
import { ApiError, fetchCompliance } from '@/services/api';
import type {
  ComplianceEvaluation,
  ComplianceFinding,
  ComplianceTier,
  RiskTier,
} from '@/types';

/* ── Tier theme ───────────────────────────────────────────────────────── */

const TIER_CONFIG: Record<RiskTier, { label: string; text: string; bg: string; border: string; dot: string }> = {
  overdue: {
    label: 'Overdue', text: 'text-red-400', bg: 'bg-red-500/10',
    border: 'border-red-500/40', dot: 'bg-red-500',
  },
  transitional: {
    label: 'Transitional', text: 'text-amber-400', bg: 'bg-amber-500/10',
    border: 'border-amber-500/40', dot: 'bg-amber-500',
  },
  'low-risk': {
    label: 'Low-risk', text: 'text-emerald-400', bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/40', dot: 'bg-emerald-500',
  },
};

/** Urgency ordering, so we can tell escalation from easing. */
const TIER_RANK: Record<RiskTier, number> = { overdue: 3, transitional: 2, 'low-risk': 1 };

type LoadState =
  | { kind: 'loading' }
  | { kind: 'loaded'; evaluation: ComplianceEvaluation }
  | { kind: 'empty' }
  | { kind: 'error'; message: string };

/** Short label for a preset chip (drops the long parenthetical). */
function shortName(name: string): string {
  return name.replace(/\s*\(.*\)\s*/, '').trim();
}

/* ── Summary stat with baseline delta ─────────────────────────────────── */

const StatCard: React.FC<{
  label: string;
  value: number;
  tier: RiskTier;
  delta?: number;
}> = ({ label, value, tier, delta }) => {
  const cfg = TIER_CONFIG[tier];
  return (
    <div className={`rounded-xl border ${cfg.border} ${cfg.bg} p-4`}>
      <div className="flex items-center gap-1.5">
        <span className={`h-2 w-2 rounded-full ${cfg.dot}`} />
        <span className="font-mono text-[10px] font-semibold uppercase tracking-wider text-slate-400">
          {label}
        </span>
      </div>
      <div className="mt-2 flex items-baseline gap-2">
        <span className={`font-mono text-3xl font-extrabold ${cfg.text}`}>{value}</span>
        {delta != null && delta !== 0 ? (
          <span
            className={`font-mono text-xs font-bold ${
              delta > 0 ? 'text-red-400' : 'text-emerald-400'
            }`}
            title="Change versus the baseline preset"
          >
            {delta > 0 ? `+${delta}` : delta} vs baseline
          </span>
        ) : (
          <span className="font-mono text-[11px] text-slate-500">= baseline</span>
        )}
      </div>
    </div>
  );
};

/* ── Escalation chart: overdue count across every deadline ────────────── */

const EscalationChart: React.FC<{
  evaluation: ComplianceEvaluation;
  selectedName: string;
  onSelect: (name: string) => void;
}> = ({ evaluation, selectedName, onSelect }) => {
  // Earliest deadline first — overdue counts should climb as the horizon tightens.
  const ordered = [...evaluation.presets].sort((a, b) => a.targetYear - b.targetYear);
  const maxOverdue = Math.max(
    1,
    ...ordered.map((p) => evaluation.summaryByPreset[p.name]?.overdue ?? 0),
  );

  return (
    <div className="rounded-xl border border-[#222B35] bg-[#0C1117] p-5">
      <div className="mb-4 flex items-center gap-2">
        <Icon name="trending-up" size={15} className="text-[#7DB7E8]" />
        <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-slate-300">
          Overdue findings by deadline
        </span>
        <span className="text-[11px] text-slate-500">— tighter deadlines surface more risk</span>
      </div>

      <div className="flex items-end gap-2 overflow-x-auto pb-1" style={{ minHeight: 140 }}>
        {ordered.map((preset) => {
          const summary = evaluation.summaryByPreset[preset.name];
          const overdue = summary?.overdue ?? 0;
          const heightPct = Math.round((overdue / maxOverdue) * 100);
          const active = preset.name === selectedName;
          return (
            <button
              key={preset.name}
              onClick={() => onSelect(preset.name)}
              className="group flex min-w-[84px] flex-1 flex-col items-center gap-1.5"
              title={preset.source}
            >
              <span className={`font-mono text-xs font-bold ${active ? 'text-red-400' : 'text-slate-400'}`}>
                {overdue}
              </span>
              <div className="flex h-24 w-full items-end justify-center">
                <div
                  className={`w-8 rounded-t transition-all ${
                    active ? 'bg-red-500' : 'bg-red-500/30 group-hover:bg-red-500/50'
                  }`}
                  style={{ height: `${Math.max(heightPct, 4)}%` }}
                />
              </div>
              <span
                className={`text-center font-mono text-[10px] leading-tight ${
                  active ? 'text-slate-100' : 'text-slate-500'
                }`}
              >
                {shortName(preset.name)}
              </span>
              <span className={`font-mono text-[9px] ${active ? 'text-[#7DB7E8]' : 'text-slate-600'}`}>
                {preset.targetYear}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
};

/* ── One finding row: baseline tier → tier under selected preset ──────── */

const FindingRow: React.FC<{ finding: ComplianceFinding; selectedName: string }> = ({
  finding,
  selectedName,
}) => {
  const selected: ComplianceTier | undefined = finding.tiersByPreset[selectedName];
  const baselineCfg = TIER_CONFIG[finding.baselineTier];
  const selectedTier = selected?.tier ?? finding.baselineTier;
  const selectedCfg = TIER_CONFIG[selectedTier];

  const flipped = selectedTier !== finding.baselineTier;
  const escalated = TIER_RANK[selectedTier] > TIER_RANK[finding.baselineTier];
  const notApplicable = selected ? !selected.applicable : true;

  return (
    <Link
      to={`/findings/${finding.findingId}`}
      className={`group block rounded-lg border p-3 transition-all hover:border-[#7DB7E8]/50 hover:bg-[#0E141C] ${
        flipped ? `${selectedCfg.border} ${selectedCfg.bg}` : 'border-[#222B35] bg-[#0C1117]'
      }`}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5 font-mono text-sm">
          <span className="font-bold text-slate-200">{finding.displayName}</span>
          {finding.criticality ? (
            <span className="rounded border border-[#222B35] bg-[#11171E] px-2 py-0.5 text-[10px] text-slate-400 capitalize">
              {finding.criticality}
            </span>
          ) : null}
        </div>

        {/* baseline tier → selected tier */}
        <div className="flex items-center gap-2 font-mono text-[11px]">
          <span className={`rounded px-2 py-0.5 ${baselineCfg.bg} ${baselineCfg.text}`}>
            {baselineCfg.label}
          </span>
          <Icon name="arrow-right" size={13} className={flipped ? 'text-[#7DB7E8]' : 'text-slate-600'} />
          <span className={`rounded px-2 py-0.5 font-bold ${selectedCfg.bg} ${selectedCfg.text}`}>
            {selectedCfg.label}
          </span>
          {flipped ? (
            <span
              className={`flex items-center gap-0.5 rounded px-1.5 py-0.5 text-[10px] font-bold ${
                escalated ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'
              }`}
            >
              {escalated ? '▲ escalated' : '▼ eased'}
            </span>
          ) : null}
        </div>
      </div>

      <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-slate-500">
        <span className="flex items-center gap-1 font-mono">
          <Icon name="file-code" size={12} />
          {finding.filePath}
          {finding.lineNumber != null ? `:${finding.lineNumber}` : ''}
        </span>
        {notApplicable ? (
          <span className="rounded bg-slate-800 px-1.5 py-0.5" title="Shor does not break this algorithm; Mosca timing does not apply">
            n/a — not Shor-breakable
          </span>
        ) : selected ? (
          <span className="font-mono" title="Mosca inequality under the selected deadline">
            {selected.equation}
            <span className={selected.marginYears > 0 ? 'text-red-400' : 'text-slate-500'}>
              {'  '}(margin {selected.marginYears > 0 ? '+' : ''}
              {selected.marginYears} yrs)
            </span>
          </span>
        ) : null}
      </div>
    </Link>
  );
};

/* ══════════════════════════════════════════════════════════════════════════
   COMPLIANCE SENSITIVITY PAGE
   ══════════════════════════════════════════════════════════════════════════ */

export const CompliancePage: React.FC = () => {
  const [state, setState] = useState<LoadState>({ kind: 'loading' });
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const [flippedOnly, setFlippedOnly] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetchCompliance()
      .then((evaluation) => {
        if (cancelled) return;
        // Defensive: normalise malformed/partial responses so rendering cannot
        // crash on undefined presets/findings/summaryByPreset.
        const safe = evaluation && typeof evaluation === 'object'
          ? {
              ...evaluation,
              totalFindings: typeof evaluation.totalFindings === 'number' ? evaluation.totalFindings : 0,
              presets: Array.isArray(evaluation.presets) ? evaluation.presets : [],
              findings: Array.isArray(evaluation.findings) ? evaluation.findings : [],
              summaryByPreset: evaluation.summaryByPreset && typeof evaluation.summaryByPreset === 'object'
                ? evaluation.summaryByPreset
                : {},
              baselinePresetName: typeof evaluation.baselinePresetName === 'string' ? evaluation.baselinePresetName : '',
            }
          : null;

        if (!safe || safe.totalFindings === 0 || safe.presets.length === 0) {
          setState({ kind: 'empty' });
        } else {
          setState({ kind: 'loaded', evaluation: safe as ComplianceEvaluation });
          setSelectedName(safe.baselinePresetName);
        }
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        if (err instanceof ApiError && err.status === 404) {
          setState({ kind: 'empty' });
        } else {
          setState({
            kind: 'error',
            message: err instanceof Error ? err.message : 'Failed to load compliance view.',
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const evaluation = state.kind === 'loaded' ? state.evaluation : null;
  const activeName = selectedName ?? evaluation?.baselinePresetName ?? '';
  const selectedPreset = evaluation?.presets.find((p) => p.name === activeName) ?? null;
  const summary = evaluation?.summaryByPreset[activeName] ?? null;
  const isBaseline = evaluation ? activeName === evaluation.baselinePresetName : false;

  // Findings sorted: flips first, then by urgency under the selected preset.
  const sortedFindings = useMemo(() => {
    if (!evaluation) return [];
    const withMeta = evaluation.findings.map((f) => {
      const tier = f.tiersByPreset[activeName]?.tier ?? f.baselineTier;
      const flipped = tier !== f.baselineTier;
      return { finding: f, tier, flipped };
    });
    withMeta.sort((a, b) => {
      if (a.flipped !== b.flipped) return a.flipped ? -1 : 1;
      if (TIER_RANK[b.tier] !== TIER_RANK[a.tier]) return TIER_RANK[b.tier] - TIER_RANK[a.tier];
      return a.finding.displayName.localeCompare(b.finding.displayName);
    });
    return withMeta;
  }, [evaluation, activeName]);

  const flipCount = sortedFindings.filter((f) => f.flipped).length;
  const shownFindings = flippedOnly ? sortedFindings.filter((f) => f.flipped) : sortedFindings;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-100">Compliance Sensitivity</h1>
        <p className="mt-1 max-w-3xl text-xs text-slate-400">
          The same finding can be low-risk under one deadline and overdue under another. Pick a
          regulatory horizon and watch the tiers re-evaluate — same Mosca math, different Z. This is
          the policy dependency most discovery tools hide.
        </p>
      </div>

      {state.kind === 'loading' ? (
        <div className="flex h-64 flex-col items-center justify-center gap-3">
          <Icon name="refresh" size={28} className="animate-spin text-[#7DB7E8]" />
          <span className="font-mono text-xs text-slate-400">Evaluating deadlines…</span>
        </div>
      ) : null}

      {state.kind === 'empty' ? (
        <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-10 text-center">
          <Icon name="shield" size={32} className="mx-auto text-slate-600" />
          <h3 className="mt-3 text-base font-bold text-slate-200">No findings to evaluate</h3>
          <p className="mt-1 text-xs text-slate-400">
            Run a scan first — the compliance view re-tiers real findings.
          </p>
          <Link
            to="/scan"
            className="mt-4 inline-flex items-center gap-2 rounded-lg border border-[#7DB7E8]/40 bg-[#7DB7E8] px-4 py-2 text-xs font-bold text-[#080B0F] hover:bg-[#9BC7EA]"
          >
            <Icon name="play" size={14} />
            <span>Go to Scanner</span>
          </Link>
        </div>
      ) : null}

      {state.kind === 'error' ? (
        <div className="rounded-xl border border-red-500/40 bg-red-500/10 p-6">
          <div className="flex items-center gap-2">
            <Icon name="alert-triangle" size={18} className="text-red-400" />
            <h3 className="text-sm font-bold text-red-400">Could not load compliance view</h3>
          </div>
          <p className="mt-1 text-xs text-slate-300">{state.message}</p>
        </div>
      ) : null}

      {evaluation && selectedPreset && summary ? (
        <>
          {/* Preset selector */}
          <div className="rounded-xl border border-[#222B35] bg-[#0C1117] p-5">
            <div className="mb-3 flex items-center gap-2">
              <Icon name="target" size={15} className="text-[#7DB7E8]" />
              <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-slate-300">
                Regulatory horizon
              </span>
            </div>
            <div className="flex flex-wrap gap-2">
              {evaluation.presets.map((preset) => {
                const active = preset.name === activeName;
                const baseline = preset.name === evaluation.baselinePresetName;
                return (
                  <button
                    key={preset.name}
                    onClick={() => setSelectedName(preset.name)}
                    className={`flex flex-col items-start gap-0.5 rounded-lg border px-3 py-2 text-left transition-all ${
                      active
                        ? 'border-[#7DB7E8] bg-[#7DB7E8]/10'
                        : 'border-[#222B35] bg-[#11171E] hover:border-slate-600'
                    }`}
                  >
                    <span className={`font-mono text-[11px] font-semibold ${active ? 'text-[#7DB7E8]' : 'text-slate-300'}`}>
                      {shortName(preset.name)}
                      {baseline ? <span className="ml-1 text-slate-500">(baseline)</span> : null}
                    </span>
                    <span className="font-mono text-[10px] text-slate-500">
                      Z = {preset.z} yr · target {preset.targetYear}
                    </span>
                  </button>
                );
              })}
            </div>
            <p className="mt-3 border-t border-[#222B35] pt-3 text-[11px] text-slate-500">
              <span className="text-slate-400">{selectedPreset.name}</span> — {selectedPreset.source}
            </p>
          </div>

          {/* Summary under the selected preset (deltas vs baseline) */}
          <div>
            <p className="mb-2 text-xs text-slate-400">
              Under <span className="font-semibold text-slate-200">{shortName(selectedPreset.name)}</span>{' '}
              (Z = {selectedPreset.z} yr):
              {isBaseline ? (
                <span className="ml-1 text-slate-500">this is your baseline assessment.</span>
              ) : summary.overdueDelta > 0 ? (
                <span className="ml-1 text-red-400">
                  {summary.overdueDelta} more finding{summary.overdueDelta === 1 ? '' : 's'} become
                  overdue.
                </span>
              ) : summary.overdueDelta < 0 ? (
                <span className="ml-1 text-emerald-400">
                  {Math.abs(summary.overdueDelta)} fewer overdue than baseline.
                </span>
              ) : (
                <span className="ml-1 text-slate-500">no change in overdue count vs baseline.</span>
              )}
            </p>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <StatCard label="Overdue" value={summary.overdue} tier="overdue" delta={isBaseline ? undefined : summary.overdueDelta} />
              <StatCard label="Transitional" value={summary.transitional} tier="transitional" />
              <StatCard label="Low-risk" value={summary.lowRisk} tier="low-risk" />
            </div>
          </div>

          {/* Escalation chart across all deadlines */}
          <EscalationChart
            evaluation={evaluation}
            selectedName={activeName}
            onSelect={setSelectedName}
          />

          {/* Findings, baseline → selected */}
          <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-5">
            <div className="mb-4 flex flex-wrap items-center gap-3">
              <div className="flex items-center gap-2">
                <Icon name="layers" size={15} className="text-[#7DB7E8]" />
                <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-slate-300">
                  Findings — baseline → {shortName(selectedPreset.name)}
                </span>
              </div>
              <span className="rounded-full bg-slate-800 px-2.5 py-0.5 font-mono text-[11px] text-slate-300">
                {flipCount} of {evaluation.totalFindings} change tier
              </span>
              {flipCount > 0 ? (
                <button
                  onClick={() => setFlippedOnly((v) => !v)}
                  className={`ml-auto rounded border px-2.5 py-1 font-mono text-[11px] transition-colors ${
                    flippedOnly
                      ? 'border-[#7DB7E8]/40 bg-[#7DB7E8]/10 text-[#7DB7E8]'
                      : 'border-[#222B35] bg-[#0C1117] text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {flippedOnly ? 'Show all' : 'Show changed only'}
                </button>
              ) : null}
            </div>

            <div className="card-scroll card-scroll-vh space-y-2">
              {shownFindings.map(({ finding }) => (
                <FindingRow key={finding.findingId} finding={finding} selectedName={activeName} />
              ))}
            </div>
          </div>

          <p className="text-center font-mono text-[11px] text-slate-500">
            {evaluation.totalFindings} findings re-tiered against {evaluation.presets.length}{' '}
            deadlines · same X + Y &gt; Z engine · baseline: {shortName(evaluation.baselinePresetName)}
          </p>
        </>
      ) : null}
    </div>
  );
};
