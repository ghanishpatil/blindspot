import React, { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

import { Icon, type IconName } from '@/components/Icon';
import { ApiError, fetchRoadmap } from '@/services/api';
import type { MigrationRoadmap, MigrationWave, RoadmapItem } from '@/types';

/** Per-wave visual theme + short label, strategy icon, and target timeframe. */
const WAVE_CONFIG: Record<
  string,
  {
    border: string;
    bg: string;
    text: string;
    dot: string;
    short: string;
    icon: IconName;
    timeframe: string;
  }
> = {
  remediate_now: {
    border: 'border-orange-500/40', bg: 'bg-orange-500/10', text: 'text-orange-400',
    dot: 'bg-orange-500', short: 'Fix Now', icon: 'alert-triangle', timeframe: 'Immediate',
  },
  wave_1: {
    border: 'border-red-500/40', bg: 'bg-red-500/10', text: 'text-red-400',
    dot: 'bg-red-500', short: 'Wave 1 · PQC', icon: 'shield', timeframe: '0–1 yr',
  },
  wave_2: {
    border: 'border-amber-500/40', bg: 'bg-amber-500/10', text: 'text-amber-400',
    dot: 'bg-amber-500', short: 'Wave 2 · Hybrid', icon: 'layers', timeframe: '1–3 yr',
  },
  wave_3: {
    border: 'border-emerald-500/40', bg: 'bg-emerald-500/10', text: 'text-emerald-400',
    dot: 'bg-emerald-500', short: 'Wave 3 · Monitor', icon: 'clock', timeframe: 'Monitor',
  },
  investigate: {
    border: 'border-slate-500/40', bg: 'bg-slate-500/10', text: 'text-slate-300',
    dot: 'bg-slate-500', short: 'Investigate', icon: 'help-circle', timeframe: 'Review',
  },
};

const DEFAULT_CONFIG = WAVE_CONFIG.investigate;

function effortBadge(effort: string): string {
  const e = effort.toLowerCase();
  if (e === 'high') return 'text-red-400 border-red-500/30 bg-red-500/10';
  if (e === 'moderate') return 'text-amber-400 border-amber-500/30 bg-amber-500/10';
  if (e === 'low') return 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
  return 'text-slate-400 border-slate-600/40 bg-slate-700/20';
}

function costColor(cost: string): string {
  const c = cost.toLowerCase();
  if (c === 'high') return 'text-red-400';
  if (c === 'medium') return 'text-amber-400';
  if (c === 'low') return 'text-emerald-400';
  return 'text-slate-400';
}

/** CSV-safe cell quoting, with spreadsheet formula-injection neutralized.
 *
 * A cell beginning with = + - @ (or tab / CR) can be executed as a formula by
 * Excel / Google Sheets. Since cell values include scanned repo content
 * (file paths, rationale), prefix any such value with a single quote so it is
 * treated as text, then apply standard CSV quoting. */
function csvCell(value: string): string {
  const s = value ?? '';
  const guarded = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return /[",\n]/.test(guarded) ? `"${guarded.replace(/"/g, '""')}"` : guarded;
}

type LoadState =
  | { kind: 'loading' }
  | { kind: 'loaded'; roadmap: MigrationRoadmap }
  | { kind: 'empty' }
  | { kind: 'error'; message: string };

type CritFilter = 'all' | 'high' | 'medium' | 'low';
type EffortFilter = 'all' | 'high' | 'moderate' | 'low';

/* ── (1) Executive summary bar ────────────────────────────────────────── */

const ExecSummary: React.FC<{
  roadmap: MigrationRoadmap;
  onPrint: () => void;
  onCsv: () => void;
}> = ({ roadmap, onPrint, onCsv }) => {
  const all = roadmap.waves.flatMap((w) => w.items);
  const brokenToday = all.filter((i) => i.isCurrentWeakness).length;
  const overdue = all.filter((i) => i.riskTier === 'overdue').length;
  const hybrid = all.filter((i) => i.strategy === 'HYBRID').length;
  const effortHigh = all.filter((i) => i.effort.toLowerCase() === 'high').length;
  const effortModerate = all.filter((i) => i.effort.toLowerCase() === 'moderate').length;
  const effortLow = all.filter((i) => i.effort.toLowerCase() === 'low').length;

  const parts: string[] = [];
  if (brokenToday) parts.push(`${brokenToday} broken today`);
  if (overdue) parts.push(`${overdue} overdue for PQC`);
  if (hybrid) parts.push(`${hybrid} need a hybrid transition`);

  return (
    <div className="rounded-xl border border-[#7DB7E8]/30 bg-gradient-to-r from-[#11171E] to-[#0C1117] p-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex-1 min-w-[260px]">
          <div className="flex items-center gap-2">
            <Icon name="target" size={16} className="text-[#7DB7E8]" />
            <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-slate-300">
              Executive Summary
            </span>
          </div>
          <p className="mt-2 text-sm text-slate-200">
            <span className="font-bold text-slate-100">{roadmap.totalItems}</span> cryptographic
            assets planned
            {parts.length ? (
              <>
                {' '}— <span className="text-slate-300">{parts.join(' · ')}</span>.
              </>
            ) : (
              '.'
            )}
          </p>
          <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] font-mono">
            <span className="text-slate-500">Estimated effort:</span>
            <span className="rounded border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-red-400">
              {effortHigh} high
            </span>
            <span className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-amber-400">
              {effortModerate} moderate
            </span>
            <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-emerald-400">
              {effortLow} low
            </span>
          </div>
        </div>

        {/* (6) Export the plan */}
        <div className="flex items-center gap-2">
          <button
            onClick={onCsv}
            className="flex items-center gap-1.5 rounded-lg border border-[#7DB7E8]/40 bg-[#7DB7E8]/10 px-3 py-1.5 font-mono text-[11px] font-semibold text-[#7DB7E8] transition-colors hover:bg-[#7DB7E8]/20"
          >
            <Icon name="download" size={13} />
            <span>Export CSV</span>
          </button>
          <button
            onClick={onPrint}
            className="flex items-center gap-1.5 rounded-lg border border-[#222B35] bg-[#11171E] px-3 py-1.5 font-mono text-[11px] font-semibold text-slate-300 transition-colors hover:border-slate-600 hover:text-white"
          >
            <Icon name="file" size={13} />
            <span>Print / PDF</span>
          </button>
        </div>
      </div>
    </div>
  );
};

/* ── (2,5) Journey strip: connected phases with icon + timeframe ──────── */

const JourneyStrip: React.FC<{ waves: MigrationWave[] }> = ({ waves }) => (
  <div className="rounded-xl border border-[#222B35] bg-[#0C1117] p-5">
    <div className="mb-4 flex items-center gap-2">
      <Icon name="trending-up" size={15} className="text-[#7DB7E8]" />
      <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-slate-300">
        Migration Journey
      </span>
      <span className="text-[11px] text-slate-500">— work left to right, top to bottom</span>
    </div>

    <div className="flex items-start gap-1 overflow-x-auto pb-1">
      {waves.map((wave, index) => {
        const cfg = WAVE_CONFIG[wave.key] ?? DEFAULT_CONFIG;
        const dim = wave.itemCount === 0 ? 'opacity-40' : '';
        return (
          <React.Fragment key={wave.key}>
            <div className={`flex min-w-[112px] flex-col items-center gap-1.5 ${dim}`}>
              <div
                className={`relative flex h-14 w-14 items-center justify-center rounded-full border-2 ${cfg.border} ${cfg.bg}`}
              >
                <span className={`font-mono text-xl font-extrabold ${cfg.text}`}>
                  {wave.itemCount}
                </span>
                <span className={`absolute -right-1 -top-1 rounded-full border border-[#0C1117] bg-[#11171E] p-1 ${cfg.text}`}>
                  <Icon name={cfg.icon} size={11} />
                </span>
              </div>
              <span className="text-center font-mono text-[10px] font-semibold uppercase tracking-wide text-slate-400">
                {cfg.short}
              </span>
              <span className={`rounded px-1.5 py-0.5 text-[9px] font-mono ${cfg.bg} ${cfg.text}`}>
                {cfg.timeframe}
              </span>
            </div>

            {index < waves.length - 1 ? (
              <div className="flex items-center pt-5 text-slate-600">
                <div className="h-px w-5 bg-[#2A3543]" />
                <Icon name="chevron-right" size={16} />
              </div>
            ) : null}
          </React.Fragment>
        );
      })}
    </div>
  </div>
);

/* ── Single roadmap item (with rank badge) ────────────────────────────── */

const ItemRow: React.FC<{ item: RoadmapItem; rank: number; accentDot: string; accentText: string }> = ({
  item,
  rank,
  accentDot,
  accentText,
}) => (
  <Link
    to={`/findings/${item.findingId}`}
    className="group block rounded-lg border border-[#222B35] bg-[#0C1117] p-4 transition-all hover:border-[#7DB7E8]/50 hover:bg-[#0E141C]"
  >
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div className="flex items-center gap-2.5 font-mono text-sm">
        {/* (3) Rank badge */}
        <span
          className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-[#222B35] bg-[#11171E] text-[10px] font-bold ${accentText}`}
          title="Priority rank within this wave"
        >
          {rank}
        </span>
        <span className={`h-2 w-2 shrink-0 rounded-full ${accentDot}`} />
        <span className="font-bold text-slate-200">{item.currentAlgorithm}</span>
        <Icon name="arrow-right" size={15} className="text-[#7DB7E8]" />
        <span className="font-bold text-[#7DB7E8]">{item.targetAlgorithm}</span>
        {item.parameterSet ? (
          <span className="text-[11px] text-slate-500">({item.parameterSet})</span>
        ) : null}
      </div>

      <div className="flex items-center gap-2 text-[11px] font-mono">
        {item.criticality ? (
          <span className="rounded border border-[#222B35] bg-[#11171E] px-2 py-0.5 text-slate-400 capitalize">
            {item.criticality}
          </span>
        ) : null}
        <span className={`rounded border px-2 py-0.5 ${effortBadge(item.effort)}`}>
          {item.effort} effort
        </span>
        <span className="rounded border border-[#222B35] bg-[#11171E] px-2 py-0.5 text-slate-400">
          cost <span className={costColor(item.costBand)}>{item.costBand}</span>
        </span>
      </div>
    </div>

    <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-slate-500">
      <span className="flex items-center gap-1 font-mono">
        <Icon name="file-code" size={12} />
        {item.filePath}
        {item.lineNumber != null ? `:${item.lineNumber}` : ''}
      </span>
      {item.blastRadius > 1 ? (
        <span className="rounded bg-slate-800 px-1.5 py-0.5" title="Other crypto usages in the same file">
          blast radius {item.blastRadius}
        </span>
      ) : null}
      <span className="rounded bg-slate-800 px-1.5 py-0.5" title="Priority = risk tier x100 + criticality x10 + blast radius">
        priority {item.priorityScore}
      </span>
    </div>

    <div className="mt-2 flex items-start justify-between gap-3">
      <p className="text-xs leading-relaxed text-slate-400">{item.rationale}</p>
      <span className="flex shrink-0 items-center gap-1 pt-0.5 text-[11px] text-slate-500 group-hover:text-[#7DB7E8]">
        view finding
        <Icon name="arrow-right" size={12} />
      </span>
    </div>
  </Link>
);

/* ── (4,8,9) One wave in the vertical timeline ────────────────────────── */

const TimelineWave: React.FC<{
  wave: MigrationWave;
  isLast: boolean;
  collapsed: boolean;
  onToggle: () => void;
  visible: (item: RoadmapItem) => boolean;
  filtersActive: boolean;
}> = ({ wave, isLast, collapsed, onToggle, visible, filtersActive }) => {
  const cfg = WAVE_CONFIG[wave.key] ?? DEFAULT_CONFIG;
  const empty = wave.itemCount === 0;

  // Preserve true priority rank (index in the full ordered wave) while filtering.
  const ranked = wave.items.map((item, idx) => ({ item, rank: idx + 1 }));
  const shown = ranked.filter((r) => visible(r.item));

  // (4) Wave roll-up: effort breakdown across the full wave.
  const effortCounts = wave.items.reduce(
    (acc, it) => {
      const e = it.effort.toLowerCase();
      if (e === 'high') acc.high += 1;
      else if (e === 'moderate') acc.moderate += 1;
      else if (e === 'low') acc.low += 1;
      return acc;
    },
    { high: 0, moderate: 0, low: 0 },
  );
  const rollupParts: string[] = [];
  if (effortCounts.high) rollupParts.push(`${effortCounts.high} high`);
  if (effortCounts.moderate) rollupParts.push(`${effortCounts.moderate} moderate`);
  if (effortCounts.low) rollupParts.push(`${effortCounts.low} low`);

  return (
    <div className={`relative pl-16 ${empty ? 'opacity-60' : ''}`}>
      {!isLast ? <div className="absolute left-[27px] top-14 bottom-0 w-0.5 bg-[#222B35]" /> : null}

      {/* Numbered node with strategy icon */}
      <div
        className={`absolute left-0 top-0 flex h-14 w-14 flex-col items-center justify-center rounded-full border-2 ${cfg.border} ${cfg.bg}`}
      >
        <span className={`font-mono text-base font-extrabold ${cfg.text}`}>{wave.order}</span>
        <Icon name={cfg.icon} size={11} className={cfg.text} />
      </div>

      {/* (9) Empty wave: slim muted node, no card body */}
      {empty ? (
        <div className="flex h-14 items-center gap-3 rounded-xl border border-dashed border-[#222B35] bg-[#0C1117]/50 px-5">
          <span className={`text-sm font-bold ${cfg.text}`}>{wave.title}</span>
          <span className="text-[11px] text-slate-500">— no assets in this phase</span>
          <span className="ml-auto rounded px-1.5 py-0.5 text-[10px] font-mono text-slate-500">
            {cfg.timeframe}
          </span>
        </div>
      ) : (
        <section className={`rounded-xl border ${cfg.border} bg-[#11171E] shadow-xl`}>
          {/* Header (clickable to collapse) */}
          <button
            onClick={onToggle}
            className="flex w-full flex-wrap items-center gap-3 border-b border-[#222B35] p-5 text-left"
          >
            <h3 className={`text-base font-bold ${cfg.text}`}>{wave.title}</h3>
            <span className={`rounded-full ${cfg.bg} ${cfg.text} px-2 py-0.5 font-mono text-[10px] font-semibold`}>
              {cfg.timeframe}
            </span>
            <span className="rounded-full bg-slate-800 px-2.5 py-0.5 font-mono text-[11px] text-slate-300">
              {filtersActive ? `${shown.length} of ${wave.itemCount}` : `${wave.itemCount}`}{' '}
              {wave.itemCount === 1 ? 'asset' : 'assets'}
            </span>
            {rollupParts.length ? (
              <span className="font-mono text-[11px] text-slate-500">
                effort: {rollupParts.join(' · ')}
              </span>
            ) : null}
            <span className="ml-auto text-slate-500">
              <Icon name={collapsed ? 'chevron-right' : 'chevron-down'} size={16} />
            </span>
          </button>

          {!collapsed ? (
            <div className="p-5">
              <p className="mb-3 text-xs text-slate-400">{wave.description}</p>
              {shown.length ? (
                <div className="card-scroll card-scroll-md space-y-3">
                  {shown.map(({ item, rank }) => (
                    <ItemRow
                      key={item.findingId}
                      item={item}
                      rank={rank}
                      accentDot={cfg.dot}
                      accentText={cfg.text}
                    />
                  ))}
                </div>
              ) : (
                <p className="rounded-lg border border-dashed border-[#222B35] px-4 py-3 text-center text-[11px] text-slate-500">
                  No assets in this wave match the current filters.
                </p>
              )}
            </div>
          ) : null}
        </section>
      )}
    </div>
  );
};

/* ══════════════════════════════════════════════════════════════════════════
   MIGRATION ROADMAP PAGE
   ══════════════════════════════════════════════════════════════════════════ */

export const RoadmapPage: React.FC = () => {
  const [state, setState] = useState<LoadState>({ kind: 'loading' });
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [critFilter, setCritFilter] = useState<CritFilter>('all');
  const [effortFilter, setEffortFilter] = useState<EffortFilter>('all');
  const [overdueOnly, setOverdueOnly] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetchRoadmap()
      .then((roadmap) => {
        if (cancelled) return;
        setState(roadmap.totalItems === 0 ? { kind: 'empty' } : { kind: 'loaded', roadmap });
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        if (err instanceof ApiError && err.status === 404) {
          setState({ kind: 'empty' });
        } else {
          setState({
            kind: 'error',
            message: err instanceof Error ? err.message : 'Failed to load roadmap.',
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const filtersActive = critFilter !== 'all' || effortFilter !== 'all' || overdueOnly;

  const isVisible = useMemo(
    () =>
      (item: RoadmapItem): boolean => {
        if (critFilter !== 'all' && (item.criticality ?? '').toLowerCase() !== critFilter) return false;
        if (effortFilter !== 'all' && item.effort.toLowerCase() !== effortFilter) return false;
        if (overdueOnly && item.riskTier !== 'overdue') return false;
        return true;
      },
    [critFilter, effortFilter, overdueOnly],
  );

  const toggleWave = (key: string) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const handlePrint = () => window.print();

  const handleCsv = () => {
    if (state.kind !== 'loaded') return;
    const header = [
      'Wave', 'Rank', 'Current', 'Target', 'ParameterSet', 'RiskTier', 'Criticality',
      'Effort', 'Cost', 'Priority', 'BlastRadius', 'File', 'Line', 'Rationale',
    ];
    const rows: string[][] = [header];
    for (const wave of state.roadmap.waves) {
      wave.items.forEach((it, idx) => {
        rows.push([
          wave.title, String(idx + 1), it.currentAlgorithm, it.targetAlgorithm,
          it.parameterSet ?? '', it.riskTier ?? '', it.criticality ?? '', it.effort,
          it.costBand, String(it.priorityScore), String(it.blastRadius), it.filePath,
          it.lineNumber != null ? String(it.lineNumber) : '', it.rationale,
        ]);
      });
    }
    const csv = rows.map((r) => r.map(csvCell).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `blindspot-migration-roadmap-${state.roadmap.scanId ?? 'scan'}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-100">Migration Roadmap</h1>
        <p className="mt-1 max-w-3xl text-xs text-slate-400">
          A prioritized, costed migration plan — sequenced by quantum urgency, business
          criticality, and change impact. Not just what you have, but what to fix first.
        </p>
      </div>

      {state.kind === 'loading' ? (
        <div className="flex h-64 flex-col items-center justify-center gap-3">
          <Icon name="refresh" size={28} className="animate-spin text-[#7DB7E8]" />
          <span className="font-mono text-xs text-slate-400">Building migration plan…</span>
        </div>
      ) : null}

      {state.kind === 'empty' ? (
        <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-10 text-center">
          <Icon name="target" size={32} className="mx-auto text-slate-600" />
          <h3 className="mt-3 text-base font-bold text-slate-200">No roadmap yet</h3>
          <p className="mt-1 text-xs text-slate-400">
            Run a scan first — the roadmap is built from real findings.
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
            <h3 className="text-sm font-bold text-red-400">Could not load roadmap</h3>
          </div>
          <p className="mt-1 text-xs text-slate-300">{state.message}</p>
        </div>
      ) : null}

      {state.kind === 'loaded' ? (
        <>
          <ExecSummary roadmap={state.roadmap} onPrint={handlePrint} onCsv={handleCsv} />
          <JourneyStrip waves={state.roadmap.waves} />

          {/* (7) Filters + (10) legend */}
          <div className="flex flex-wrap items-center gap-x-5 gap-y-3 rounded-lg border border-[#222B35] bg-[#0C1117] px-4 py-3">
            <div className="flex items-center gap-2">
              <Icon name="filter" size={13} className="text-slate-500" />
              <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                Filter
              </span>
            </div>

            <label className="flex items-center gap-1.5 text-[11px] text-slate-400">
              Criticality
              <select
                value={critFilter}
                onChange={(e) => setCritFilter(e.target.value as CritFilter)}
                className="rounded border border-[#222B35] bg-[#11171E] px-2 py-1 font-mono text-[11px] text-slate-200 focus:border-[#7DB7E8] focus:outline-none"
              >
                <option value="all">all</option>
                <option value="high">high</option>
                <option value="medium">medium</option>
                <option value="low">low</option>
              </select>
            </label>

            <label className="flex items-center gap-1.5 text-[11px] text-slate-400">
              Effort
              <select
                value={effortFilter}
                onChange={(e) => setEffortFilter(e.target.value as EffortFilter)}
                className="rounded border border-[#222B35] bg-[#11171E] px-2 py-1 font-mono text-[11px] text-slate-200 focus:border-[#7DB7E8] focus:outline-none"
              >
                <option value="all">all</option>
                <option value="high">high</option>
                <option value="moderate">moderate</option>
                <option value="low">low</option>
              </select>
            </label>

            <button
              onClick={() => setOverdueOnly((v) => !v)}
              className={`rounded border px-2.5 py-1 font-mono text-[11px] transition-colors ${
                overdueOnly
                  ? 'border-red-500/40 bg-red-500/10 text-red-400'
                  : 'border-[#222B35] bg-[#11171E] text-slate-400 hover:text-slate-200'
              }`}
            >
              Overdue only
            </button>

            {filtersActive ? (
              <button
                onClick={() => {
                  setCritFilter('all');
                  setEffortFilter('all');
                  setOverdueOnly(false);
                }}
                className="rounded border border-[#222B35] bg-[#11171E] px-2.5 py-1 font-mono text-[11px] text-slate-400 hover:text-slate-200"
              >
                Clear
              </button>
            ) : null}

            {/* (10) Legend */}
            <div className="ml-auto flex items-center gap-3 font-mono text-[10px] text-slate-500">
              <span>effort/cost:</span>
              <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-emerald-500" /> low</span>
              <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-amber-500" /> moderate/med</span>
              <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-red-500" /> high</span>
            </div>
          </div>

          {/* Timeline — all waves, including empty ones */}
          <div className="space-y-6 pt-1">
            {state.roadmap.waves.map((wave, i) => (
              <TimelineWave
                key={wave.key}
                wave={wave}
                isLast={i === state.roadmap.waves.length - 1}
                collapsed={collapsed.has(wave.key)}
                onToggle={() => toggleWave(wave.key)}
                visible={isVisible}
                filtersActive={filtersActive}
              />
            ))}
          </div>

          <p className="text-center font-mono text-[11px] text-slate-500">
            {state.roadmap.totalItems} assets planned · priority = risk tier x100 + criticality
            x10 + blast radius · deterministic
          </p>
        </>
      ) : null}
    </div>
  );
};
