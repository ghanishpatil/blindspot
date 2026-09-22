import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import { Icon } from '@/components/Icon';
import { fetchRoadmap } from '@/services/api';
import type { MigrationRoadmap, MigrationWave, RoadmapItem } from '@/types';

type State =
  | { kind: 'loading' }
  | { kind: 'empty' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; roadmap: MigrationRoadmap };

/**
 * Dashboard-scoped wave-plan summary.
 *
 * The full roadmap surface lives on ``/roadmap`` and the executive
 * PDF report reproduces it in section 4. This card is the *dashboard*
 * variant: one compact row per wave, showing wave order, strategy,
 * item count, and an aggregate effort snapshot. Clicking through
 * jumps to the full roadmap page.
 *
 * Silent when no scan exists yet; falls back to an empty state prompt.
 */
export function WavePlanCard() {
  const [state, setState] = useState<State>({ kind: 'loading' });

  useEffect(() => {
    let cancelled = false;
    fetchRoadmap()
      .then((roadmap) => {
        if (cancelled) return;
        if (!roadmap.waves || roadmap.waves.length === 0) {
          setState({ kind: 'empty' });
          return;
        }
        setState({ kind: 'ready', roadmap });
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setState({
          kind: 'error',
          message:
            err instanceof Error ? err.message : 'Unable to load roadmap.',
        });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <section className="surface-panel p-6" data-testid="wave-plan-card">
      <header className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="eyebrow">Migration wave plan</div>
          <h2 className="mt-1 text-lg font-semibold text-[color:var(--color-ink)]">
            The migration, one wave at a time
          </h2>
          <p className="mt-1 max-w-2xl text-[11px] text-[color:var(--color-ink-muted)]">
            Findings grouped by strategy (REMEDIATE_NOW → PQC → HYBRID →
            INVESTIGATE → DEFER) and ordered by Mosca risk. Same waves
            appear in section 4 of the executive PDF.
          </p>
        </div>
        <Link
          to="/roadmap"
          className="inline-flex items-center gap-2 rounded-md border border-[color:var(--color-border-subtle)] px-3 py-1.5 text-[11px] font-semibold text-[color:var(--color-ink-muted)] hover:text-[color:var(--color-ink)]"
          data-testid="wave-plan-view-full"
        >
          Full roadmap <Icon name="arrow-right" size={12} />
        </Link>
      </header>

      {state.kind === 'loading' ? (
        <p className="flex items-center gap-2 py-4 text-[11px] text-[color:var(--color-ink-muted)]">
          <Icon name="refresh" size={14} className="animate-spin" />
          Loading roadmap…
        </p>
      ) : null}

      {state.kind === 'empty' ? (
        <div
          className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-[color:var(--color-border-subtle)] py-8 text-center text-[11px] text-[color:var(--color-ink-muted)]"
          data-testid="wave-plan-empty"
        >
          <Icon name="target" size={18} className="text-slate-500" />
          <p>No roadmap yet. Run a scan to build a wave-by-wave plan.</p>
        </div>
      ) : null}

      {state.kind === 'error' ? (
        <p className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-[11px] text-red-300">
          {state.message}
        </p>
      ) : null}

      {state.kind === 'ready' ? (
        <div className="overflow-hidden rounded-md border border-[color:var(--color-border-subtle)]">
          <table className="w-full text-left text-[11px]">
            <thead className="bg-[color:var(--color-canvas-deep)] text-[10px] uppercase tracking-widest text-[color:var(--color-ink-muted)]">
              <tr>
                <th className="px-3 py-2">Wave</th>
                <th className="px-3 py-2">Strategy</th>
                <th className="px-3 py-2">Items</th>
                <th className="px-3 py-2">Effort</th>
                <th className="px-3 py-2">Focus</th>
              </tr>
            </thead>
            <tbody data-testid="wave-plan-tbody">
              {state.roadmap.waves.map((wave) => (
                <WaveRow key={wave.key} wave={wave} />
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Row
// ---------------------------------------------------------------------------

const WaveRow: React.FC<{ wave: MigrationWave }> = ({ wave }) => {
  const effort = _summariseEffort(wave.items);
  return (
    <tr
      className="border-t border-[color:var(--color-border-subtle)]"
      data-testid={`wave-row-${wave.order}`}
    >
      <td className="px-3 py-2 font-mono text-[color:var(--color-ink)]">
        {wave.order}
      </td>
      <td className="px-3 py-2">
        <span
          className={`inline-flex rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-widest ${_strategyTone(
            wave.strategy,
          )}`}
        >
          {wave.strategy}
        </span>
      </td>
      <td className="px-3 py-2 font-mono">{wave.itemCount}</td>
      <td className="px-3 py-2 text-[color:var(--color-ink-muted)]">
        {effort}
      </td>
      <td className="px-3 py-2 text-[color:var(--color-ink-muted)]">
        {_focusLine(wave)}
      </td>
    </tr>
  );
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Roll up the per-item effort field into a per-wave summary. */
function _summariseEffort(items: RoadmapItem[]): string {
  if (items.length === 0) return '—';
  const counts: Record<string, number> = {};
  for (const it of items) {
    const key = String((it as { effort?: string }).effort ?? 'unspecified');
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return Object.entries(counts)
    .map(([k, v]) => `${v} × ${k}`)
    .join(', ');
}

function _focusLine(wave: MigrationWave): string {
  const first = wave.items[0];
  if (!first) return wave.description;
  const target = (first as { targetAlgorithm?: string }).targetAlgorithm;
  if (!target) return wave.description;
  return `${wave.items.length === 1 ? '' : `${wave.items.length} findings · `}${target}${wave.items.length > 1 ? ' + others' : ''}`;
}

function _strategyTone(strategy: string): string {
  switch (strategy) {
    case 'REMEDIATE_NOW':
      return 'bg-red-500/20 text-red-200';
    case 'PQC':
      return 'bg-purple-500/20 text-purple-200';
    case 'HYBRID':
      return 'bg-blue-500/20 text-blue-200';
    case 'INVESTIGATE':
      return 'bg-amber-500/20 text-amber-200';
    case 'DEFER':
      return 'bg-slate-500/20 text-slate-300';
    default:
      return 'bg-slate-500/20 text-slate-300';
  }
}
