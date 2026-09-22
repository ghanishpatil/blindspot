import { useEffect, useMemo, useState } from 'react';

import { DetectionSourceBadge } from '@/components/DetectionSourceBadge';
import { Icon } from '@/components/Icon';
import { RiskChip } from '@/design';
import {
  getScanDiff,
  listScans,
  type DiffRow,
  type ScanDiffResponse,
  type ScanSummaryRow,
} from '@/services/scansApi';
import type { RiskTier } from '@/types';

interface DiffPanelProps {
  projectId?: string;
}

type State =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; scans: ScanSummaryRow[] };

type DiffState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ok'; diff: ScanDiffResponse };

/**
 * Two-scan diff surface.
 *
 * Loads the scan list once, lets the user pick a base + head, then
 * calls ``GET /api/scans/diff`` and renders the three buckets (added /
 * removed / changed) plus the signed summary delta. Restart-safe --
 * data comes off the on-disk artefact mirror, not from any in-memory
 * cache.
 *
 * The delta chip in the header is the single most valuable number for
 * a demo: a negative overdue delta means "the migration progressed";
 * a positive one means "a PR introduced new quantum-vulnerable
 * cryptography" -- the shift-left regression signal.
 */
export function DiffPanel({ projectId }: DiffPanelProps) {
  const [scans, setScans] = useState<State>({ kind: 'loading' });
  const [base, setBase] = useState<string>('');
  const [head, setHead] = useState<string>('');
  const [diff, setDiff] = useState<DiffState>({ kind: 'idle' });

  useEffect(() => {
    const controller = new AbortController();
    listScans({ projectId, signal: controller.signal })
      .then((res) => {
        setScans({ kind: 'ready', scans: res.scans });
        // Pre-fill: head = newest, base = second-newest -- the most
        // common "did my migration actually reduce overdue?" comparison.
        if (res.scans.length >= 2) {
          setHead(res.scans[0].scanId ?? '');
          setBase(res.scans[1].scanId ?? '');
        }
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) return;
        setScans({
          kind: 'error',
          message: err instanceof Error ? err.message : 'Unable to load scans.',
        });
      });
    return () => controller.abort();
  }, [projectId]);

  const canCompare = useMemo(
    () => Boolean(base && head && base !== head),
    [base, head],
  );

  async function runCompare() {
    if (!canCompare) return;
    setDiff({ kind: 'loading' });
    try {
      const result = await getScanDiff(base, head);
      setDiff({ kind: 'ok', diff: result });
    } catch (err: unknown) {
      setDiff({
        kind: 'error',
        message: err instanceof Error ? err.message : 'Diff failed.',
      });
    }
  }

  return (
    <section className="surface-panel p-6" data-testid="diff-panel">
      <header className="mb-4">
        <div className="eyebrow">Cross-scan diff</div>
        <h2 className="mt-1 text-lg font-semibold text-[color:var(--color-ink)]">
          Compare two scans
        </h2>
        <p className="mt-1 max-w-2xl text-[11px] text-[color:var(--color-ink-muted)]">
          Pick a base and a head scan. Negative overdue delta means the
          migration progressed; positive means a regression -- new
          quantum-vulnerable crypto entered the codebase.
        </p>
      </header>

      {scans.kind === 'loading' ? (
        <div className="flex items-center gap-2 py-4 text-[11px] text-[color:var(--color-ink-muted)]">
          <Icon name="refresh" size={14} className="animate-spin" />
          Loading scans…
        </div>
      ) : null}

      {scans.kind === 'error' ? (
        <div className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-[11px] text-amber-200">
          <Icon name="alert-triangle" size={13} className="mt-0.5 shrink-0" />
          <div>
            <p className="font-semibold text-amber-100">Cannot load scan list.</p>
            <p className="mt-0.5 text-amber-200/80">{scans.message}</p>
          </div>
        </div>
      ) : null}

      {scans.kind === 'ready' && scans.scans.length < 2 ? (
        <div className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-[color:var(--color-border-subtle)] py-8 text-center text-[11px] text-[color:var(--color-ink-muted)]" data-testid="diff-empty">
          <Icon name="barchart" size={18} className="text-slate-500" />
          <p>Diffing needs at least two scans on disk. Run another scan and this panel activates.</p>
          <span className="font-mono text-[10px] uppercase tracking-widest text-[color:var(--color-ink-faint)]">
            {scans.scans.length} of &ge; 2 scans
          </span>
        </div>
      ) : null}

      {scans.kind === 'ready' && scans.scans.length >= 2 ? (
        <>
          <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] sm:items-end">
            <ScanSelector
              label="Base (older / reference)"
              value={base}
              onChange={setBase}
              scans={scans.scans}
              testid="diff-base-select"
            />
            <ScanSelector
              label="Head (newer / candidate)"
              value={head}
              onChange={setHead}
              scans={scans.scans}
              testid="diff-head-select"
            />
            <button
              type="button"
              onClick={() => void runCompare()}
              disabled={!canCompare || diff.kind === 'loading'}
              className="inline-flex items-center gap-2 rounded-md bg-[color:var(--color-accent)] px-4 py-2 text-sm font-semibold text-[color:var(--color-canvas)] transition-colors hover:bg-[color:var(--color-accent-strong)] disabled:opacity-50"
              data-testid="diff-run-button"
            >
              <Icon name="filter" size={14} />
              Compare
            </button>
          </div>

          {!canCompare && base && head ? (
            <p className="mt-2 text-[11px] text-amber-300">
              Base and head must be different scans.
            </p>
          ) : null}

          {diff.kind === 'loading' ? (
            <div className="mt-4 flex items-center gap-2 text-[11px] text-[color:var(--color-ink-muted)]">
              <Icon name="refresh" size={14} className="animate-spin" />
              Running diff…
            </div>
          ) : null}

          {diff.kind === 'error' ? (
            <p className="mt-4 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-[11px] text-red-300">
              {diff.message}
            </p>
          ) : null}

          {diff.kind === 'ok' ? (
            <div className="mt-6 space-y-6" data-testid="diff-result">
              <DeltaHeader diff={diff.diff} />
              <DiffBucket
                title="Changed tier"
                rows={diff.diff.changed}
                emptyLabel="No findings changed tier between these scans."
                variant="changed"
                testid="diff-changed"
              />
              <DiffBucket
                title="Added"
                rows={diff.diff.added}
                emptyLabel="No new findings introduced."
                variant="added"
                testid="diff-added"
              />
              <DiffBucket
                title="Removed"
                rows={diff.diff.removed}
                emptyLabel="No findings removed."
                variant="removed"
                testid="diff-removed"
              />
              <p className="text-[11px] text-[color:var(--color-ink-muted)]">
                <span className="font-mono">{diff.diff.unchangedCount}</span> finding
                {diff.diff.unchangedCount === 1 ? '' : 's'} unchanged (same tier in both scans).
              </p>
            </div>
          ) : null}
        </>
      ) : null}
    </section>
  );
}


// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

const ScanSelector: React.FC<{
  label: string;
  value: string;
  onChange: (v: string) => void;
  scans: ScanSummaryRow[];
  testid: string;
}> = ({ label, value, onChange, scans, testid }) => (
  <label className="block">
    <span className="eyebrow-muted">{label}</span>
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      data-testid={testid}
      className="mt-1 w-full rounded-md border border-[color:var(--color-border-subtle)] bg-[color:var(--color-canvas)] px-3 py-2 font-mono text-xs text-[color:var(--color-ink)] focus:border-[color:var(--color-accent)] focus:outline-none"
    >
      <option value="">— select a scan —</option>
      {scans.map((s) => (
        <option key={s.scanId ?? ''} value={s.scanId ?? ''}>
          {formatOption(s)}
        </option>
      ))}
    </select>
  </label>
);

const DeltaHeader: React.FC<{ diff: ScanDiffResponse }> = ({ diff }) => (
  <div className="rounded-md border border-[color:var(--color-border-subtle)] bg-[color:var(--color-panel)] p-4">
    <div className="mb-2 text-[11px] font-mono uppercase tracking-widest text-[color:var(--color-ink-muted)]">
      Signed delta (head - base)
    </div>
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
      <DeltaChip label="Total"        value={diff.summaryDelta.totalFindings ?? 0} />
      <DeltaChip label="Overdue"      value={diff.summaryDelta.overdue ?? 0}       invertColour />
      <DeltaChip label="Transitional" value={diff.summaryDelta.transitional ?? 0}  invertColour />
      <DeltaChip label="Low-risk"     value={diff.summaryDelta.lowRisk ?? 0} />
      <DeltaChip label="HNDL"         value={diff.summaryDelta.hndlExposed ?? 0}   invertColour />
      <DeltaChip label="Weak-now"     value={diff.summaryDelta.currentWeakCrypto ?? 0} invertColour />
    </div>
  </div>
);

const DeltaChip: React.FC<{
  label: string;
  value: number;
  /** When true, a NEGATIVE delta is 'good' (fewer overdue is good). */
  invertColour?: boolean;
}> = ({ label, value, invertColour }) => {
  let colour = 'text-[color:var(--color-ink)]';
  if (value !== 0) {
    const isGood = invertColour ? value < 0 : value > 0;
    colour = isGood ? 'text-emerald-400' : 'text-red-400';
  }
  const sign = value > 0 ? '+' : '';
  return (
    <div>
      <div className="text-[10px] uppercase tracking-widest text-[color:var(--color-ink-muted)]">
        {label}
      </div>
      <div className={`mt-0.5 font-mono text-lg font-bold ${colour}`}>
        {sign}
        {value}
      </div>
    </div>
  );
};

/**
 * DiffBucket
 *
 * UX rule: each bucket's table scrolls INSIDE its own bounded region.
 * A 300-row Added list on a big migration must not push the Changed
 * / Removed buckets off the page. The whole page's scroll should
 * stay predictable no matter how big the diff is.
 *
 * Additional affordance: click the bucket header to collapse it
 * entirely. Auto-collapse kicks in once a bucket exceeds
 * ``AUTO_COLLAPSE_THRESHOLD`` rows so the panel opens compact by
 * default on huge diffs; the user always sees the count badge.
 */
const AUTO_COLLAPSE_THRESHOLD = 25;

const DiffBucket: React.FC<{
  title: string;
  rows: DiffRow[];
  emptyLabel: string;
  variant: 'added' | 'removed' | 'changed';
  testid: string;
}> = ({ title, rows, emptyLabel, variant, testid }) => {
  const badge =
    variant === 'added'
      ? { text: `+${rows.length}`, tone: 'text-emerald-300 border-emerald-500/40 bg-emerald-500/10' }
      : variant === 'removed'
        ? { text: `-${rows.length}`, tone: 'text-red-300 border-red-500/40 bg-red-500/10' }
        : { text: `${rows.length}`, tone: 'text-amber-300 border-amber-500/40 bg-amber-500/10' };

  // Auto-collapse huge buckets on first render, but respect the user's
  // subsequent choice. useState's lazy initialiser fires once per row-set.
  const [collapsed, setCollapsed] = useState(
    () => rows.length > AUTO_COLLAPSE_THRESHOLD,
  );

  const hasRows = rows.length > 0;

  return (
    <div data-testid={testid}>
      <button
        type="button"
        onClick={() => setCollapsed((c) => !c)}
        disabled={!hasRows}
        className="mb-2 flex w-full items-center gap-2 rounded-md py-0.5 text-left disabled:cursor-default"
        aria-expanded={hasRows ? !collapsed : undefined}
        data-testid={`${testid}-toggle`}
      >
        {hasRows ? (
          <Icon
            name={collapsed ? 'chevron-right' : 'chevron-down'}
            size={13}
            className="text-[color:var(--color-ink-muted)]"
          />
        ) : (
          <span className="inline-block w-[13px]" />
        )}
        <h3 className="text-sm font-semibold text-[color:var(--color-ink)]">{title}</h3>
        <span
          className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-widest ${badge.tone}`}
        >
          {badge.text}
        </span>
        {hasRows && collapsed ? (
          <span className="ml-auto text-[10px] uppercase tracking-widest text-[color:var(--color-ink-faint)]">
            click to expand
          </span>
        ) : null}
      </button>
      {!hasRows ? (
        <p className="text-[11px] text-[color:var(--color-ink-muted)]">{emptyLabel}</p>
      ) : collapsed ? null : (
        <div
          className="max-h-[320px] overflow-auto rounded-md border border-[color:var(--color-border-subtle)]"
          data-testid={`${testid}-scroller`}
        >
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 z-10 bg-[color:var(--color-panel)] font-mono text-[10px] uppercase tracking-widest text-[color:var(--color-ink-muted)] shadow-[0_1px_0_var(--color-border-subtle)]">
              <tr>
                <th className="px-3 py-2 font-medium">Algorithm</th>
                <th className="px-3 py-2 font-medium">Source</th>
                <th className="px-3 py-2 font-medium">Location</th>
                <th className="px-3 py-2 font-medium">
                  {variant === 'changed' ? 'Tier change' : 'Tier'}
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[color:var(--color-border-subtle)]">
              {rows.map((row) => (
                <tr key={`${variant}-${row.id ?? row.algorithm}-${row.filePath}`}>
                  <td className="px-3 py-2 font-mono text-[color:var(--color-ink)]">
                    {row.displayName ?? row.algorithm ?? '—'}
                  </td>
                  <td className="px-3 py-2">
                    <DetectionSourceBadge method={row.detectionMethod} size="sm" />
                  </td>
                  <td className="px-3 py-2 font-mono text-[color:var(--color-ink-muted)]">
                    {row.filePath}
                    {row.lineNumber != null ? `:${row.lineNumber}` : ''}
                  </td>
                  <td className="px-3 py-2">
                    {variant === 'changed' ? (
                      <span className="inline-flex items-center gap-1.5 font-mono text-[11px]">
                        <RiskChip tier={(row.previousTier ?? null) as RiskTier | null} size="sm" />
                        <Icon name="chevron-right" size={12} className="text-slate-500" />
                        <RiskChip tier={(row.currentTier ?? null) as RiskTier | null} size="sm" />
                      </span>
                    ) : (
                      <RiskChip tier={(row.riskTier ?? null) as RiskTier | null} size="sm" />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};


function formatOption(row: ScanSummaryRow): string {
  const when = row.startedAt
    ? new Date(row.startedAt).toLocaleString()
    : '(unknown time)';
  return `${row.scanId ?? '?'} · ${when} · ${row.findingCount} findings`;
}
