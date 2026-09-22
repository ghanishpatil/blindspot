import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { Icon } from '@/components/Icon';
import { listScans, type ScanSummaryRow } from '@/services/scansApi';

interface BackendScanHistoryProps {
  projectId?: string;
  /** Max rows to render. Deeper history is available by scrolling / drilling. */
  limit?: number;
}

type State =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ok'; scans: ScanSummaryRow[] };

/**
 * Server-persisted scan list, read from `GET /api/scans`.
 *
 * This is the honest source-of-truth history: every scan the local mirror
 * knows about, newest first, surviving backend restarts. Complements the
 * localStorage-backed :class:`ScanHistory` (which is scoped to *this*
 * browser session). Both are honest -- they answer different questions.
 */
export function BackendScanHistory({ projectId, limit = 10 }: BackendScanHistoryProps) {
  const [state, setState] = useState<State>({ kind: 'loading' });
  const navigate = useNavigate();

  useEffect(() => {
    const controller = new AbortController();
    listScans({ projectId, signal: controller.signal })
      .then((res) => setState({ kind: 'ok', scans: res.scans.slice(0, limit) }))
      .catch((err: unknown) => {
        if (controller.signal.aborted) {
          return;
        }
        setState({
          kind: 'error',
          message: err instanceof Error ? err.message : 'Unable to load history.',
        });
      });
    return () => controller.abort();
  }, [projectId, limit]);

  return (
    <section className="surface-panel p-6" data-testid="backend-scan-history">
      <header className="mb-4 flex flex-wrap items-baseline justify-between gap-3">
        <div>
          <div className="eyebrow">Server history</div>
          <h2 className="mt-1 text-lg font-semibold text-[color:var(--color-ink)]">
            Scans on disk
          </h2>
          <p className="mt-1 max-w-2xl text-[11px] text-[color:var(--color-ink-muted)]">
            Every scan mirrored to <span className="font-mono">artifacts/</span> on the
            backend. Survives restart. Same data judges get from{' '}
            <span className="font-mono">GET /api/scans</span>.
          </p>
        </div>
        {state.kind === 'ok' ? (
          <span className="rounded border border-[color:var(--color-border-subtle)] bg-[color:var(--color-panel)] px-2 py-0.5 font-mono text-[10px] uppercase tracking-widest text-[color:var(--color-ink-muted)]">
            {state.scans.length} row{state.scans.length === 1 ? '' : 's'}
          </span>
        ) : null}
      </header>

      {state.kind === 'loading' ? (
        <div className="flex items-center gap-2 py-6 text-[11px] text-[color:var(--color-ink-muted)]">
          <Icon name="refresh" size={14} className="animate-spin" />
          Loading history…
        </div>
      ) : null}

      {state.kind === 'error' ? (
        <div className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-[11px] text-amber-200">
          <Icon name="alert-triangle" size={13} className="mt-0.5 shrink-0" />
          <div>
            <p className="font-semibold text-amber-100">Server history unavailable.</p>
            <p className="mt-0.5 text-amber-200/80">{state.message}</p>
          </div>
        </div>
      ) : null}

      {state.kind === 'ok' && state.scans.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-[color:var(--color-border-subtle)] py-8 text-center text-[11px] text-[color:var(--color-ink-muted)]">
          <Icon name="database" size={18} className="text-slate-500" />
          <p>
            No scans on disk yet. Run one from{' '}
            <span className="font-mono text-[color:var(--color-accent)]">Scanner</span> and
            it appears here.
          </p>
        </div>
      ) : null}

      {state.kind === 'ok' && state.scans.length > 0 ? (
        <div className="overflow-x-auto rounded-md border border-[color:var(--color-border-subtle)]">
          <table className="w-full text-left text-xs">
            <thead className="bg-[color:var(--color-panel)] font-mono text-[10px] uppercase tracking-widest text-[color:var(--color-ink-muted)]">
              <tr>
                <th className="px-3 py-2 font-medium">Scan</th>
                <th className="px-3 py-2 font-medium">Project</th>
                <th className="px-3 py-2 font-medium">When</th>
                <th className="px-3 py-2 text-right font-medium">Findings</th>
                <th className="px-3 py-2 text-right font-medium">Overdue</th>
                <th className="px-3 py-2 text-right font-medium">Weak now</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[color:var(--color-border-subtle)]">
              {state.scans.map((row) => (
                <tr
                  key={row.scanId ?? row.startedAt ?? Math.random()}
                  className="cursor-pointer transition-colors hover:bg-[color:var(--color-panel)]"
                  onClick={() => navigate('/findings')}
                >
                  <td className="px-3 py-2 font-mono text-[color:var(--color-ink)]">
                    {row.scanId ?? '—'}
                  </td>
                  <td className="px-3 py-2 font-mono text-[color:var(--color-ink-muted)]">
                    {row.projectId ?? '—'}
                  </td>
                  <td className="px-3 py-2 font-mono text-[color:var(--color-ink-muted)]">
                    {formatWhen(row.startedAt)}
                  </td>
                  <td className="px-3 py-2 text-right font-mono text-[color:var(--color-ink)]">
                    {row.findingCount}
                  </td>
                  <td
                    className={`px-3 py-2 text-right font-mono ${
                      row.summary.overdue > 0 ? 'text-red-400' : 'text-[color:var(--color-ink-muted)]'
                    }`}
                  >
                    {row.summary.overdue}
                  </td>
                  <td
                    className={`px-3 py-2 text-right font-mono ${
                      row.summary.currentWeakCrypto > 0
                        ? 'text-red-400'
                        : 'text-[color:var(--color-ink-muted)]'
                    }`}
                  >
                    {row.summary.currentWeakCrypto}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}

function formatWhen(iso: string | null): string {
  if (!iso) return '—';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString();
}
