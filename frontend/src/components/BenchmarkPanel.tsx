import { useEffect, useState } from 'react';

import { Icon } from '@/components/Icon';
import {
  getLatestBenchmark,
  runBenchmark,
  type BenchmarkReport,
} from '@/services/benchmarkApi';

type LoadState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'empty' } // no cached report yet
  | { kind: 'error'; message: string }
  | { kind: 'ready'; report: BenchmarkReport };

type RunState =
  | { kind: 'idle' }
  | { kind: 'running' }
  | { kind: 'error'; message: string };

/**
 * Benchmark harness surface.
 *
 * Renders the last precision / recall / F1 score for the bundled
 * ground-truth dataset and lets an operator re-run the harness on
 * demand. Every number comes from ``/api/benchmark/latest`` (or the
 * fresh POST /run) -- nothing is faked. When no cached run exists
 * the panel offers a "run now" button instead of an empty gauge.
 *
 * The per-category rollup exposes where the scanner is strongest and
 * where it misses -- honest, and directly actionable (which rules
 * need tuning next).
 */
export function BenchmarkPanel() {
  const [state, setState] = useState<LoadState>({ kind: 'idle' });
  const [run, setRun] = useState<RunState>({ kind: 'idle' });

  useEffect(() => {
    const controller = new AbortController();
    setState({ kind: 'loading' });
    getLatestBenchmark(controller.signal)
      .then((report) => {
        if (controller.signal.aborted) return;
        setState(report === null ? { kind: 'empty' } : { kind: 'ready', report });
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) return;
        setState({
          kind: 'error',
          message: err instanceof Error ? err.message : 'Unable to load benchmark.',
        });
      });
    return () => controller.abort();
  }, []);

  async function onRun() {
    setRun({ kind: 'running' });
    try {
      const report = await runBenchmark();
      setState({ kind: 'ready', report });
      setRun({ kind: 'idle' });
    } catch (err: unknown) {
      setRun({
        kind: 'error',
        message: err instanceof Error ? err.message : 'Benchmark failed.',
      });
    }
  }

  return (
    <section className="surface-panel p-6" data-testid="benchmark-panel">
      <header className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="eyebrow">Benchmark harness</div>
          <h2 className="mt-1 text-lg font-semibold text-[color:var(--color-ink)]">
            Precision · Recall · F1
          </h2>
          <p className="mt-1 max-w-2xl text-[11px] text-[color:var(--color-ink-muted)]">
            Runs the bundled labelled corpus through the same pipeline
            production uses, then scores every case: TP, FP, FN, TN.
            No numbers are fabricated -- every metric traces back to a
            case row you can inspect.
          </p>
        </div>
        <button
          type="button"
          onClick={() => void onRun()}
          disabled={run.kind === 'running'}
          className="inline-flex items-center gap-2 rounded-md bg-[color:var(--color-accent)] px-4 py-2 text-sm font-semibold text-[color:var(--color-canvas)] transition-colors hover:bg-[color:var(--color-accent-strong)] disabled:opacity-50"
          data-testid="benchmark-run-button"
        >
          <Icon
            name={run.kind === 'running' ? 'refresh' : 'play'}
            size={14}
            className={run.kind === 'running' ? 'animate-spin' : ''}
          />
          {run.kind === 'running' ? 'Running…' : 'Run benchmark'}
        </button>
      </header>

      {state.kind === 'loading' ? (
        <div className="flex items-center gap-2 py-4 text-[11px] text-[color:var(--color-ink-muted)]">
          <Icon name="refresh" size={14} className="animate-spin" />
          Loading latest benchmark…
        </div>
      ) : null}

      {state.kind === 'error' ? (
        <p className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-[11px] text-red-300">
          {state.message}
        </p>
      ) : null}

      {state.kind === 'empty' ? (
        <div
          className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-[color:var(--color-border-subtle)] py-8 text-center text-[11px] text-[color:var(--color-ink-muted)]"
          data-testid="benchmark-empty"
        >
          <Icon name="barchart" size={18} className="text-slate-500" />
          <p>No benchmark has run yet. Click "Run benchmark" to score the pipeline against the bundled dataset.</p>
        </div>
      ) : null}

      {run.kind === 'error' ? (
        <p
          className="mt-3 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-[11px] text-red-300"
          data-testid="benchmark-run-error"
        >
          {run.message}
        </p>
      ) : null}

      {state.kind === 'ready' ? (
        <BenchmarkResult report={state.report} />
      ) : null}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Result rendering
// ---------------------------------------------------------------------------

const BenchmarkResult: React.FC<{ report: BenchmarkReport }> = ({ report }) => {
  const o = report.overall;
  return (
    <div className="space-y-5" data-testid="benchmark-result">
      <div className="grid gap-3 sm:grid-cols-4">
        <ScoreCard label="Precision" value={o.precision} />
        <ScoreCard label="Recall" value={o.recall} />
        <ScoreCard label="F1" value={o.f1} />
        <ScoreCard label="Accuracy" value={o.accuracy} />
      </div>

      <div className="grid gap-3 sm:grid-cols-4 text-[11px]">
        <CountCard label="True positives" value={o.tp} tone="ok" />
        <CountCard label="False positives" value={o.fp} tone="warn" />
        <CountCard label="False negatives" value={o.fn} tone="danger" />
        <CountCard label="True negatives" value={o.tn} tone="ok" />
      </div>

      <p className="text-[11px] text-[color:var(--color-ink-muted)]">
        Dataset: <code className="text-[color:var(--color-ink)]">{report.datasetName}</code>{' '}
        · {report.totalCases} cases · scored in {report.elapsedSeconds.toFixed(2)} s
        · pipeline {report.pipelineVersion} · generated{' '}
        <time dateTime={report.generatedAt}>{formatDate(report.generatedAt)}</time>
      </p>

      <div>
        <h3 className="text-sm font-semibold text-[color:var(--color-ink)]">
          Per-category rollup
        </h3>
        <div className="mt-2 max-h-[280px] overflow-auto rounded-md border border-[color:var(--color-border-subtle)]">
          <table className="w-full text-left text-[11px]">
            <thead className="bg-[color:var(--color-canvas-deep)] text-[10px] uppercase tracking-widest text-[color:var(--color-ink-muted)]">
              <tr>
                <th className="px-3 py-2">Category</th>
                <th className="px-3 py-2">Cases</th>
                <th className="px-3 py-2">TP</th>
                <th className="px-3 py-2">FP</th>
                <th className="px-3 py-2">FN</th>
                <th className="px-3 py-2">TN</th>
                <th className="px-3 py-2">F1</th>
              </tr>
            </thead>
            <tbody data-testid="benchmark-categories-tbody">
              {Object.entries(report.categories).map(([name, cat]) => (
                <tr key={name} className="border-t border-[color:var(--color-border-subtle)]">
                  <td className="px-3 py-2 font-mono text-[color:var(--color-ink)]">
                    {name}
                  </td>
                  <td className="px-3 py-2">{cat.cases}</td>
                  <td className="px-3 py-2 text-emerald-300">{cat.tp}</td>
                  <td className="px-3 py-2 text-amber-300">{cat.fp}</td>
                  <td className="px-3 py-2 text-red-300">{cat.fn}</td>
                  <td className="px-3 py-2 text-emerald-300">{cat.tn}</td>
                  <td className="px-3 py-2 font-mono">{formatFraction(cat.f1)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {report.cases.length > 0 ? (
        <div>
          <h3 className="text-sm font-semibold text-[color:var(--color-ink)]">
            Per-case detail
          </h3>
          <div className="mt-2 max-h-[380px] overflow-auto rounded-md border border-[color:var(--color-border-subtle)]">
            <table className="w-full text-left text-[11px]">
              <thead className="bg-[color:var(--color-canvas-deep)] text-[10px] uppercase tracking-widest text-[color:var(--color-ink-muted)]">
                <tr>
                  <th className="px-3 py-2">Case</th>
                  <th className="px-3 py-2">File</th>
                  <th className="px-3 py-2">Expected</th>
                  <th className="px-3 py-2">Reported</th>
                  <th className="px-3 py-2">TP</th>
                  <th className="px-3 py-2">FP</th>
                  <th className="px-3 py-2">FN</th>
                </tr>
              </thead>
              <tbody data-testid="benchmark-cases-tbody">
                {report.cases.map((c) => (
                  <tr
                    key={c.caseId}
                    className="border-t border-[color:var(--color-border-subtle)]"
                  >
                    <td className="px-3 py-2 font-mono text-[color:var(--color-ink)]">
                      {c.caseId}
                    </td>
                    <td className="px-3 py-2 font-mono text-[10px] text-[color:var(--color-ink-muted)]">
                      {c.file}
                    </td>
                    <td className="px-3 py-2">{c.expectedCount}</td>
                    <td className="px-3 py-2">{c.reportedCount}</td>
                    <td className="px-3 py-2 text-emerald-300">{c.tp}</td>
                    <td className="px-3 py-2 text-amber-300">{c.fp}</td>
                    <td className="px-3 py-2 text-red-300">{c.fn}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Small sub-components
// ---------------------------------------------------------------------------

const ScoreCard: React.FC<{ label: string; value: number }> = ({ label, value }) => (
  <div
    className="rounded-md border border-[color:var(--color-border-subtle)] bg-[color:var(--color-canvas-deep)] p-4"
    data-testid={`benchmark-score-${label.toLowerCase()}`}
  >
    <div className="text-[10px] font-semibold uppercase tracking-widest text-[color:var(--color-ink-muted)]">
      {label}
    </div>
    <div className="mt-1 font-mono text-2xl text-[color:var(--color-ink)]">
      {formatFraction(value)}
    </div>
  </div>
);

const CountCard: React.FC<{
  label: string;
  value: number;
  tone: 'ok' | 'warn' | 'danger';
}> = ({ label, value, tone }) => {
  const cls =
    tone === 'ok'
      ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
      : tone === 'warn'
        ? 'border-amber-500/30 bg-amber-500/10 text-amber-200'
        : 'border-red-500/30 bg-red-500/10 text-red-200';
  return (
    <div className={`rounded-md border p-3 ${cls}`}>
      <div className="text-[9px] font-semibold uppercase tracking-widest opacity-80">
        {label}
      </div>
      <div className="mt-0.5 font-mono text-lg">{value}</div>
    </div>
  );
};

function formatFraction(v: number): string {
  if (!Number.isFinite(v)) return '—';
  return v.toFixed(3);
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}
