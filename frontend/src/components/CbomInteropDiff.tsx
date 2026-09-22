import { useMemo, useState } from 'react';

import { Icon } from '@/components/Icon';
import {
  diffCboms,
  type CbomInteropDiffResponse,
} from '@/services/cbomInteropApi';

type State =
  | { kind: 'idle' }
  | { kind: 'diffing' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; result: CbomInteropDiffResponse };

interface Slot {
  filename: string | null;
  parsed: Record<string, unknown> | null;
  error: string | null;
}

const EMPTY_SLOT: Slot = { filename: null, parsed: null, error: null };

/**
 * CBOM interop-diff panel.
 *
 * Drop two CycloneDX 1.6 CBOM JSON files (one from Blindspot, one
 * from IBM CBOMkit or any other conformant tool). The panel POSTs
 * them to ``/api/cbom/diff`` and renders added / removed / changed
 * crypto assets with the exact fields that drifted.
 *
 * The parse step is client-side (``JSON.parse`` on the file text),
 * so users see "not JSON" or "no crypto components" errors before a
 * network round-trip.
 */
export function CbomInteropDiff() {
  const [base, setBase] = useState<Slot>(EMPTY_SLOT);
  const [head, setHead] = useState<Slot>(EMPTY_SLOT);
  const [state, setState] = useState<State>({ kind: 'idle' });

  const canDiff = useMemo(
    () => Boolean(base.parsed && head.parsed && !base.error && !head.error),
    [base, head],
  );

  async function onDiff() {
    if (!base.parsed || !head.parsed) return;
    setState({ kind: 'diffing' });
    try {
      const result = await diffCboms(base.parsed, head.parsed);
      setState({ kind: 'ready', result });
    } catch (err: unknown) {
      setState({
        kind: 'error',
        message: err instanceof Error ? err.message : 'CBOM diff failed.',
      });
    }
  }

  return (
    <section className="surface-panel p-6" data-testid="cbom-interop-panel">
      <header className="mb-4">
        <div className="eyebrow">CBOM interoperability</div>
        <h2 className="mt-1 text-lg font-semibold text-[color:var(--color-ink)]">
          Diff any two CycloneDX 1.6 CBOMs
        </h2>
        <p className="mt-1 max-w-2xl text-[11px] text-[color:var(--color-ink-muted)]">
          Drop a Blindspot CBOM and one from any other tool (IBM CBOMkit,
          sonatype, …) to compare their crypto-asset inventories side by side.
          Matches by <code>name + primitive</code>; drift is grouped by
          class (algorithm, parameter, curve, mode, tier).
        </p>
      </header>

      <div className="grid gap-3 sm:grid-cols-2">
        <CbomSlot
          label="Base CBOM"
          slot={base}
          onChange={setBase}
          testid="cbom-slot-base"
        />
        <CbomSlot
          label="Head CBOM"
          slot={head}
          onChange={setHead}
          testid="cbom-slot-head"
        />
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={() => void onDiff()}
          disabled={!canDiff || state.kind === 'diffing'}
          className="inline-flex items-center gap-2 rounded-md bg-[color:var(--color-accent)] px-4 py-2 text-sm font-semibold text-[color:var(--color-canvas)] transition-colors hover:bg-[color:var(--color-accent-strong)] disabled:opacity-50"
          data-testid="cbom-diff-run"
        >
          <Icon name="filter" size={14} />
          Run diff
        </button>
        <button
          type="button"
          onClick={() => {
            setBase(EMPTY_SLOT);
            setHead(EMPTY_SLOT);
            setState({ kind: 'idle' });
          }}
          className="inline-flex items-center gap-2 rounded-md border border-[color:var(--color-border-subtle)] px-3 py-2 text-[11px] font-semibold text-[color:var(--color-ink-muted)] hover:text-[color:var(--color-ink)]"
          data-testid="cbom-diff-clear"
        >
          Clear
        </button>
      </div>

      {state.kind === 'diffing' ? (
        <p className="mt-4 flex items-center gap-2 text-[11px] text-[color:var(--color-ink-muted)]">
          <Icon name="refresh" size={14} className="animate-spin" />
          Running diff…
        </p>
      ) : null}

      {state.kind === 'error' ? (
        <p
          className="mt-4 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-[11px] text-red-300"
          data-testid="cbom-diff-error"
        >
          {state.message}
        </p>
      ) : null}

      {state.kind === 'ready' ? <DiffResult result={state.result} /> : null}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Slot -- file drop / paste
// ---------------------------------------------------------------------------

const CbomSlot: React.FC<{
  label: string;
  slot: Slot;
  onChange: (next: Slot) => void;
  testid: string;
}> = ({ label, slot, onChange, testid }) => {
  async function handleFile(file: File): Promise<void> {
    let text: string;
    try {
      text = await _readAsText(file);
    } catch (err) {
      onChange({
        filename: file.name,
        parsed: null,
        error: err instanceof Error ? err.message : 'Could not read file.',
      });
      return;
    }
    try {
      const parsed = JSON.parse(text);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('File is not a JSON object.');
      }
      onChange({ filename: file.name, parsed, error: null });
    } catch (err) {
      onChange({
        filename: file.name,
        parsed: null,
        error: err instanceof Error ? err.message : 'Could not parse file.',
      });
    }
  }

  return (
    <div
      className="rounded-md border border-dashed border-[color:var(--color-border-subtle)] bg-[color:var(--color-canvas-deep)] p-4"
      onDragOver={(e) => e.preventDefault()}
      onDrop={(e) => {
        e.preventDefault();
        const file = e.dataTransfer.files?.[0];
        if (file) void handleFile(file);
      }}
    >
      <div className="mb-2 flex items-center justify-between">
        <span className="eyebrow-muted">{label}</span>
        {slot.filename ? (
          <span
            className="font-mono text-[10px] text-[color:var(--color-ink-muted)]"
            data-testid={`${testid}-filename`}
          >
            {slot.filename}
          </span>
        ) : null}
      </div>
      <label className="block cursor-pointer text-center text-[11px] text-[color:var(--color-ink-muted)] hover:text-[color:var(--color-ink)]">
        <input
          type="file"
          accept="application/json,.json"
          className="hidden"
          data-testid={`${testid}-input`}
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) void handleFile(file);
          }}
        />
        <span className="block rounded-md border border-[color:var(--color-border-subtle)] bg-[color:var(--color-canvas)] py-6">
          Drop a .json CBOM here or click to select
        </span>
      </label>
      {slot.error ? (
        <p
          className="mt-2 rounded-md border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-[11px] text-amber-200"
          data-testid={`${testid}-error`}
        >
          {slot.error}
        </p>
      ) : null}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Result rendering
// ---------------------------------------------------------------------------

const DiffResult: React.FC<{ result: CbomInteropDiffResponse }> = ({ result }) => (
  <div className="mt-6 space-y-5" data-testid="cbom-diff-result">
    <div className="grid gap-2 sm:grid-cols-4 text-[11px]">
      <Metric label="Added" value={result.counts.added} tone="warn" />
      <Metric label="Removed" value={result.counts.removed} tone="warn" />
      <Metric label="Changed" value={result.counts.changed} tone="danger" />
      <Metric label="Unchanged" value={result.counts.unchanged} tone="ok" />
    </div>

    <p className="text-[11px] text-[color:var(--color-ink-muted)]">
      Base tools: <code>{result.base.tools.join(', ') || 'unknown'}</code>
      &nbsp;·&nbsp; Head tools:{' '}
      <code>{result.head.tools.join(', ') || 'unknown'}</code>
    </p>

    <Bucket
      title="Changed"
      empty="No crypto assets changed between the two CBOMs."
      rows={result.changed.map((c) => (
        <tr
          key={c.name + JSON.stringify(c.changes)}
          className="border-t border-[color:var(--color-border-subtle)]"
        >
          <td className="px-3 py-2 font-mono text-[color:var(--color-ink)]">
            {c.name}
          </td>
          <td className="px-3 py-2">
            <div className="flex flex-wrap gap-1">
              {c.changeClasses.map((k) => (
                <span
                  key={k}
                  className="rounded-full bg-red-500/20 px-2 py-0.5 text-[10px] font-semibold uppercase text-red-200"
                >
                  {k.replace('_', ' ')}
                </span>
              ))}
            </div>
          </td>
          <td className="px-3 py-2 text-[10px] font-mono text-[color:var(--color-ink-muted)]">
            {Object.entries(c.changes).map(([k, v]) => (
              <div key={k}>
                <span className="text-[color:var(--color-ink)]">{k}</span>: {String(v.from)} → {String(v.to)}
              </div>
            ))}
          </td>
        </tr>
      ))}
      testid="cbom-diff-changed"
      columns={['Name', 'Change classes', 'Diff']}
    />

    <Bucket
      title="Added (only in head)"
      empty="No new crypto assets on the head side."
      rows={result.added.map((a) => (
        <tr
          key={a.name + (a.primitive ?? '')}
          className="border-t border-[color:var(--color-border-subtle)]"
        >
          <td className="px-3 py-2 font-mono text-[color:var(--color-ink)]">{a.name}</td>
          <td className="px-3 py-2">{a.primitive ?? '—'}</td>
          <td className="px-3 py-2">{a.parameterSetIdentifier ?? '—'}</td>
          <td className="px-3 py-2">{a.curve ?? '—'}</td>
        </tr>
      ))}
      testid="cbom-diff-added"
      columns={['Name', 'Primitive', 'Parameter', 'Curve']}
    />

    <Bucket
      title="Removed (only in base)"
      empty="No crypto assets missing on the head side."
      rows={result.removed.map((a) => (
        <tr
          key={a.name + (a.primitive ?? '')}
          className="border-t border-[color:var(--color-border-subtle)]"
        >
          <td className="px-3 py-2 font-mono text-[color:var(--color-ink)]">{a.name}</td>
          <td className="px-3 py-2">{a.primitive ?? '—'}</td>
          <td className="px-3 py-2">{a.parameterSetIdentifier ?? '—'}</td>
          <td className="px-3 py-2">{a.curve ?? '—'}</td>
        </tr>
      ))}
      testid="cbom-diff-removed"
      columns={['Name', 'Primitive', 'Parameter', 'Curve']}
    />
  </div>
);

const Bucket: React.FC<{
  title: string;
  empty: string;
  rows: React.ReactNode[];
  testid: string;
  columns: string[];
}> = ({ title, empty, rows, testid, columns }) => (
  <div data-testid={testid}>
    <h3 className="text-sm font-semibold text-[color:var(--color-ink)]">{title}</h3>
    {rows.length === 0 ? (
      <p className="mt-2 rounded-md border border-dashed border-[color:var(--color-border-subtle)] p-3 text-[11px] text-[color:var(--color-ink-muted)]">
        {empty}
      </p>
    ) : (
      <div className="mt-2 max-h-[300px] overflow-auto rounded-md border border-[color:var(--color-border-subtle)]">
        <table className="w-full text-left text-[11px]">
          <thead className="bg-[color:var(--color-canvas-deep)] text-[10px] uppercase tracking-widest text-[color:var(--color-ink-muted)]">
            <tr>
              {columns.map((c) => (
                <th key={c} className="px-3 py-2">
                  {c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    )}
  </div>
);

// Cross-environment file read: `File.text()` is spec but not present
// in every jsdom version, so we fall back to FileReader.
function _readAsText(file: File): Promise<string> {
  if (typeof (file as unknown as { text?: () => Promise<string> }).text === 'function') {
    return (file as unknown as { text: () => Promise<string> }).text();
  }
  return new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error('Could not read file.'));
    reader.onload = () => resolve(String(reader.result ?? ''));
    reader.readAsText(file);
  });
}

const Metric: React.FC<{
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
    <div className={`rounded-md border px-3 py-2 ${cls}`}>
      <div className="text-[9px] font-semibold uppercase tracking-widest opacity-80">
        {label}
      </div>
      <div className="mt-0.5 font-mono text-lg">{value}</div>
    </div>
  );
};
