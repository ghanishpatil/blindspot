import { useEffect, useMemo, useState } from 'react';

import { Icon } from '@/components/Icon';
import {
  getActivePolicy,
  getDefaultPolicy,
  resetActivePolicy,
  saveActivePolicy,
  simulatePolicy,
  type PolicyDocument,
  type PolicyEnvelope,
  type PolicySimulationResponse,
} from '@/services/policyApi';
import { listScans, type ScanSummaryRow } from '@/services/scansApi';

interface PolicyEditorProps {
  projectId?: string;
}

type LoadState =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; envelope: PolicyEnvelope };

type SaveState =
  | { kind: 'idle' }
  | { kind: 'saving' }
  | { kind: 'ok'; message: string }
  | { kind: 'error'; message: string };

type SimulationState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ok'; result: PolicySimulationResponse };

/**
 * Policy-as-code editor.
 *
 * The dashboard surface for the same policy engine that
 * ``blindspot-scan gate`` runs in CI. One JSON document, one active
 * override on disk, four operations (view / edit / reset / simulate).
 *
 * Editor is deliberately JSON-textarea + client-side parse feedback:
 * server is the schema authority (PUT /api/policy returns 400 with
 * the exact reason on malformed input), and a rules-table below the
 * textarea gives the operator a visual sanity check without a full
 * form UI.
 *
 * Simulate re-uses the scan list from ``GET /api/scans`` so an
 * operator can test "would this policy block that PR?" against a
 * pair of historical scans before saving anything.
 */
export function PolicyEditor({ projectId }: PolicyEditorProps) {
  // Active policy load + local edit buffer.
  const [state, setState] = useState<LoadState>({ kind: 'loading' });
  const [editorText, setEditorText] = useState<string>('');
  const [save, setSave] = useState<SaveState>({ kind: 'idle' });

  // Simulation panel state.
  const [scans, setScans] = useState<ScanSummaryRow[]>([]);
  const [scansError, setScansError] = useState<string | null>(null);
  const [base, setBase] = useState<string>('');
  const [head, setHead] = useState<string>('');
  const [simulation, setSimulation] = useState<SimulationState>({ kind: 'idle' });

  // -- Load active policy on mount / project change ---------------------
  useEffect(() => {
    const controller = new AbortController();
    setState({ kind: 'loading' });
    setSave({ kind: 'idle' });
    getActivePolicy(controller.signal)
      .then((envelope) => {
        setState({ kind: 'ready', envelope });
        setEditorText(prettyJson(envelope.policy));
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) return;
        setState({
          kind: 'error',
          message: err instanceof Error ? err.message : 'Unable to load policy.',
        });
      });
    return () => controller.abort();
  }, []);

  // -- Load scan list once for the simulation selectors -----------------
  useEffect(() => {
    const controller = new AbortController();
    listScans({ projectId, signal: controller.signal })
      .then((res) => {
        setScans(res.scans);
        if (res.scans.length >= 2) {
          setHead(res.scans[0].scanId ?? '');
          setBase(res.scans[1].scanId ?? '');
        }
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) return;
        setScansError(
          err instanceof Error ? err.message : 'Unable to load scans.',
        );
      });
    return () => controller.abort();
  }, [projectId]);

  // -- Client-side parse: give instant feedback before the round trip ---
  const parseResult = useMemo(() => parseAsPolicy(editorText), [editorText]);
  const canSave = parseResult.ok;
  const canSimulate = Boolean(base && head && base !== head);

  async function onSave() {
    if (!parseResult.ok) return;
    setSave({ kind: 'saving' });
    try {
      const envelope = await saveActivePolicy(parseResult.value);
      setState({ kind: 'ready', envelope });
      setEditorText(prettyJson(envelope.policy));
      setSave({
        kind: 'ok',
        message: envelope.isDefault
          ? 'Saved (matches built-in default).'
          : 'Policy saved. This is now the active override.',
      });
    } catch (err: unknown) {
      setSave({
        kind: 'error',
        message: err instanceof Error ? err.message : 'Save failed.',
      });
    }
  }

  async function onReset() {
    setSave({ kind: 'saving' });
    try {
      const envelope = await resetActivePolicy();
      setState({ kind: 'ready', envelope });
      setEditorText(prettyJson(envelope.policy));
      setSave({ kind: 'ok', message: 'Reverted to built-in default policy.' });
    } catch (err: unknown) {
      setSave({
        kind: 'error',
        message: err instanceof Error ? err.message : 'Reset failed.',
      });
    }
  }

  async function onLoadDefaultPreview() {
    try {
      const envelope = await getDefaultPolicy();
      setEditorText(prettyJson(envelope.policy));
      setSave({
        kind: 'ok',
        message: 'Loaded default policy into the editor. Not saved yet.',
      });
    } catch (err: unknown) {
      setSave({
        kind: 'error',
        message: err instanceof Error ? err.message : 'Preview failed.',
      });
    }
  }

  async function onSimulate() {
    if (!canSimulate) return;
    // Simulate the *edited* buffer if it parses, else the persisted one.
    const draft = parseResult.ok ? parseResult.value : null;
    setSimulation({ kind: 'loading' });
    try {
      const result = await simulatePolicy(base, head, draft);
      setSimulation({ kind: 'ok', result });
    } catch (err: unknown) {
      setSimulation({
        kind: 'error',
        message: err instanceof Error ? err.message : 'Simulation failed.',
      });
    }
  }

  return (
    <section className="surface-panel p-6" data-testid="policy-editor">
      <header className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="eyebrow">Policy as code</div>
          <h2 className="mt-1 text-lg font-semibold text-[color:var(--color-ink)]">
            CI/CD gate policy
          </h2>
          <p className="mt-1 max-w-2xl text-[11px] text-[color:var(--color-ink-muted)]">
            Same policy engine as <code>blindspot-scan gate</code> in CI.
            Edit here, simulate against any two scans, save when green.
          </p>
        </div>
        {state.kind === 'ready' ? (
          <span
            className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-widest ${
              state.envelope.isDefault
                ? 'border-slate-500/40 bg-slate-500/10 text-slate-300'
                : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
            }`}
            data-testid="policy-status-chip"
          >
            <Icon
              name={state.envelope.isDefault ? 'shield' : 'check'}
              size={11}
            />
            {state.envelope.isDefault ? 'Built-in default' : 'Custom override'}
          </span>
        ) : null}
      </header>

      {state.kind === 'loading' ? (
        <div className="flex items-center gap-2 py-4 text-[11px] text-[color:var(--color-ink-muted)]">
          <Icon name="refresh" size={14} className="animate-spin" />
          Loading active policy…
        </div>
      ) : null}

      {state.kind === 'error' ? (
        <p className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-[11px] text-red-300">
          {state.message}
        </p>
      ) : null}

      {state.kind === 'ready' ? (
        <>
          <div className="grid gap-4 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
            {/* -- JSON editor -------------------------------------------- */}
            <div>
              <label className="eyebrow-muted mb-2 block" htmlFor="policy-json">
                Policy JSON
              </label>
              <textarea
                id="policy-json"
                value={editorText}
                onChange={(e) => setEditorText(e.target.value)}
                spellCheck={false}
                rows={18}
                className="w-full rounded-md border border-[color:var(--color-border-subtle)] bg-[color:var(--color-canvas-deep)] p-3 font-mono text-[12px] text-[color:var(--color-ink)] focus:border-[color:var(--color-accent)] focus:outline-none"
                data-testid="policy-editor-textarea"
              />
              <div
                className={`mt-2 flex items-center gap-2 text-[11px] ${
                  parseResult.ok
                    ? 'text-emerald-300'
                    : 'text-amber-300'
                }`}
                data-testid="policy-parse-status"
              >
                <Icon
                  name={parseResult.ok ? 'check' : 'alert-triangle'}
                  size={12}
                />
                {parseResult.ok
                  ? `Valid JSON. ${parseResult.value.rules.length} rule(s), name = "${parseResult.value.name}".`
                  : parseResult.message}
              </div>

              <div className="mt-3 flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => void onSave()}
                  disabled={!canSave || save.kind === 'saving'}
                  className="inline-flex items-center gap-2 rounded-md bg-[color:var(--color-accent)] px-4 py-2 text-sm font-semibold text-[color:var(--color-canvas)] transition-colors hover:bg-[color:var(--color-accent-strong)] disabled:opacity-50"
                  data-testid="policy-save-button"
                >
                  <Icon name="download" size={14} />
                  Save policy
                </button>
                <button
                  type="button"
                  onClick={() => void onReset()}
                  disabled={save.kind === 'saving'}
                  className="inline-flex items-center gap-2 rounded-md border border-[color:var(--color-border-subtle)] px-4 py-2 text-sm font-semibold text-[color:var(--color-ink)] transition-colors hover:border-[color:var(--color-accent)] disabled:opacity-50"
                  data-testid="policy-reset-button"
                >
                  <Icon name="refresh" size={14} />
                  Reset to default
                </button>
                <button
                  type="button"
                  onClick={() => void onLoadDefaultPreview()}
                  className="inline-flex items-center gap-2 rounded-md px-3 py-2 text-[11px] font-semibold text-[color:var(--color-ink-muted)] hover:text-[color:var(--color-ink)]"
                  data-testid="policy-load-default-button"
                >
                  Load default into editor
                </button>
              </div>

              {save.kind === 'ok' ? (
                <p
                  className="mt-3 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-[11px] text-emerald-200"
                  data-testid="policy-save-ok"
                >
                  {save.message}
                </p>
              ) : null}
              {save.kind === 'error' ? (
                <p
                  className="mt-3 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-[11px] text-red-300"
                  data-testid="policy-save-error"
                >
                  {save.message}
                </p>
              ) : null}
            </div>

            {/* -- Parsed rules table ------------------------------------ */}
            <div>
              <div className="eyebrow-muted mb-2">Rules preview</div>
              {parseResult.ok ? (
                <RulesTable rules={parseResult.value.rules} />
              ) : (
                <p className="rounded-md border border-dashed border-[color:var(--color-border-subtle)] p-3 text-[11px] text-[color:var(--color-ink-muted)]">
                  Fix the JSON on the left to see rules here.
                </p>
              )}
            </div>
          </div>

          {/* -- Simulation ------------------------------------------------ */}
          <div
            className="mt-8 rounded-md border border-[color:var(--color-border-subtle)] bg-[color:var(--color-canvas-deep)] p-5"
            data-testid="policy-simulate-section"
          >
            <h3 className="text-sm font-semibold text-[color:var(--color-ink)]">
              Simulate against a scan pair
            </h3>
            <p className="mt-1 text-[11px] text-[color:var(--color-ink-muted)]">
              Runs the edited policy against a delta computed the same way
              CI does. Nothing is persisted; edit freely and re-run.
            </p>

            {scansError ? (
              <p className="mt-3 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-[11px] text-amber-200">
                {scansError}
              </p>
            ) : null}

            {scans.length < 2 ? (
              <p className="mt-3 rounded-md border border-dashed border-[color:var(--color-border-subtle)] p-3 text-[11px] text-[color:var(--color-ink-muted)]">
                Simulation needs at least two scans on disk.
                Currently {scans.length}.
              </p>
            ) : (
              <div className="mt-3 grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] sm:items-end">
                <ScanPicker
                  label="Base"
                  value={base}
                  onChange={setBase}
                  scans={scans}
                  testid="policy-sim-base"
                />
                <ScanPicker
                  label="Head"
                  value={head}
                  onChange={setHead}
                  scans={scans}
                  testid="policy-sim-head"
                />
                <button
                  type="button"
                  onClick={() => void onSimulate()}
                  disabled={!canSimulate || simulation.kind === 'loading'}
                  className="inline-flex items-center gap-2 rounded-md bg-[color:var(--color-accent)] px-4 py-2 text-sm font-semibold text-[color:var(--color-canvas)] transition-colors hover:bg-[color:var(--color-accent-strong)] disabled:opacity-50"
                  data-testid="policy-sim-run"
                >
                  <Icon name="filter" size={14} />
                  Simulate
                </button>
              </div>
            )}

            {simulation.kind === 'loading' ? (
              <p className="mt-3 flex items-center gap-2 text-[11px] text-[color:var(--color-ink-muted)]">
                <Icon name="refresh" size={13} className="animate-spin" />
                Running simulation…
              </p>
            ) : null}
            {simulation.kind === 'error' ? (
              <p
                className="mt-3 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-[11px] text-red-300"
                data-testid="policy-sim-error"
              >
                {simulation.message}
              </p>
            ) : null}
            {simulation.kind === 'ok' ? (
              <SimulationResult result={simulation.result} />
            ) : null}
          </div>
        </>
      ) : null}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Helpers -- kept module-local. Small enough not to justify their own file.
// ---------------------------------------------------------------------------

function prettyJson(policy: PolicyDocument): string {
  return JSON.stringify(policy, null, 2);
}

type ParseResult =
  | { ok: true; value: PolicyDocument }
  | { ok: false; message: string };

/** Client-side sanity check for the editor. Not the schema authority --
 *  the backend re-validates on PUT and returns 400 with the real reason. */
function parseAsPolicy(text: string): ParseResult {
  const trimmed = text.trim();
  if (!trimmed) {
    return { ok: false, message: 'Editor is empty.' };
  }
  let raw: unknown;
  try {
    raw = JSON.parse(trimmed);
  } catch (err) {
    return {
      ok: false,
      message: `Invalid JSON: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, message: 'Root must be a JSON object.' };
  }
  const obj = raw as Record<string, unknown>;
  const name = typeof obj.name === 'string' ? obj.name : '';
  const rules = obj.rules;
  if (!Array.isArray(rules)) {
    return { ok: false, message: 'Field "rules" must be an array.' };
  }
  // The backend enforces the full schema. Here we only need enough to
  // render the rules table + know we can send it.
  for (let i = 0; i < rules.length; i += 1) {
    const r = rules[i];
    if (!r || typeof r !== 'object') {
      return { ok: false, message: `rules[${i}] must be an object.` };
    }
  }
  return {
    ok: true,
    value: {
      schemaVersion: typeof obj.schemaVersion === 'string' ? obj.schemaVersion : undefined,
      name: name || 'unnamed',
      rules: rules as PolicyDocument['rules'],
    },
  };
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

const RulesTable: React.FC<{ rules: PolicyDocument['rules'] }> = ({ rules }) => {
  if (rules.length === 0) {
    return (
      <p className="rounded-md border border-dashed border-[color:var(--color-border-subtle)] p-3 text-[11px] text-[color:var(--color-ink-muted)]">
        No rules. Nothing will fire.
      </p>
    );
  }
  return (
    <div className="max-h-[420px] overflow-auto rounded-md border border-[color:var(--color-border-subtle)]">
      <table className="w-full text-left text-[11px]">
        <thead className="bg-[color:var(--color-canvas-deep)] text-[10px] uppercase tracking-widest text-[color:var(--color-ink-muted)]">
          <tr>
            <th className="px-3 py-2">Rule id</th>
            <th className="px-3 py-2">On</th>
            <th className="px-3 py-2">Action</th>
            <th className="px-3 py-2">Match</th>
          </tr>
        </thead>
        <tbody data-testid="policy-rules-tbody">
          {rules.map((r) => (
            <tr
              key={r.id ?? Math.random()}
              className="border-t border-[color:var(--color-border-subtle)]"
            >
              <td className="px-3 py-2 font-mono text-[color:var(--color-ink)]">
                {String(r.id ?? '(unnamed)')}
              </td>
              <td className="px-3 py-2 text-[color:var(--color-ink-muted)]">
                {String(r.on ?? '')}
              </td>
              <td className="px-3 py-2">
                <span
                  className={`inline-flex rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase ${
                    r.action === 'block'
                      ? 'bg-red-500/20 text-red-200'
                      : 'bg-amber-500/20 text-amber-200'
                  }`}
                >
                  {String(r.action ?? '')}
                </span>
              </td>
              <td className="px-3 py-2 font-mono text-[10px] text-[color:var(--color-ink-muted)]">
                {JSON.stringify(r.match)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

const ScanPicker: React.FC<{
  label: string;
  value: string;
  onChange: (v: string) => void;
  scans: ScanSummaryRow[];
  testid: string;
}> = ({ label, value, onChange, scans, testid }) => (
  <label className="block">
    <span className="eyebrow-muted">{label}</span>
    <select
      className="mt-1 w-full rounded-md border border-[color:var(--color-border-subtle)] bg-[color:var(--color-canvas)] px-3 py-2 text-sm text-[color:var(--color-ink)] focus:border-[color:var(--color-accent)] focus:outline-none"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      data-testid={testid}
    >
      <option value="">— select a scan —</option>
      {scans.map((s) => (
        <option key={s.scanId ?? ''} value={s.scanId ?? ''}>
          {s.scanId} · {s.startedAt ?? 'no timestamp'} · {s.findingCount} finding
          {s.findingCount === 1 ? '' : 's'}
        </option>
      ))}
    </select>
  </label>
);

const SimulationResult: React.FC<{ result: PolicySimulationResponse }> = ({
  result,
}) => (
  <div className="mt-4 space-y-3" data-testid="policy-sim-result">
    <div className="flex flex-wrap items-center gap-3">
      <span
        className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-[11px] font-semibold uppercase tracking-widest ${
          result.wouldBlock
            ? 'border-red-500/50 bg-red-500/10 text-red-200'
            : 'border-emerald-500/50 bg-emerald-500/10 text-emerald-200'
        }`}
        data-testid="policy-sim-verdict"
      >
        <Icon name={result.wouldBlock ? 'alert-triangle' : 'check'} size={12} />
        {result.wouldBlock ? 'Would block CI' : 'Would pass CI'}
      </span>
      <span className="text-[11px] text-[color:var(--color-ink-muted)]">
        Policy: <code className="text-[color:var(--color-ink)]">{result.policyName}</code>
      </span>
    </div>

    <div className="grid gap-2 sm:grid-cols-4 text-[11px]">
      <Metric label="Introduced" value={result.counts.introduced} />
      <Metric label="Resolved" value={result.counts.resolved} />
      <Metric label="Changed" value={result.counts.changed} />
      <Metric label="Unchanged" value={result.counts.unchanged} />
    </div>

    <div className="grid gap-2 sm:grid-cols-2 text-[11px]">
      <Metric label="Block violations" value={result.blockCount} tone="danger" />
      <Metric label="Warn violations" value={result.warnCount} tone="warn" />
    </div>

    {result.violations.length > 0 ? (
      <div className="max-h-[320px] overflow-auto rounded-md border border-[color:var(--color-border-subtle)]">
        <table className="w-full text-left text-[11px]">
          <thead className="bg-[color:var(--color-canvas-deep)] text-[10px] uppercase tracking-widest text-[color:var(--color-ink-muted)]">
            <tr>
              <th className="px-3 py-2">Rule</th>
              <th className="px-3 py-2">Action</th>
              <th className="px-3 py-2">Finding</th>
              <th className="px-3 py-2">Reason</th>
            </tr>
          </thead>
          <tbody data-testid="policy-sim-violations-tbody">
            {result.violations.map((v, idx) => (
              <tr
                key={`${v.ruleId}-${v.findingId ?? idx}`}
                className="border-t border-[color:var(--color-border-subtle)]"
              >
                <td className="px-3 py-2 font-mono text-[color:var(--color-ink)]">
                  {v.ruleId}
                </td>
                <td className="px-3 py-2">
                  <span
                    className={`inline-flex rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase ${
                      v.action === 'block'
                        ? 'bg-red-500/20 text-red-200'
                        : 'bg-amber-500/20 text-amber-200'
                    }`}
                  >
                    {v.action}
                  </span>
                </td>
                <td className="px-3 py-2 font-mono text-[10px] text-[color:var(--color-ink-muted)]">
                  {v.findingId ?? '(unbound)'}
                </td>
                <td className="px-3 py-2 text-[color:var(--color-ink-muted)]">
                  {v.reason}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    ) : null}
  </div>
);

const Metric: React.FC<{
  label: string;
  value: number;
  tone?: 'danger' | 'warn' | 'default';
}> = ({ label, value, tone = 'default' }) => {
  const toneClasses =
    tone === 'danger'
      ? 'border-red-500/30 bg-red-500/10 text-red-200'
      : tone === 'warn'
        ? 'border-amber-500/30 bg-amber-500/10 text-amber-200'
        : 'border-[color:var(--color-border-subtle)] bg-[color:var(--color-canvas)] text-[color:var(--color-ink)]';
  return (
    <div className={`rounded-md border px-3 py-2 ${toneClasses}`}>
      <div className="text-[9px] font-semibold uppercase tracking-widest opacity-70">
        {label}
      </div>
      <div className="mt-0.5 font-mono text-sm">{value}</div>
    </div>
  );
};
