import { useEffect, useMemo, useState } from 'react';

import { Icon } from '@/components/Icon';
import { RiskChip } from '@/design';
import { fetchCompliance } from '@/services/api';
import type {
  ComplianceEvaluation,
  ComplianceFinding,
  CompliancePreset,
  RiskTier,
} from '@/types';

interface FindingPresetSensitivityProps {
  findingId: string;
}

type State =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; evaluation: ComplianceEvaluation; row: ComplianceFinding };

/**
 * Preset-sensitivity strip for the Finding detail page.
 *
 * Re-uses the existing ``GET /api/compliance`` matrix (no new
 * backend endpoint required). Given a ``findingId``, we render:
 *
 * 1. A preset dropdown (all named quantum-horizon Z presets).
 * 2. This finding's tier chip under the selected preset.
 * 3. The Mosca inequality under that preset (X + Y > Z), verbatim
 *    from the backend evaluator -- no client-side math.
 * 4. A small "flip indicator" showing whether the tier differs from
 *    the baseline preset -- the *actual* dramatic demo moment.
 *
 * If the endpoint returns 404 (no scan yet) the component silently
 * hides itself; the finding page still renders its usual Mosca block.
 */
export function FindingPresetSensitivity({
  findingId,
}: FindingPresetSensitivityProps) {
  const [state, setState] = useState<State>({ kind: 'loading' });
  const [selectedPreset, setSelectedPreset] = useState<string>('');

  useEffect(() => {
    let cancelled = false;
    setState({ kind: 'loading' });

    fetchCompliance()
      .then((evaluation) => {
        if (cancelled) return;
        const row = evaluation.findings.find((f) => f.findingId === findingId);
        if (!row) {
          setState({
            kind: 'error',
            message:
              'This finding is not present in the current scan\u2019s compliance matrix.',
          });
          return;
        }
        setState({ kind: 'ready', evaluation, row });
        // Default: baseline preset. Falls back to the first preset when the
        // evaluation omits an explicit baseline name.
        setSelectedPreset(
          evaluation.baselinePresetName ||
            evaluation.presets[0]?.name ||
            '',
        );
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setState({
          kind: 'error',
          message: err instanceof Error ? err.message : 'Cannot load preset data.',
        });
      });

    return () => {
      cancelled = true;
    };
  }, [findingId]);

  const activeTier = useMemo(() => {
    if (state.kind !== 'ready' || !selectedPreset) return null;
    return state.row.tiersByPreset[selectedPreset] ?? null;
  }, [state, selectedPreset]);

  const baselineTier = useMemo(() => {
    if (state.kind !== 'ready') return null;
    return state.row.tiersByPreset[state.evaluation.baselinePresetName] ?? null;
  }, [state]);

  if (state.kind === 'loading') {
    return null; // Silent -- the surrounding page already shows a loading skeleton.
  }

  if (state.kind === 'error') {
    // Non-blocking. This is a nice-to-have; page still functions.
    return null;
  }

  const flipped =
    activeTier &&
    baselineTier &&
    activeTier.tier !== baselineTier.tier;

  return (
    <section
      className="surface-panel px-5 py-5"
      data-testid="finding-preset-sensitivity"
    >
      <header className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="eyebrow">Compliance sensitivity</div>
          <h3 className="mt-1 text-sm font-semibold text-[color:var(--color-ink)]">
            Watch this finding\u2019s tier flip across quantum-horizon presets
          </h3>
        </div>
        <PresetPicker
          presets={state.evaluation.presets}
          value={selectedPreset}
          onChange={setSelectedPreset}
        />
      </header>

      {activeTier ? (
        <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_minmax(0,2fr)] sm:items-center">
          <div
            className="flex flex-col gap-2 rounded-md border border-[color:var(--color-border-subtle)] bg-[color:var(--color-canvas-deep)] p-4"
            data-testid="preset-sensitivity-tier-block"
          >
            <div className="text-[10px] font-semibold uppercase tracking-widest text-[color:var(--color-ink-muted)]">
              Tier under {selectedPreset}
            </div>
            <div className="flex items-center gap-2">
              <RiskChip
                tier={(activeTier.tier as RiskTier) ?? 'unknown'}
                size="md"
              />
              {flipped ? (
                <span
                  className="inline-flex items-center gap-1 rounded-full border border-red-500/40 bg-red-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-widest text-red-200"
                  data-testid="preset-sensitivity-flip-indicator"
                >
                  <Icon name="alert-triangle" size={11} /> flipped
                </span>
              ) : (
                <span
                  className="inline-flex items-center gap-1 rounded-full border border-slate-500/40 bg-slate-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-widest text-slate-300"
                  data-testid="preset-sensitivity-stable-indicator"
                >
                  stable
                </span>
              )}
            </div>
            {baselineTier ? (
              <p className="text-[11px] text-[color:var(--color-ink-muted)]">
                Baseline (
                <code className="text-[color:var(--color-ink)]">
                  {state.evaluation.baselinePresetName}
                </code>
                ): {baselineTier.tier}
              </p>
            ) : null}
          </div>

          <div className="flex flex-col gap-2 text-[11px]">
            <div className="rounded-md border border-[color:var(--color-border-subtle)] bg-[color:var(--color-canvas-deep)] p-4 font-mono">
              <div className="text-[10px] uppercase tracking-widest text-[color:var(--color-ink-muted)]">
                Mosca inequality
              </div>
              <div
                className="mt-1 text-sm text-[color:var(--color-ink)]"
                data-testid="preset-sensitivity-equation"
              >
                {activeTier.applicable
                  ? activeTier.equation
                  : 'Mosca does not apply (algorithm Shor cannot break).'}
              </div>
              <div className="mt-2 text-[10px] text-[color:var(--color-ink-muted)]">
                X = {activeTier.x.toFixed(1)} y &nbsp;|&nbsp; Y ={' '}
                {activeTier.y.toFixed(1)} y &nbsp;|&nbsp; Z ={' '}
                {activeTier.z.toFixed(1)} y &nbsp;|&nbsp; margin ={' '}
                {activeTier.marginYears >= 0
                  ? `+${activeTier.marginYears.toFixed(1)}`
                  : activeTier.marginYears.toFixed(1)}{' '}
                y
              </div>
              <div className="mt-1 text-[10px] text-[color:var(--color-ink-faint)]">
                Z source:{' '}
                {state.evaluation.presets.find((p) => p.name === selectedPreset)?.source ??
                  selectedPreset}
              </div>
            </div>
          </div>
        </div>
      ) : (
        <p className="text-[11px] text-[color:var(--color-ink-muted)]">
          Select a preset to see the Mosca math under that quantum horizon.
        </p>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Preset dropdown
// ---------------------------------------------------------------------------

const PresetPicker: React.FC<{
  presets: CompliancePreset[];
  value: string;
  onChange: (v: string) => void;
}> = ({ presets, value, onChange }) => (
  <label className="flex items-center gap-2 text-[11px] text-[color:var(--color-ink-muted)]">
    <span className="eyebrow-muted">Preset</span>
    <select
      className="rounded-md border border-[color:var(--color-border-subtle)] bg-[color:var(--color-canvas)] px-3 py-1.5 text-sm text-[color:var(--color-ink)] focus:border-[color:var(--color-accent)] focus:outline-none"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      data-testid="preset-sensitivity-select"
    >
      {presets.map((p) => (
        <option key={p.name} value={p.name}>
          {p.name} · Z = {p.z}y
        </option>
      ))}
    </select>
  </label>
);
