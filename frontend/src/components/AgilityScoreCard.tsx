import { useEffect, useState } from 'react';

import { Icon } from '@/components/Icon';
import {
  getAgilityScore,
  type AgilityGrade,
  type AgilityScoreResponse,
} from '@/services/agilityApi';
import { listScans } from '@/services/scansApi';

interface AgilityScoreCardProps {
  projectId?: string;
}

type State =
  | { kind: 'loading' }
  | { kind: 'empty' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; score: AgilityScoreResponse };

/**
 * Crypto-agility score card.
 *
 * Renders the 0-100 score, letter grade, and additive breakdown for
 * the *latest* scan of the given project. Every number is fetched
 * from ``GET /api/agility/{scanId}`` -- the backend derives it from
 * the persisted scan.summary, so nothing on this component is
 * fabricated or client-computed.
 */
export function AgilityScoreCard({ projectId }: AgilityScoreCardProps) {
  const [state, setState] = useState<State>({ kind: 'loading' });

  useEffect(() => {
    const controller = new AbortController();
    setState({ kind: 'loading' });

    (async () => {
      try {
        const list = await listScans({ projectId, signal: controller.signal });
        if (controller.signal.aborted) return;
        const latest = list.scans[0]?.scanId;
        if (!latest) {
          setState({ kind: 'empty' });
          return;
        }
        const score = await getAgilityScore(latest, controller.signal);
        if (controller.signal.aborted) return;
        setState({ kind: 'ready', score });
      } catch (err: unknown) {
        if (controller.signal.aborted) return;
        setState({
          kind: 'error',
          message: err instanceof Error ? err.message : 'Failed to load agility score.',
        });
      }
    })();

    return () => controller.abort();
  }, [projectId]);

  return (
    <section className="surface-panel p-6" data-testid="agility-score-card">
      <header className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="eyebrow">Crypto-agility score</div>
          <h2 className="mt-1 text-lg font-semibold text-[color:var(--color-ink)]">
            Migration readiness · 0–100
          </h2>
          <p className="mt-1 max-w-2xl text-[11px] text-[color:var(--color-ink-muted)]">
            Composite of tier posture (60), weakness immunity (25), and
            HNDL immunity (15). Every point traces back to a specific
            finding in the latest scan.
          </p>
        </div>
      </header>

      {state.kind === 'loading' ? (
        <div className="flex items-center gap-2 py-4 text-[11px] text-[color:var(--color-ink-muted)]">
          <Icon name="refresh" size={14} className="animate-spin" />
          Loading agility score…
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
          data-testid="agility-empty"
        >
          <Icon name="target" size={18} className="text-slate-500" />
          <p>Run a scan to see your crypto-agility score.</p>
        </div>
      ) : null}

      {state.kind === 'ready' ? <AgilityBody score={state.score} /> : null}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Rendered result
// ---------------------------------------------------------------------------

const AgilityBody: React.FC<{ score: AgilityScoreResponse }> = ({ score }) => (
  <div className="space-y-5" data-testid="agility-result">
    <div className="grid gap-5 md:grid-cols-[auto_minmax(0,1fr)] md:items-center">
      <GradeBadge grade={score.grade} score={score.score} />
      <BreakdownStack breakdown={score.breakdown} />
    </div>

    <div className="grid gap-2 sm:grid-cols-6 text-[11px]">
      <InputTile label="Total" value={score.inputs.totalFindings} />
      <InputTile label="Overdue" value={score.inputs.overdue} tone="danger" />
      <InputTile label="Transitional" value={score.inputs.transitional} tone="warn" />
      <InputTile label="Low-risk" value={score.inputs.lowRisk} tone="ok" />
      <InputTile
        label="Weak now"
        value={score.inputs.currentWeakCrypto}
        tone="danger"
      />
      <InputTile
        label="HNDL"
        value={score.inputs.hndlExposed}
        tone="danger"
      />
    </div>

    {score.rationale.length > 0 ? (
      <ul
        className="list-disc space-y-1 rounded-md border border-[color:var(--color-border-subtle)] bg-[color:var(--color-canvas-deep)] p-4 pl-8 text-[11px] text-[color:var(--color-ink-muted)]"
        data-testid="agility-rationale"
      >
        {score.rationale.map((line, idx) => (
          <li key={idx}>{line}</li>
        ))}
      </ul>
    ) : null}

    <p className="text-[10px] uppercase tracking-widest text-[color:var(--color-ink-faint)]">
      Scan {score.scanId} · schema {score.schemaVersion}
      {score.generatedAt ? ` · generated ${formatDate(score.generatedAt)}` : null}
    </p>
  </div>
);

const GradeBadge: React.FC<{ grade: AgilityGrade; score: number }> = ({
  grade,
  score,
}) => {
  const tone = _gradeTone(grade);
  return (
    <div
      className={`flex items-baseline justify-center gap-3 rounded-xl border px-6 py-5 ${tone}`}
      data-testid="agility-grade-badge"
    >
      <span className="font-mono text-6xl font-bold leading-none">{grade}</span>
      <div className="flex flex-col items-start">
        <span className="text-[10px] font-semibold uppercase tracking-widest opacity-75">
          Score
        </span>
        <span
          className="font-mono text-2xl font-semibold leading-none"
          data-testid="agility-score-value"
        >
          {score.toFixed(1)}
        </span>
      </div>
    </div>
  );
};

const BreakdownStack: React.FC<{
  breakdown: AgilityScoreResponse['breakdown'];
}> = ({ breakdown }) => (
  <div className="flex flex-col gap-3">
    <BreakdownBar label="Tier posture" band={breakdown.tierPosture} />
    <BreakdownBar label="Weakness immunity" band={breakdown.weaknessImmunity} />
    <BreakdownBar label="HNDL immunity" band={breakdown.hndlImmunity} />
  </div>
);

const BreakdownBar: React.FC<{
  label: string;
  band: { earned: number; max: number };
}> = ({ label, band }) => {
  const pct = band.max > 0 ? (band.earned / band.max) * 100 : 0;
  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-[11px]">
        <span className="text-[color:var(--color-ink)]">{label}</span>
        <span className="font-mono text-[color:var(--color-ink-muted)]">
          {band.earned.toFixed(1)} / {band.max.toFixed(0)}
        </span>
      </div>
      <div className="h-2 w-full overflow-hidden rounded-full bg-[color:var(--color-canvas-deep)]">
        <div
          className="h-full rounded-full bg-[color:var(--color-accent)] transition-all"
          style={{ width: `${pct}%` }}
          data-testid={`agility-bar-${label.split(' ')[0].toLowerCase()}`}
        />
      </div>
    </div>
  );
};

const InputTile: React.FC<{
  label: string;
  value: number;
  tone?: 'default' | 'ok' | 'warn' | 'danger';
}> = ({ label, value, tone = 'default' }) => {
  const cls =
    tone === 'ok'
      ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
      : tone === 'warn'
        ? 'border-amber-500/30 bg-amber-500/10 text-amber-200'
        : tone === 'danger'
          ? 'border-red-500/30 bg-red-500/10 text-red-200'
          : 'border-[color:var(--color-border-subtle)] bg-[color:var(--color-canvas-deep)] text-[color:var(--color-ink)]';
  return (
    <div className={`rounded-md border px-3 py-2 ${cls}`}>
      <div className="text-[9px] font-semibold uppercase tracking-widest opacity-80">
        {label}
      </div>
      <div className="mt-0.5 font-mono text-sm">{value}</div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function _gradeTone(grade: AgilityGrade): string {
  switch (grade) {
    case 'A':
      return 'border-emerald-500/50 bg-emerald-500/10 text-emerald-200';
    case 'B':
      return 'border-teal-500/50 bg-teal-500/10 text-teal-200';
    case 'C':
      return 'border-amber-500/50 bg-amber-500/10 text-amber-200';
    case 'D':
      return 'border-orange-500/50 bg-orange-500/10 text-orange-200';
    case 'F':
      return 'border-red-500/50 bg-red-500/10 text-red-200';
  }
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}
