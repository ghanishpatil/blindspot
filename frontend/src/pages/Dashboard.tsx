import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { FindingTable } from '@/components/FindingTable';
import { Icon } from '@/components/Icon';
import { RiskChip, SectionEyebrow, Stat } from '@/design';
import { fetchFindings, fetchHealth, startScan } from '@/services/api';
import { DEMO_HEALTH_RESPONSE, DEMO_PLANTED_FINDINGS } from '@/services/mockData';
import type { Finding, HealthResponse, RiskTier } from '@/types';

/* ═══════════════════════════════════════════════════════════════════════════
   Dashboard — the operational center.

   The previous version tried to say too many things at once with a pie chart,
   a redundant Total-vs-Findings stat pair, and a decorated primitives list.
   This version reads left-to-right, top-to-bottom, as one operator would use
   it: posture strip → what's on your surface → what to do first → the full
   findings table. Subsystem readiness is a footer strip.
   ═══════════════════════════════════════════════════════════════════════════ */

type LoadState =
  | { kind: 'loading' }
  | { kind: 'loaded'; health: HealthResponse; findings: Finding[] }
  | { kind: 'error'; message: string };

const SUBSYSTEM_LABELS: Record<string, string> = {
  firebase: 'Firebase',
  semgrep: 'Semgrep',
  demoRepository: 'Demo repository',
  fallbackCache: 'Fallback cache',
};

const TIER_WEIGHT: Record<string, number> = { overdue: 3, transitional: 2, 'low-risk': 1, unknown: 0 };

export default function Dashboard() {
  const navigate = useNavigate();
  const [load, setLoad] = useState<LoadState>({ kind: 'loading' });
  const [scanning, setScanning] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetchHealth()
      .then(async (health) => {
        let findings: Finding[] = [];
        try {
          findings = await fetchFindings({ projectId: 'demo' });
        } catch {
          findings = DEMO_PLANTED_FINDINGS;
        }
        return { health, findings };
      })
      .catch(() => ({ health: DEMO_HEALTH_RESPONSE, findings: DEMO_PLANTED_FINDINGS }))
      .then(({ health, findings }) => {
        if (cancelled) return;
        setLoad({
          kind: 'loaded',
          health: health || DEMO_HEALTH_RESPONSE,
          findings: findings && findings.length > 0 ? findings : DEMO_PLANTED_FINDINGS,
        });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleRunScan = async () => {
    setScanning(true);
    try {
      await startScan({ projectId: 'demo' });
      const updatedFindings = await fetchFindings({ projectId: 'demo' });
      const updatedHealth = await fetchHealth();
      setLoad({ kind: 'loaded', health: updatedHealth, findings: updatedFindings });
    } catch (err) {
      console.error('Scan failed:', err);
    } finally {
      setScanning(false);
    }
  };

  if (load.kind === 'loading') return <LoadingState />;
  if (load.kind === 'error') return <ErrorState message={load.message} />;

  const { findings, health } = load;
  return (
    <div className="space-y-8">
      <Header scanning={scanning} onRunScan={handleRunScan} />
      <PostureStrip findings={findings} />
      <HonestyBar findings={findings} onReview={() => navigate('/findings')} />

      <div className="grid gap-6 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <CryptoSurface findings={findings} onDrilldown={(algo) => navigate(`/findings?algorithm=${encodeURIComponent(algo)}`)} />
        <NextActions findings={findings} onOpen={(id) => navigate(`/findings/${id}`)} />
      </div>

      <FindingsSection findings={findings} onSeeAll={() => navigate('/findings')} />

      <SubsystemStrip health={health} />
    </div>
  );
}

/* ─── Header ────────────────────────────────────────────────────────────── */

const Header: React.FC<{ scanning: boolean; onRunScan: () => void }> = ({ scanning, onRunScan }) => (
  <div className="flex flex-wrap items-end justify-between gap-4">
    <div>
      <SectionEyebrow>Overview</SectionEyebrow>
      <h1 className="mt-2 text-2xl font-semibold tracking-tight text-[color:var(--color-ink)]">
        Cryptographic posture
      </h1>
      <p className="mt-1 max-w-2xl text-sm text-[color:var(--color-ink-muted)]">
        Real-time inventory of discovered cryptographic assets, quantum risk tiering, and the
        migration decisions that follow.
      </p>
    </div>

    <div className="flex items-center gap-3">
      <button
        onClick={onRunScan}
        disabled={scanning}
        className="inline-flex items-center gap-2 rounded-md bg-[color:var(--color-accent)] px-4 py-2 text-sm font-semibold text-[color:var(--color-canvas)] transition-colors hover:bg-[color:var(--color-accent-strong)] disabled:opacity-50"
      >
        <Icon name="refresh" size={14} className={scanning ? 'animate-spin' : ''} />
        {scanning ? 'Scanning…' : 'Run scan'}
      </button>
    </div>
  </div>
);

/* ─── Posture strip ─────────────────────────────────────────────────────── */

const PostureStrip: React.FC<{ findings: Finding[] }> = ({ findings }) => {
  const total = findings.length;
  const overdue = findings.filter((f) => f.riskTier === 'overdue').length;
  const transitional = findings.filter((f) => f.riskTier === 'transitional').length;
  const lowRisk = findings.filter((f) => f.riskTier === 'low-risk').length;
  const hndl = findings.filter((f) => f.isHndlExposed).length;
  const weakNow = findings.filter((f) => f.isCurrentlyWeak).length;

  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-6">
      <Stat label="Artefacts" value={total} icon="database" accent="accent" hint="Discovered on this scan" />
      <Stat label="Overdue" value={overdue} icon="alert-triangle" accent="overdue" hint="Migrate first" />
      <Stat label="Transitional" value={transitional} icon="clock" accent="transitional" hint="Hybrid window" />
      <Stat label="Low-risk" value={lowRisk} icon="check-circle" accent="low-risk" hint="Monitor" />
      <Stat label="HNDL" value={hndl} icon="eye" accent="hndl" hint="Harvest-now-decrypt-later" />
      <Stat label="Weak now" value={weakNow} icon="alert-triangle" accent="muted" hint="Present-day defect" />
    </div>
  );
};

/* ─── Honesty bar ───────────────────────────────────────────────────────── */

const HonestyBar: React.FC<{ findings: Finding[]; onReview: () => void }> = ({ findings, onReview }) => {
  const flagged = findings.filter((f) => f.needsVerification).length;
  const tone = flagged > 0 ? 'amber' : 'accent';

  return (
    <div className={`flex flex-wrap items-center gap-4 rounded-lg border border-[color:var(--color-border-subtle)] bg-[color:var(--color-panel)] px-5 py-3`}>
      <span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-md ${tone === 'amber' ? 'bg-[#E9A73A]/10 text-[#E9A73A]' : 'bg-[color:var(--color-low-risk-soft)] text-[#4FB37A]'}`}>
        <Icon name={flagged > 0 ? 'help-circle' : 'check-circle'} size={16} />
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-sm text-[color:var(--color-ink)]">
          <span className={`font-mono font-semibold ${flagged > 0 ? 'text-[#E9A73A]' : 'text-[#4FB37A]'}`}>{flagged}</span>{' '}
          finding{flagged === 1 ? '' : 's'} flagged for manual verification
        </p>
        <p className="text-[11px] text-[color:var(--color-ink-muted)]">
          Low detection confidence or an unresolved parameter. We surface uncertainty rather than assert it.
        </p>
      </div>
      {flagged > 0 ? (
        <button
          onClick={onReview}
          className="rounded-md border border-[color:var(--color-border-subtle)] bg-[color:var(--color-panel)] px-3 py-1.5 font-mono text-[11px] text-[color:var(--color-ink-muted)] transition-colors hover:border-[color:var(--color-accent)]/40 hover:text-[color:var(--color-ink)]"
        >
          Review flagged
        </button>
      ) : null}
    </div>
  );
};

/* ─── Cryptographic surface ─────────────────────────────────────────────── */

interface AlgoTile {
  algorithm: string;
  count: number;
  worstTier: string;
  hasHndl: boolean;
  hasWeak: boolean;
}

const CryptoSurface: React.FC<{
  findings: Finding[];
  onDrilldown: (algorithm: string) => void;
}> = ({ findings, onDrilldown }) => {
  const tiles = useMemo<AlgoTile[]>(() => {
    const buckets = new Map<string, AlgoTile>();
    for (const f of findings) {
      const key = f.algorithm;
      const existing = buckets.get(key);
      const tier = f.riskTier || 'unknown';
      if (existing) {
        existing.count += 1;
        if ((TIER_WEIGHT[tier] || 0) > (TIER_WEIGHT[existing.worstTier] || 0)) existing.worstTier = tier;
        existing.hasHndl = existing.hasHndl || f.isHndlExposed;
        existing.hasWeak = existing.hasWeak || f.isCurrentlyWeak;
      } else {
        buckets.set(key, {
          algorithm: key,
          count: 1,
          worstTier: tier,
          hasHndl: f.isHndlExposed,
          hasWeak: f.isCurrentlyWeak,
        });
      }
    }
    return Array.from(buckets.values()).sort(
      (a, b) => (TIER_WEIGHT[b.worstTier] || 0) - (TIER_WEIGHT[a.worstTier] || 0) || b.count - a.count,
    );
  }, [findings]);

  return (
    <section className="surface-panel p-6">
      <div className="mb-4 flex items-baseline justify-between gap-3">
        <div>
          <SectionEyebrow>Cryptographic surface</SectionEyebrow>
          <h2 className="mt-1 text-lg font-semibold text-[color:var(--color-ink)]">Algorithms in your scan</h2>
        </div>
        <p className="hidden max-w-xs text-[11px] text-[color:var(--color-ink-muted)] md:block">
          Each tile is one algorithm; the number is how many times it was matched. Tint reflects the
          worst risk tier detected for that algorithm.
        </p>
      </div>

      {tiles.length === 0 ? (
        <p className="text-sm text-[color:var(--color-ink-muted)]">No findings yet.</p>
      ) : (
        <div className="card-scroll card-scroll-md grid grid-cols-2 gap-2 md:grid-cols-3">
          {tiles.map((tile) => (
            <button
              key={tile.algorithm}
              onClick={() => onDrilldown(tile.algorithm)}
              className="group relative overflow-hidden rounded-md border border-[color:var(--color-border-subtle)] bg-[color:var(--color-canvas)] p-3 text-left transition-all hover:border-[color:var(--color-border-strong)]"
            >
              <TierBorder tier={tile.worstTier} />
              <div className="flex items-baseline justify-between">
                <span className="font-mono text-sm font-semibold text-[color:var(--color-ink)]">
                  {tile.algorithm}
                </span>
                <span className="metric-value text-lg text-[color:var(--color-ink)]">{tile.count}</span>
              </div>
              <div className="mt-2 flex flex-wrap items-center gap-1.5">
                <RiskChip tier={tile.worstTier as RiskTier} size="sm" />
                {tile.hasHndl ? (
                  <span className="rounded bg-[#B090F5]/10 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-widest text-[#B090F5]">
                    HNDL
                  </span>
                ) : null}
                {tile.hasWeak ? (
                  <span className="rounded bg-[#EB6480]/10 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-widest text-[#EB6480]">
                    Weak
                  </span>
                ) : null}
              </div>
            </button>
          ))}
        </div>
      )}
    </section>
  );
};

const TierBorder: React.FC<{ tier: string }> = ({ tier }) => {
  const color =
    tier === 'overdue' ? '#E85D5D' : tier === 'transitional' ? '#E9A73A' : tier === 'low-risk' ? '#4FB37A' : '#3E4652';
  return (
    <span
      aria-hidden="true"
      className="absolute inset-y-0 left-0 w-[3px]"
      style={{ background: color }}
    />
  );
};

/* ─── Next actions ─────────────────────────────────────────────────────── */

const NextActions: React.FC<{ findings: Finding[]; onOpen: (id: string) => void }> = ({ findings, onOpen }) => {
  const ranked = useMemo(() => {
    // Priority: HNDL exposed > weak-now > overdue > transitional. Ties broken by
    // criticality then by identifier for determinism.
    const score = (f: Finding): number => {
      let s = 0;
      if (f.isHndlExposed) s += 100;
      if (f.isCurrentlyWeak) s += 80;
      if (f.riskTier === 'overdue') s += 60;
      if (f.riskTier === 'transitional') s += 30;
      if (f.classification?.criticality === 'high') s += 8;
      else if (f.classification?.criticality === 'medium') s += 4;
      return s;
    };
    return [...findings]
      .map((f) => ({ f, s: score(f) }))
      .filter((r) => r.s > 0)
      .sort((a, b) => b.s - a.s || a.f.id.localeCompare(b.f.id))
      .slice(0, 3)
      .map((r) => r.f);
  }, [findings]);

  return (
    <section className="surface-panel p-6">
      <SectionEyebrow accent="overdue">Do this first</SectionEyebrow>
      <h2 className="mt-1 text-lg font-semibold text-[color:var(--color-ink)]">Next actions</h2>
      <p className="mt-1 text-[11px] text-[color:var(--color-ink-muted)]">
        Sequenced by HNDL exposure, present-day weakness, tier, and criticality.
      </p>

      <ol className="mt-4 space-y-3">
        {ranked.length === 0 ? (
          <p className="text-sm text-[color:var(--color-ink-muted)]">Nothing urgent right now. Monitor and re-scan.</p>
        ) : (
          ranked.map((f, i) => (
            <li key={f.id}>
              <button
                onClick={() => onOpen(f.id)}
                className="group flex w-full items-start gap-3 rounded-md border border-[color:var(--color-border-subtle)] bg-[color:var(--color-canvas)] p-3 text-left transition-all hover:border-[color:var(--color-accent)]/30"
              >
                <span className="font-mono text-[11px] font-semibold text-[color:var(--color-ink-faint)]">
                  {String(i + 1).padStart(2, '0')}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-sm font-semibold text-[color:var(--color-ink)]">
                      {f.algorithm}
                    </span>
                    <RiskChip tier={f.riskTier} />
                    {f.isHndlExposed ? (
                      <span className="rounded bg-[#B090F5]/10 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-widest text-[#B090F5]">
                        HNDL
                      </span>
                    ) : null}
                    {f.isCurrentlyWeak ? (
                      <span className="rounded bg-[#EB6480]/10 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-widest text-[#EB6480]">
                        Weak
                      </span>
                    ) : null}
                  </div>
                  <p className="mt-1 truncate font-mono text-[11px] text-[color:var(--color-ink-muted)]">
                    {f.filePath}
                    {f.lineNumber ? `:L${f.lineNumber}` : ''}
                  </p>
                  {f.recommendation ? (
                    <p className="mt-1 text-[11px] text-[color:var(--color-ink-muted)]">
                      →{' '}
                      <span className="text-[color:var(--color-accent)]">{f.recommendation.algorithm}</span>
                    </p>
                  ) : null}
                </div>
                <Icon
                  name="arrow-right"
                  size={13}
                  className="mt-1 text-[color:var(--color-ink-faint)] transition-transform group-hover:translate-x-0.5 group-hover:text-[color:var(--color-accent)]"
                />
              </button>
            </li>
          ))
        )}
      </ol>
    </section>
  );
};

/* ─── Findings section ─────────────────────────────────────────────────── */

const FindingsSection: React.FC<{ findings: Finding[]; onSeeAll: () => void }> = ({
  findings,
  onSeeAll,
}) => (
  <section>
    <div className="mb-4 flex items-end justify-between">
      <div>
        <SectionEyebrow>Detailed inventory</SectionEyebrow>
        <h2 className="mt-1 text-lg font-semibold text-[color:var(--color-ink)]">Findings</h2>
      </div>
      <button
        onClick={onSeeAll}
        className="font-mono text-[11px] uppercase tracking-widest text-[color:var(--color-ink-muted)] transition-colors hover:text-[color:var(--color-accent)]"
      >
        View all →
      </button>
    </div>
    <FindingTable findings={findings} maxBodyHeight="420px" />
  </section>
);

/* ─── Subsystem strip ───────────────────────────────────────────────────── */

const SubsystemStrip: React.FC<{ health: HealthResponse }> = ({ health }) => (
  <footer className="rounded-lg border border-[color:var(--color-border-subtle)] bg-[color:var(--color-panel)]/60 px-5 py-3">
    <div className="flex flex-wrap items-center gap-4">
      <span className="eyebrow-muted">Subsystem readiness</span>
      <div className="flex flex-wrap items-center gap-4 text-[11px]">
        {Object.entries(health.subsystems).map(([name, status]) => (
          <span key={name} className="flex items-center gap-1.5 font-mono">
            <span
              className={`h-1.5 w-1.5 rounded-full ${status.available ? 'bg-[#4FB37A]' : 'bg-[#E9A73A]'}`}
            />
            <span className="text-[color:var(--color-ink-muted)]">
              {SUBSYSTEM_LABELS[name] || name}
            </span>
          </span>
        ))}
      </div>
    </div>
  </footer>
);

/* ─── Loading / error states ───────────────────────────────────────────── */

const LoadingState: React.FC = () => (
  <div className="flex h-96 flex-col items-center justify-center gap-3">
    <Icon name="refresh" size={28} className="animate-spin text-[color:var(--color-accent)]" />
    <span className="font-mono text-xs uppercase tracking-widest text-[color:var(--color-ink-muted)]">
      Loading cryptographic posture
    </span>
  </div>
);

const ErrorState: React.FC<{ message: string }> = ({ message }) => (
  <div className="surface-panel space-y-3 p-6">
    <div className="flex items-center gap-2">
      <Icon name="alert-triangle" size={20} className="text-[#E85D5D]" />
      <h2 className="text-base font-semibold text-[color:var(--color-ink)]">Backend unreachable</h2>
    </div>
    <p className="text-sm text-[color:var(--color-ink-muted)]">{message}</p>
    <p className="font-mono text-xs text-[color:var(--color-ink-faint)]">
      Run: <code className="text-[color:var(--color-accent)]">uvicorn app.main:app --port 8000</code> in <code>backend/</code>
    </p>
  </div>
);


