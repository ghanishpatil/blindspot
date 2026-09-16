import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';

import { CodeEvidence } from '@/components/CodeEvidence';
import { Icon, type IconName } from '@/components/Icon';
import { RecommendationCard } from '@/components/RecommendationCard';
import { KeyValue, MoscaVisualiser, RiskChip, SectionEyebrow } from '@/design';
import { fetchFinding } from '@/services/api';
import { DEMO_PLANTED_FINDINGS } from '@/services/mockData';
import type { Finding } from '@/types';

/* ═══════════════════════════════════════════════════════════════════════════
   FindingDetail — the chain-of-analysis view.

   Design intent: the whole product's argument for its value lives here. A
   user must be able to follow, without hunting, the reasoning that produced
   the recommendation:

       Evidence  →  Classification  →  Mosca risk  →  Recommendation

   The previous version buried this in tabs. Tabs hide the chain and force
   the user to reconstruct it. This version shows the entire chain at once,
   with evidence sticky on the left as the anchor, and the analysis unfolding
   as a vertical narrative on the right.
   ═══════════════════════════════════════════════════════════════════════════ */

type ChainStage = { id: string; label: string; icon: IconName; description: string };

const CHAIN: ChainStage[] = [
  { id: 'evidence', label: 'Evidence', icon: 'file-code', description: 'What was matched and how' },
  { id: 'classification', label: 'Classification', icon: 'layers', description: 'Type, lifetime, criticality' },
  { id: 'risk', label: 'Mosca risk', icon: 'clock', description: 'X + Y measured against Z' },
  { id: 'recommendation', label: 'Recommendation', icon: 'target', description: 'Concrete migration action' },
];

export default function FindingDetail() {
  const { findingId } = useParams<{ findingId: string }>();
  const navigate = useNavigate();
  const [finding, setFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!findingId) return;
    fetchFinding(findingId)
      .then((data) => setFinding(data))
      .catch(() => {
        const found = DEMO_PLANTED_FINDINGS.find((item) => item.id === findingId);
        setFinding(found || DEMO_PLANTED_FINDINGS[0]);
      })
      .finally(() => setLoading(false));
  }, [findingId]);

  if (loading) return <LoadingState />;
  if (!finding) return <NotFoundState onBack={() => navigate('/findings')} />;

  return (
    <div className="space-y-6">
      {/* Back link + chain crumb */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <button
          onClick={() => navigate('/findings')}
          className="inline-flex items-center gap-2 font-mono text-[11px] uppercase tracking-widest text-[color:var(--color-ink-muted)] transition-colors hover:text-[color:var(--color-ink)]"
        >
          <Icon name="arrow-right" size={12} className="rotate-180" />
          Findings
        </button>
        <ChainCrumb />
      </div>

      {/* Finding header */}
      <FindingHeader finding={finding} />

      {/* Two-column chain */}
      <div className="grid gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
        {/* Left: evidence — sticky on desktop so it stays as an anchor while
            the analysis unfolds on the right. */}
        <aside className="lg:sticky lg:top-6 lg:self-start">
          <StageMarker index="01" label="Evidence" active />
          <div className="mt-3">
            <CodeEvidence evidence={finding.evidence} />
          </div>
        </aside>

        {/* Right: the analysis chain, top to bottom */}
        <div className="space-y-8">
          <ClassificationBlock finding={finding} />
          <MoscaBlock finding={finding} />
          <div>
            <StageMarker index="04" label="Recommendation" active />
            <div className="mt-3">
              <RecommendationCard recommendation={finding.recommendation} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ─── Header ──────────────────────────────────────────────────────────── */

const FindingHeader: React.FC<{ finding: Finding }> = ({ finding }) => {
  const {
    algorithm,
    displayName,
    filePath,
    lineNumber,
    parameterStatus,
    isHndlExposed,
    needsVerification,
    riskTier,
  } = finding;

  return (
    <header className="surface-panel px-6 py-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="font-mono text-2xl font-semibold tracking-tight text-[color:var(--color-ink)]">
              {algorithm}
            </h1>
            <RiskChip tier={riskTier} size="md" />
            {isHndlExposed ? (
              <span
                title="Harvest-Now-Decrypt-Later exposure: confidentiality + Shor-breakable + overdue."
                className="rounded-md bg-[#B090F5]/10 px-2 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-widest text-[#B090F5] ring-1 ring-inset ring-[#B090F5]/25"
              >
                HNDL
              </span>
            ) : null}
            {needsVerification ? (
              <span
                title="Flagged for manual verification: low confidence or unresolved parameter."
                className="rounded-md bg-[color:var(--color-border-subtle)]/50 px-2 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-widest text-[color:var(--color-ink-muted)] ring-1 ring-inset ring-[color:var(--color-border-strong)]"
              >
                Verify
              </span>
            ) : null}
            {parameterStatus === 'unresolved' ? (
              <span className="rounded-md bg-[#E9A73A]/10 px-2 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-widest text-[#E9A73A] ring-1 ring-inset ring-[#E9A73A]/25">
                Unresolved
              </span>
            ) : null}
          </div>
          <p className="mt-1.5 text-sm text-[color:var(--color-ink-muted)]">{displayName}</p>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <Icon name="file-code" size={14} className="text-[color:var(--color-accent)]" />
          <span className="text-[color:var(--color-ink)]">{filePath}</span>
          {lineNumber ? <span className="text-[color:var(--color-ink-faint)]">:L{lineNumber}</span> : null}
        </div>
      </div>
    </header>
  );
};

/* ─── Chain crumb — visual pipeline breadcrumb, all four stages active ─── */

const ChainCrumb: React.FC = () => (
  <ol className="hidden items-center gap-1.5 md:flex">
    {CHAIN.map((s, i) => (
      <li key={s.id} className="flex items-center gap-1.5">
        <span
          className="inline-flex items-center gap-1.5 rounded-md border border-[color:var(--color-border-subtle)] bg-[color:var(--color-panel)] px-2 py-1 font-mono text-[10px] uppercase tracking-widest text-[color:var(--color-ink-muted)]"
          title={s.description}
        >
          <Icon name={s.icon} size={11} className="text-[color:var(--color-accent)]" />
          {s.label}
        </span>
        {i < CHAIN.length - 1 ? (
          <span className="text-[color:var(--color-ink-faint)]">
            <Icon name="chevron-right" size={12} />
          </span>
        ) : null}
      </li>
    ))}
  </ol>
);

/* ─── StageMarker — a lightweight header for each block of the chain ─── */

const StageMarker: React.FC<{ index: string; label: string; active?: boolean }> = ({
  index,
  label,
  active,
}) => (
  <div className="flex items-center gap-3">
    <span
      className={`inline-flex h-8 w-8 items-center justify-center rounded-md border font-mono text-[11px] font-semibold ${
        active
          ? 'border-[color:var(--color-accent)]/40 bg-[color:var(--color-accent-soft)] text-[color:var(--color-accent)]'
          : 'border-[color:var(--color-border-subtle)] bg-[color:var(--color-panel)] text-[color:var(--color-ink-muted)]'
      }`}
    >
      {index}
    </span>
    <div>
      <div className="eyebrow">Stage {index}</div>
      <div className="text-sm font-semibold text-[color:var(--color-ink)]">{label}</div>
    </div>
  </div>
);

/* ─── Classification block ──────────────────────────────────────────── */

const ClassificationBlock: React.FC<{ finding: Finding }> = ({ finding }) => {
  const { algorithm, parameter, artefactType, library, classification, currentRisk, quantumRisk } = finding;

  return (
    <section>
      <StageMarker index="02" label="Classification" active />
      <div className="mt-3 grid gap-4 md:grid-cols-2">
        <div className="surface-panel px-5 py-4">
          <SectionEyebrow>Artefact</SectionEyebrow>
          <div className="mt-3 divide-y divide-[color:var(--color-border-subtle)]/60">
            <KeyValue label="Algorithm" value={<span className="font-semibold">{algorithm}</span>} mono />
            <KeyValue label="Parameter" value={parameter || 'unknown'} mono />
            <KeyValue
              label="Artefact type"
              value={
                <span className="capitalize text-[color:var(--color-accent)]">{artefactType}</span>
              }
              mono
            />
            <KeyValue label="Library" value={library || 'stdlib'} mono />
          </div>
        </div>

        <div className="surface-panel px-5 py-4">
          <SectionEyebrow>Analysis inputs</SectionEyebrow>
          <div className="mt-3 divide-y divide-[color:var(--color-border-subtle)]/60">
            <KeyValue
              label="Data lifetime · X"
              value={<span className="font-semibold">{classification?.dataLifetimeYears ?? '—'} yr</span>}
              mono
            />
            <KeyValue
              label="Criticality"
              value={<span className="capitalize">{classification?.criticality ?? '—'}</span>}
              mono
            />
            <KeyValue
              label="Security goal"
              value={<span className="capitalize">{classification?.securityGoal ?? '—'}</span>}
              mono
            />
            <KeyValue
              label="Lifetime source"
              value={<span className="text-[color:var(--color-ink-muted)]">{classification?.lifetimeSource ?? 'policy_default'}</span>}
              mono
            />
          </div>
        </div>
      </div>

      {/* Threat summary — quantum + current-day, presented in the classifier's
          own language so a reviewer can trace the wording back to the code. */}
      {(quantumRisk || currentRisk) ? (
        <div className="mt-4 grid gap-4 md:grid-cols-2">
          {quantumRisk ? (
            <div className="surface-panel px-5 py-4">
              <div className="flex items-center gap-2">
                <Icon name="alert-triangle" size={14} className="text-[color:var(--color-accent)]" />
                <span className="eyebrow">Quantum threat</span>
              </div>
              <p className="mt-2 text-sm leading-relaxed text-[color:var(--color-ink)]">
                {quantumRisk.reason}
              </p>
              {quantumRisk.effectiveSecurityLoss ? (
                <p className="mt-2 font-mono text-[11px] text-[color:var(--color-ink-muted)]">
                  {quantumRisk.effectiveSecurityLoss}
                </p>
              ) : null}
            </div>
          ) : null}
          {currentRisk ? (
            <div className="surface-panel px-5 py-4">
              <div className="flex items-center gap-2">
                <Icon name="shield" size={14} className="text-[color:var(--color-accent)]" />
                <span className="eyebrow">Present-day posture</span>
              </div>
              <p className="mt-2 text-sm leading-relaxed text-[color:var(--color-ink)]">
                {currentRisk.reason}
              </p>
            </div>
          ) : null}
        </div>
      ) : null}
    </section>
  );
};

/* ─── Mosca block ───────────────────────────────────────────────────── */

const MoscaBlock: React.FC<{ finding: Finding }> = ({ finding }) => {
  const m = finding.mosca;

  return (
    <section>
      <StageMarker index="03" label="Mosca risk" active />
      <div className="mt-3 surface-panel px-5 py-5">
        {m ? (
          <>
            <MoscaVisualiser
              x={m.x}
              y={m.y}
              z={m.z}
              zLabel={m.zSource}
              applicable={m.applicable}
            />
            {m.notes ? (
              <p className="mt-4 border-t border-[color:var(--color-border-subtle)]/60 pt-3 text-xs leading-relaxed text-[color:var(--color-ink-muted)]">
                {m.notes}
              </p>
            ) : null}
            <p className="mt-3 font-mono text-[10px] uppercase tracking-widest text-[color:var(--color-ink-faint)]">
              Z sourced from: {m.zSource}
            </p>
          </>
        ) : (
          <p className="text-sm text-[color:var(--color-ink-muted)]">
            No Mosca assessment recorded for this finding.
          </p>
        )}
      </div>
    </section>
  );
};

/* ─── Loading / not-found states ────────────────────────────────────── */

const LoadingState: React.FC = () => (
  <div className="flex h-96 flex-col items-center justify-center gap-3">
    <Icon name="refresh" size={28} className="animate-spin text-[color:var(--color-accent)]" />
    <span className="font-mono text-xs uppercase tracking-widest text-[color:var(--color-ink-muted)]">
      Loading finding analysis
    </span>
  </div>
);

const NotFoundState: React.FC<{ onBack: () => void }> = ({ onBack }) => (
  <div className="surface-panel space-y-4 p-8 text-center">
    <Icon name="alert-triangle" size={28} className="mx-auto text-[#E9A73A]" />
    <p className="text-base font-semibold text-[color:var(--color-ink)]">Finding not found.</p>
    <button
      onClick={onBack}
      className="inline-flex items-center gap-2 rounded-md border border-[color:var(--color-accent)]/40 bg-[color:var(--color-accent-soft)] px-4 py-2 text-xs font-semibold text-[color:var(--color-accent)]"
    >
      Return to findings
    </button>
  </div>
);
