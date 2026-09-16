/**
 * PipelineTrace — the seven-stage ECDAT pipeline as a single interactive strip.
 *
 * The product's whole story is a pipeline. Rather than describe it in bullet
 * points, this component makes the pipeline the interaction: seven stages
 * side-by-side, one active at a time, with a live detail panel underneath.
 * The connecting line has a subtle indicator that flows left → right so the
 * *direction* of the pipeline is legible without being noisy.
 *
 * This is a leaf component with no data dependencies — it explains the
 * architecture, not any specific scan.
 */
import React, { useEffect, useRef, useState } from 'react';

import { Icon, type IconName } from '@/components/Icon';

interface Stage {
  id: string;
  index: string;
  label: string;
  headline: string;
  detail: string;
  icon: IconName;
}

const STAGES: Stage[] = [
  {
    id: 'discover',
    index: '01',
    label: 'Discover',
    icon: 'search',
    headline: 'Cryptographic artefacts, wherever they live.',
    detail:
      'Semgrep AST rules match cryptographic usage across Python and C source code. Dependency manifests are parsed for crypto-providing packages. Container image layers, compiled binaries, and IaC configurations are read by dedicated scanners that emit findings on the same contract.',
  },
  {
    id: 'evidence',
    index: '02',
    label: 'Evidence',
    icon: 'file-code',
    headline: 'Every finding carries proof.',
    detail:
      'File path, line number, matched source, detection method, and a confidence band travel with each finding. Nothing is asserted without evidence a reviewer can inspect and disagree with on its merits.',
  },
  {
    id: 'cbom',
    index: '03',
    label: 'CBOM',
    icon: 'file-json',
    headline: 'CycloneDX 1.6 cryptographic bill-of-materials.',
    detail:
      'Every finding is normalised into a schema-valid CycloneDX component. Algorithm, parameter set, mode, and OID metadata land in a single portable document that other tools can consume unchanged.',
  },
  {
    id: 'classify',
    index: '04',
    label: 'Classify',
    icon: 'layers',
    headline: 'Type, lifetime, and business criticality.',
    detail:
      'Artefacts are typed (key exchange, signature, encryption, hash) and stamped with a data-lifetime value X keyed on usage. Confidentiality-oriented crypto is judged differently from authenticity-oriented crypto — a distinction most tools flatten away.',
  },
  {
    id: 'risk',
    index: '05',
    label: 'Risk',
    icon: 'clock',
    headline: "Mosca's inequality: X + Y > Z.",
    detail:
      'Data lifetime (X) plus migration time (Y) is measured against the quantum horizon (Z). Findings for which the sum exceeds Z are overdue for migration. Z is a configurable assumption; its provenance travels with every result.',
  },
  {
    id: 'recommend',
    index: '06',
    label: 'Recommend',
    icon: 'target',
    headline: 'PQC, hybrid, or defer — with sourced cost.',
    detail:
      'Each finding gets a deterministic recommendation: pure PQC (ML-KEM / ML-DSA), a hybrid transition, defer with monitoring, or investigate. PQC targets carry a size-cost profile drawn from FIPS 203 / 204 published parameter sizes — real bytes, never fabricated latency.',
  },
  {
    id: 'plan',
    index: '07',
    label: 'Plan',
    icon: 'trending-up',
    headline: 'A sequenced migration roadmap.',
    detail:
      'Findings roll up into a prioritised plan of five waves — from immediate remediation through hybrid transition to defer-and-monitor — with effort, cost, and blast radius per item. The plan is deterministic: the same findings always produce the same waves.',
  },
];

export interface PipelineTraceProps {
  /** Initially-active stage id. Defaults to 'discover'. */
  initial?: string;
  /** Compact variant hides the detail panel. */
  compact?: boolean;
}

export const PipelineTrace: React.FC<PipelineTraceProps> = ({ initial = 'discover', compact = false }) => {
  const [activeId, setActiveId] = useState(initial);
  const activeIndex = STAGES.findIndex((s) => s.id === activeId);
  const active = STAGES[activeIndex >= 0 ? activeIndex : 0];

  // Autoplay: advance the active stage every 4.5 s if the user hasn't touched it.
  // Interaction pauses the autoplay so the demo feels responsive but never
  // hijacks the visitor's attention.
  const [autoplay, setAutoplay] = useState(true);
  // Only run the interval while the component is actually on screen — otherwise
  // we'd be advancing state (and re-rendering the app) for nobody's benefit.
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [inView, setInView] = useState(false);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    // Environments without IntersectionObserver (tests, older engines):
    // assume the trace is always in view — autoplay just runs.
    if (typeof IntersectionObserver === 'undefined') {
      setInView(true);
      return;
    }
    const observer = new IntersectionObserver(
      ([entry]) => setInView(entry.isIntersecting),
      { threshold: 0.25 },
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!autoplay || !inView) return;
    const t = window.setInterval(() => {
      setActiveId((current) => {
        const i = STAGES.findIndex((s) => s.id === current);
        return STAGES[(i + 1) % STAGES.length].id;
      });
    }, 4500);
    return () => window.clearInterval(t);
  }, [autoplay, inView]);

  const select = (id: string) => {
    setAutoplay(false);
    setActiveId(id);
  };

  return (
    <div ref={containerRef} className="w-full">
      {/* Stage row */}
      <div className="relative">
        {/* Connecting rail */}
        <div className="absolute left-0 right-0 top-[26px] hidden h-px bg-[color:var(--color-border-subtle)] lg:block" />
        {/* Progress rail up to the active stage */}
        <div
          className="absolute left-0 top-[26px] hidden h-px bg-[color:var(--color-accent)] transition-[width] duration-700 ease-out lg:block"
          style={{
            width: `calc(${((activeIndex + 0.5) / STAGES.length) * 100}%)`,
            boxShadow: '0 0 8px var(--color-accent-line)',
          }}
        />

        <ol className="relative grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-7 lg:gap-0">
          {STAGES.map((stage, i) => {
            const isActive = stage.id === activeId;
            const isPast = i < activeIndex;
            return (
              <li key={stage.id} className="lg:flex lg:flex-col lg:items-center">
                <button
                  type="button"
                  onClick={() => select(stage.id)}
                  onMouseEnter={() => select(stage.id)}
                  aria-current={isActive ? 'step' : undefined}
                  className="group flex w-full flex-col items-center gap-2 focus:outline-none"
                >
                  {/* Node */}
                  <span
                    className={`
                      relative z-10 flex h-[52px] w-[52px] items-center justify-center rounded-full
                      border transition-all duration-300
                      ${
                        isActive
                          ? 'border-[color:var(--color-accent)] bg-[color:var(--color-accent-soft)] text-[color:var(--color-accent)] shadow-[0_0_0_4px_rgba(124,209,224,0.08)]'
                          : isPast
                            ? 'border-[color:var(--color-accent)]/50 bg-[color:var(--color-panel)] text-[color:var(--color-accent)]/70'
                            : 'border-[color:var(--color-border-subtle)] bg-[color:var(--color-panel)] text-[color:var(--color-ink-muted)] group-hover:border-[color:var(--color-border-strong)]'
                      }
                    `}
                  >
                    <Icon name={stage.icon} size={18} />
                  </span>

                  {/* Label */}
                  <div className="flex flex-col items-center gap-0.5">
                    <span className={`font-mono text-[10px] font-medium tracking-[0.14em] ${isActive ? 'text-[color:var(--color-accent)]' : 'text-[color:var(--color-ink-faint)]'}`}>
                      {stage.index}
                    </span>
                    <span className={`text-xs font-semibold ${isActive ? 'text-[color:var(--color-ink)]' : 'text-[color:var(--color-ink-muted)]'}`}>
                      {stage.label}
                    </span>
                  </div>
                </button>
              </li>
            );
          })}
        </ol>
      </div>

      {/* Detail panel */}
      {!compact ? (
        <div className="mt-8 rounded-xl border border-[color:var(--color-border-subtle)] bg-[color:var(--color-panel)] p-6 md:p-7">
          <div className="flex items-start gap-4">
            <div className="hidden h-10 w-10 shrink-0 items-center justify-center rounded-md border border-[color:var(--color-accent)]/30 bg-[color:var(--color-accent-soft)] text-[color:var(--color-accent)] md:flex">
              <Icon name={active.icon} size={18} />
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-baseline gap-3">
                <span className="font-mono text-[11px] font-medium tracking-[0.16em] text-[color:var(--color-accent)]">
                  STAGE {active.index}
                </span>
                <span className="text-xs uppercase tracking-widest text-[color:var(--color-ink-faint)]">
                  {active.label}
                </span>
              </div>
              <h4 key={active.id} className="tick-in mt-1 text-lg font-semibold text-[color:var(--color-ink)] md:text-xl">
                {active.headline}
              </h4>
              <p className="mt-2 max-w-3xl text-sm leading-relaxed text-[color:var(--color-ink-muted)]">
                {active.detail}
              </p>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
};
