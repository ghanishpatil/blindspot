import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { AnimatedBackground } from '@/components/AnimatedBackground';
import { Footer } from '@/components/Footer';
import { Icon, type IconName } from '@/components/Icon';
import { Navbar } from '@/components/Navbar';
import {
  MoscaVisualiser,
  PipelineTrace,
  RiskChip,
  SectionEyebrow,
} from '@/design';
import { useCursorAurora } from '@/hooks/useCursorAurora';
import { useReveal } from '@/hooks/useReveal';

/* ═══════════════════════════════════════════════════════════════════════════
   Landing — the product's front door.

   The goal here is not to sell in the usual SaaS sense; it's to explain a
   technical product to technical evaluators. The page follows the same
   pipeline story the product itself follows:

       Discover → Evidence → CBOM → Classify → Risk → Recommend → Plan

   Every claim on this page is grounded in an actual capability in the code.
   The old copy invented repositories, invented metrics, and used terminology
   the backend does not use ("SNDL"). This version says only what is true.
   ═══════════════════════════════════════════════════════════════════════════ */

export const Landing: React.FC = () => {
  const navigate = useNavigate();
  // Cursor aurora on the landing only. The hook is a no-op on touch devices
  // and when the OS asks for reduced motion.
  useCursorAurora();

  return (
    <div className="relative min-h-screen bg-[color:var(--color-canvas)] font-sans text-[color:var(--color-ink)] selection:bg-[color:var(--color-accent)]/25">
      {/* Background layers — fixed, non-interactive.
          1. Canvas: live grid with pulsing cells, scan beam, and real
             crypto glyphs flickering in. Draws the grid itself; no CSS grid.
          2. Aurora spotlight: cursor-tracked accent halo on top.
          Both sit at z-index 0; content lives on z-10 (see wrapper below). */}
      <AnimatedBackground />
      <div className="aurora-layer" aria-hidden="true" />

      <div className="relative z-10">
        <Navbar />

        <Hero onOpenConsole={() => navigate('/dashboard')} onGoToScan={() => navigate('/scan')} />
        <Reveal><ProblemSection /></Reveal>
        <Reveal variant="rise"><PipelineSection /></Reveal>
        <Reveal><CoverageSection /></Reveal>
        <Reveal variant="rise"><MoscaSection /></Reveal>
        <Reveal><CbomSection /></Reveal>
        <Reveal variant="soft"><ClosingCta onOpenConsole={() => navigate('/dashboard')} /></Reveal>

        <Footer />
      </div>
    </div>
  );
};

/* ─── Reveal — small wrapper that flips `.is-revealed` when the element scrolls
   into view. One-shot; the animation runs once and never flickers on return. */

interface RevealProps {
  children: React.ReactNode;
  variant?: 'default' | 'soft' | 'rise' | 'slide-x';
  delay?: number;
  className?: string;
}

const Reveal: React.FC<RevealProps> = ({ children, variant = 'default', delay = 0, className = '' }) => {
  const { ref, revealed } = useReveal<HTMLDivElement>();
  const v = variant === 'default' ? '' : `reveal-target--${variant}`;
  return (
    <div
      ref={ref}
      className={`reveal-target ${v} ${revealed ? 'is-revealed' : ''} ${className}`}
      style={delay ? { transitionDelay: `${delay}ms` } : undefined}
    >
      {children}
    </div>
  );
};

/* ═══════════════════════════════════════════════════════════════════════════
   Hero
   ─────────────────────────────────────────────────────────────────────────
   Left column: real product pitch grounded in the pipeline.
   Right column: an instrument-panel viewport showing an artefact moving
   through the seven stages — the pipeline story compressed into 4 seconds
   of motion. Not decorative; it's what the product does.
   ═══════════════════════════════════════════════════════════════════════════ */

const Hero: React.FC<{ onOpenConsole: () => void; onGoToScan: () => void }> = ({
  onOpenConsole,
  onGoToScan,
}) => (
  <section className="relative overflow-hidden border-b border-[color:var(--color-border-subtle)] pb-24 pt-32 md:pt-40">
    {/* The fixed aurora-grid layer already provides the grid + cursor beam.
        No local decorative gradient is needed here. */}
    <div className="relative mx-auto grid max-w-7xl grid-cols-1 gap-16 px-6 lg:grid-cols-[1.05fr_1fr] lg:items-center lg:px-8">
      {/* Left: pitch */}
      <div className="reveal-in max-w-2xl">
        <span className="inline-flex items-center gap-2 rounded-full border border-[color:var(--color-border-subtle)] bg-[color:var(--color-panel)] px-3 py-1 font-mono text-[11px] font-medium uppercase tracking-[0.16em] text-[color:var(--color-accent)]">
          <span className="h-1.5 w-1.5 rounded-full bg-[color:var(--color-accent)]" />
          Enterprise cryptographic discovery
        </span>

        <h1 className="mt-6 text-[40px] font-semibold leading-[1.05] tracking-tight text-[color:var(--color-ink)] md:text-[56px]">
          Discover cryptography before you migrate it.
        </h1>

        <p className="mt-5 max-w-xl text-base leading-relaxed text-[color:var(--color-ink-muted)] md:text-lg">
          Blindspot ECDAT scans source code, dependencies, binaries, container images and
          live TLS endpoints — then classifies every finding against Mosca&rsquo;s inequality
          to tell you exactly which cryptography is overdue for post-quantum migration and
          which can safely wait.
        </p>

        <div className="mt-8 flex flex-wrap items-center gap-3">
          <button
            onClick={onOpenConsole}
            className="group inline-flex items-center gap-2 rounded-md bg-[color:var(--color-accent)] px-5 py-2.5 text-sm font-semibold text-[color:var(--color-canvas)] transition-all hover:bg-[color:var(--color-accent-strong)]"
          >
            <Icon name="activity" size={16} />
            Open the console
            <Icon name="arrow-right" size={14} className="transition-transform group-hover:translate-x-0.5" />
          </button>
          <button
            onClick={onGoToScan}
            className="inline-flex items-center gap-2 rounded-md border border-[color:var(--color-border-strong)] bg-[color:var(--color-panel)] px-5 py-2.5 text-sm font-medium text-[color:var(--color-ink)] transition-colors hover:border-[color:var(--color-accent)]/40 hover:text-[color:var(--color-accent)]"
          >
            <Icon name="play" size={14} />
            Run a scan
          </button>
          <a
            href="#how-it-works"
            className="ml-2 hidden text-sm text-[color:var(--color-ink-muted)] hover:text-[color:var(--color-ink)] md:inline-flex"
          >
            See how it works &rarr;
          </a>
        </div>

        {/* Provenance strip — the *how* behind the claim, so it reads as a
            product rather than a poster. */}
        <dl className="mt-10 grid grid-cols-3 gap-x-6 gap-y-4 border-t border-[color:var(--color-border-subtle)] pt-6 text-xs">
          <ProvenanceCell k="Standard" v="CycloneDX 1.6" />
          <ProvenanceCell k="PQC Targets" v="ML-KEM · ML-DSA" />
          <ProvenanceCell k="Framework" v="Mosca (X + Y > Z)" />
        </dl>
      </div>

      {/* Right: instrument viewport */}
      <HeroViewport />
    </div>
  </section>
);

const ProvenanceCell: React.FC<{ k: string; v: string }> = ({ k, v }) => (
  <div>
    <dt className="eyebrow-muted">{k}</dt>
    <dd className="mt-1 font-mono text-sm font-semibold text-[color:var(--color-ink)]">{v}</dd>
  </div>
);

/* ─── Hero viewport ──────────────────────────────────────────────────────── */

interface Frame {
  eyebrow: string;
  title: string;
  body: React.ReactNode;
}

const ProvenanceLine: React.FC<{ k: string; v: string; tint?: string }> = ({ k, v, tint }) => (
  <div className="flex items-center justify-between border-b border-[color:var(--color-border-subtle)]/60 pb-1 text-[color:var(--color-ink-muted)]">
    <span className="text-[color:var(--color-ink-faint)]">{k}</span>
    <span style={tint ? { color: tint } : undefined} className="text-[color:var(--color-ink)]">{v}</span>
  </div>
);

const FRAMES: Frame[] = [
  {
    eyebrow: 'Stage 01 · Discover',
    title: 'RSA key generation matched in source',
    body: (
      <div className="rounded border border-[color:var(--color-border-subtle)] bg-[color:var(--color-canvas)] px-3 py-2 font-mono text-[12px] leading-relaxed text-[color:var(--color-ink-muted)]">
        <div>
          <span className="text-[color:var(--color-ink-faint)]">auth.py:42 </span>
        </div>
        <div>
          <span className="text-[color:var(--color-accent)]">key</span>
          <span> = </span>
          <span className="text-[color:var(--color-accent)]">RSA</span>
          <span className="text-[color:var(--color-ink)]">.generate</span>
          <span className="text-[color:var(--color-ink-faint)]">(</span>
          <span className="text-[#E9A73A]">2048</span>
          <span className="text-[color:var(--color-ink-faint)]">)</span>
        </div>
      </div>
    ),
  },
  {
    eyebrow: 'Stage 02 · Evidence',
    title: 'Detection method + confidence recorded',
    body: (
      <div className="space-y-1 font-mono text-[12px]">
        <ProvenanceLine k="Detection" v="semgrep_ast_confirmed" />
        <ProvenanceLine k="Rule" v="crypto.rsa-key-generation" />
        <ProvenanceLine k="Confidence" v="0.95 · High" tint="var(--color-low-risk)" />
      </div>
    ),
  },
  {
    eyebrow: 'Stage 03 · CBOM',
    title: 'Serialised into a CycloneDX asset',
    body: (
      <div className="font-mono text-[11.5px] leading-relaxed text-[color:var(--color-ink-muted)]">
        <span className="text-[color:var(--color-ink-faint)]">&#123; </span>
        <span className="text-[color:var(--color-accent)]">&quot;type&quot;</span>: <span>&quot;cryptographic-asset&quot;</span>,
        <br />
        &nbsp;&nbsp;<span className="text-[color:var(--color-accent)]">&quot;algorithm&quot;</span>: <span>&quot;RSA-2048&quot;</span>,
        <br />
        &nbsp;&nbsp;<span className="text-[color:var(--color-accent)]">&quot;usage&quot;</span>: <span>&quot;key_establishment&quot;</span>
        <br />
        <span className="text-[color:var(--color-ink-faint)]">&#125;</span>
      </div>
    ),
  },
  {
    eyebrow: 'Stage 05 · Risk',
    title: 'Overdue under Mosca',
    body: (
      <div className="pt-1">
        <MoscaVisualiser x={5} y={3} z={7} zLabel="Demo default" compact />
      </div>
    ),
  },
  {
    eyebrow: 'Stage 06 · Recommend',
    title: 'Migrate to ML-KEM-768 (FIPS 203)',
    body: (
      <div className="space-y-1.5 font-mono text-[12px] leading-relaxed">
        <div className="flex items-center gap-2 text-[color:var(--color-ink)]">
          <span className="text-[color:var(--color-ink-faint)]">RSA-2048</span>
          <Icon name="arrow-right" size={12} className="text-[color:var(--color-accent)]" />
          <span className="font-semibold text-[color:var(--color-accent)]">ML-KEM-768</span>
        </div>
        <ProvenanceLine k="Category" v="NIST FIPS 203 · Cat 3" />
        <ProvenanceLine k="Public key" v="1184 B · vs ~256 B classical" />
      </div>
    ),
  },
];

const HeroViewport: React.FC = () => {
  const [i, setI] = useState(0);
  const tiltRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const t = window.setInterval(() => setI((prev) => (prev + 1) % FRAMES.length), 3500);
    return () => window.clearInterval(t);
  }, []);

  // Subtle cursor tilt on the viewport. rAF-throttled, written to CSS custom
  // properties so React never re-renders on mousemove. Skipped on touch
  // devices and reduced-motion setups.
  useEffect(() => {
    const el = tiltRef.current;
    if (!el) return;
    const isCoarse = window.matchMedia?.('(pointer: coarse)').matches;
    const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    if (isCoarse || reduced) return;

    let raf = 0;
    const handle = (e: MouseEvent) => {
      if (raf) return;
      raf = window.requestAnimationFrame(() => {
        const rect = el.getBoundingClientRect();
        const cx = rect.left + rect.width / 2;
        const cy = rect.top + rect.height / 2;
        // Normalise to -1..1 across a generous 700px radius so the effect
        // only kicks in when the cursor is *near* the viewport.
        const nx = Math.max(-1, Math.min(1, (e.clientX - cx) / 700));
        const ny = Math.max(-1, Math.min(1, (e.clientY - cy) / 700));
        // Max 1.6°; anything more and it becomes gimmicky.
        el.style.setProperty('--tilt-x', `${(-ny * 1.6).toFixed(2)}deg`);
        el.style.setProperty('--tilt-y', `${(nx * 1.6).toFixed(2)}deg`);
        raf = 0;
      });
    };
    window.addEventListener('mousemove', handle, { passive: true });
    return () => {
      window.removeEventListener('mousemove', handle);
      if (raf) cancelAnimationFrame(raf);
    };
  }, []);

  const frame = FRAMES[i];

  return (
    <div
      ref={tiltRef}
      className="hero-tilt reveal-in relative rounded-xl border border-[color:var(--color-border-subtle)] bg-[color:var(--color-panel)] p-3"
      style={{
        transform: 'perspective(1400px) rotateX(var(--tilt-x, 0deg)) rotateY(var(--tilt-y, 0deg))',
      }}
    >
      {/* Instrument chrome */}
      <div className="flex items-center justify-between rounded-t-lg border-b border-[color:var(--color-border-subtle)] bg-[color:var(--color-canvas)] px-4 py-2.5">
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-[#3E4652]" />
          <span className="h-2 w-2 rounded-full bg-[#3E4652]" />
          <span className="h-2 w-2 rounded-full bg-[color:var(--color-accent)]/70" />
          <span className="ml-2 font-mono text-[11px] uppercase tracking-widest text-[color:var(--color-ink-faint)]">
            Blindspot · trace
          </span>
        </div>
        <span className="flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-widest text-[color:var(--color-accent)]">
          <span className="relative flex h-1.5 w-1.5">
            <span className="absolute inset-0 animate-ping rounded-full bg-[color:var(--color-accent)]/60" />
            <span className="relative h-1.5 w-1.5 rounded-full bg-[color:var(--color-accent)]" />
          </span>
          Scanning
        </span>
      </div>

      {/* Frame body */}
      <div className="relative min-h-[280px] overflow-hidden rounded-b-lg bg-[color:var(--color-canvas)] p-6">
        <div className="grid-lines-dense pointer-events-none absolute inset-0 opacity-40" />
        <div className="scanline pointer-events-none" />
        <div key={i} className="reveal-in relative">
          <span className="font-mono text-[11px] font-semibold uppercase tracking-[0.16em] text-[color:var(--color-accent)]">
            {frame.eyebrow}
          </span>
          <h3 className="mt-1.5 text-lg font-semibold text-[color:var(--color-ink)]">{frame.title}</h3>
          <div className="mt-4 max-w-md">{frame.body}</div>
        </div>

        {/* Frame indicator */}
        <div className="absolute inset-x-6 bottom-4 flex items-center gap-1.5">
          {FRAMES.map((_, idx) => (
            <span
              key={idx}
              className={`h-[2px] flex-1 rounded-full transition-colors ${
                idx === i ? 'bg-[color:var(--color-accent)]' : 'bg-[color:var(--color-border-subtle)]'
              }`}
            />
          ))}
        </div>
      </div>
    </div>
  );
};

/* ═══════════════════════════════════════════════════════════════════════════
   Problem — why any of this matters, in the product's own terminology
   ═══════════════════════════════════════════════════════════════════════════ */

const ProblemSection: React.FC = () => (
  <section id="product" className="border-b border-[color:var(--color-border-subtle)] py-24">
    <div className="mx-auto max-w-7xl px-6 lg:px-8">
      <div className="max-w-2xl">
        <SectionEyebrow>The problem</SectionEyebrow>
        <h2 className="mt-4 text-3xl font-semibold leading-tight text-[color:var(--color-ink)] md:text-4xl">
          Cryptography is everywhere.
          <br />
          <span className="text-[color:var(--color-ink-muted)]">Visibility into it isn&apos;t.</span>
        </h2>
        <p className="mt-4 max-w-xl text-sm leading-relaxed text-[color:var(--color-ink-muted)] md:text-base">
          Shor&apos;s algorithm breaks RSA and ECC outright. Any confidential data protected today
          with quantum-vulnerable cryptography is a Harvest-Now-Decrypt-Later exposure the moment
          an attacker records it. Migration takes years. You cannot migrate what you cannot find.
        </p>
      </div>

      <div className="mt-14 grid gap-px overflow-hidden rounded-xl border border-[color:var(--color-border-subtle)] bg-[color:var(--color-border-subtle)] md:grid-cols-4">
        {[
          {
            title: 'Where is cryptography used?',
            body: 'Buried inside first-party code, dependency lockfiles, static and dynamic libraries, container base images, IaC declarations, and live TLS endpoints. Rarely inventoried.',
            icon: 'search' as IconName,
          },
          {
            title: 'Which algorithms are vulnerable?',
            body: 'RSA, ECDH, ECDSA and DH are broken by Shor. AES and SHA-family are weakened by Grover but remain adequate with larger parameters.',
            icon: 'alert-triangle' as IconName,
          },
          {
            title: 'How urgent is this asset?',
            body: 'Mosca: if the data must stay secret for X years and migration takes Y years, and a quantum computer arrives in Z years, then X + Y > Z means you are overdue.',
            icon: 'clock' as IconName,
          },
          {
            title: 'What should replace it?',
            body: 'NIST-approved ML-KEM and ML-DSA (FIPS 203, 204), or a hybrid classical + PQC transition — chosen by usage, criticality, and cost.',
            icon: 'target' as IconName,
          },
        ].map((q, idx) => (
          <Reveal key={q.title} variant="soft" delay={idx * 90}>
            <div className="flex h-full flex-col gap-3 bg-[color:var(--color-panel)] p-6">
              <Icon name={q.icon} size={16} className="text-[color:var(--color-accent)]" />
              <h3 className="text-sm font-semibold text-[color:var(--color-ink)]">{q.title}</h3>
              <p className="text-xs leading-relaxed text-[color:var(--color-ink-muted)]">{q.body}</p>
            </div>
          </Reveal>
        ))}
      </div>
    </div>
  </section>
);

/* ═══════════════════════════════════════════════════════════════════════════
   Pipeline — the seven stages, told interactively
   ═══════════════════════════════════════════════════════════════════════════ */

const PipelineSection: React.FC = () => (
  <section id="how-it-works" className="border-b border-[color:var(--color-border-subtle)] py-24">
    <div className="mx-auto max-w-7xl px-6 lg:px-8">
      <div className="max-w-2xl">
        <SectionEyebrow>How ECDAT works</SectionEyebrow>
        <h2 className="mt-4 text-3xl font-semibold leading-tight text-[color:var(--color-ink)] md:text-4xl">
          Seven stages, one contract.
        </h2>
        <p className="mt-4 max-w-xl text-sm leading-relaxed text-[color:var(--color-ink-muted)] md:text-base">
          Discovery, evidence, CBOM, classification, risk, recommendation, plan. Each stage
          consumes the same normalised finding contract, so a new discovery source — TLS
          probes, container images, HSM declarations — plugs in without changing the analysis.
        </p>
      </div>

      <div className="mt-12">
        <PipelineTrace />
      </div>
    </div>
  </section>
);

/* ═══════════════════════════════════════════════════════════════════════════
   Coverage — real capabilities only. Every claim here maps to a scanner
   that exists in `backend/app/scanner/` today.
   ═══════════════════════════════════════════════════════════════════════════ */

interface CoverageItem {
  title: string;
  detail: string;
  icon: IconName;
  provenance: string;
}

const COVERAGE: CoverageItem[] = [
  {
    title: 'Source code',
    detail: 'Semgrep AST rules for Python and OpenSSL-style C. Detects RSA, ECC, DH, AES, DES, MD5, SHA-1 with parameter resolution.',
    icon: 'file-code',
    provenance: 'AST-confirmed · High confidence',
  },
  {
    title: 'Dependency manifests',
    detail: 'requirements.txt and equivalent lockfile parsers flag crypto-providing packages (pycryptodome, cryptography, and more).',
    icon: 'file-json',
    provenance: 'Manifest-declared · Informational',
  },
  {
    title: 'Container images',
    detail: 'Pulls an image via a host CLI, safely flattens its layers (zip-slip / symlink / bomb-guarded), then reuses source + dependency scanners against the rootfs.',
    icon: 'layers',
    provenance: 'Reuses source pipeline · High confidence',
  },
  {
    title: 'Compiled binaries',
    detail: 'Fingerprints SHA-2 / SHA-1 / MD5 / AES constants, ASN.1 OIDs, and library brand strings (OpenSSL, wolfSSL, mbedTLS). Every hit routes to manual verification.',
    icon: 'cpu',
    provenance: 'Fingerprint · Low confidence · verify',
  },
  {
    title: 'HSM / KMS declarations',
    detail: 'Reads Terraform, CloudFormation, Kubernetes and PKCS#11 configs for AWS KMS, GCP KMS, Azure Key Vault, CloudHSM, SoftHSM, YubiHSM, Luna, nShield.',
    icon: 'shield',
    provenance: 'Declared · Not attested',
  },
  {
    title: 'Live TLS / certificates',
    detail: 'Real socket handshake reads a host&apos;s cert, negotiated protocol and cipher. The cert&apos;s public key runs through the same classify → risk → recommend chain.',
    icon: 'lock',
    provenance: 'Live probe · Public hosts only',
  },
];

const CoverageSection: React.FC = () => (
  <section id="features" className="border-b border-[color:var(--color-border-subtle)] bg-[color:var(--color-panel)]/40 py-24">
    <div className="mx-auto max-w-7xl px-6 lg:px-8">
      <div className="flex flex-wrap items-end justify-between gap-6">
        <div className="max-w-2xl">
          <SectionEyebrow>What we scan</SectionEyebrow>
          <h2 className="mt-4 text-3xl font-semibold leading-tight text-[color:var(--color-ink)] md:text-4xl">
            Six discovery surfaces. One normalised finding.
          </h2>
        </div>
        <p className="max-w-md text-sm leading-relaxed text-[color:var(--color-ink-muted)]">
          Every discovery source emits the same shape, so classification, risk analysis and
          recommendations run identically across code, containers, binaries, IaC and the network.
        </p>
      </div>

      <div className="mt-12 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {COVERAGE.map((item, idx) => (
          <Reveal key={item.title} variant="soft" delay={idx * 80}>
          <article
            className="group relative h-full overflow-hidden rounded-lg border border-[color:var(--color-border-subtle)] bg-[color:var(--color-panel)] p-5 transition-colors hover:border-[color:var(--color-border-strong)]"
          >
            <div className="flex items-start gap-3">
              <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-[color:var(--color-border-subtle)] bg-[color:var(--color-canvas)] text-[color:var(--color-accent)] transition-colors group-hover:border-[color:var(--color-accent)]/40">
                <Icon name={item.icon} size={16} />
              </span>
              <div className="min-w-0 flex-1">
                <h3 className="text-sm font-semibold text-[color:var(--color-ink)]">{item.title}</h3>
                <p className="mt-1.5 text-xs leading-relaxed text-[color:var(--color-ink-muted)]">
                  {item.detail}
                </p>
              </div>
            </div>
            <div className="mt-4 border-t border-[color:var(--color-border-subtle)] pt-3">
              <span className="eyebrow-muted">Provenance</span>
              <p className="mt-1 font-mono text-[11px] text-[color:var(--color-ink)]">
                {item.provenance}
              </p>
            </div>
          </article>
          </Reveal>
        ))}
      </div>
    </div>
  </section>
);

/* ═══════════════════════════════════════════════════════════════════════════
   Mosca — the product's conceptual centre. A real visualiser, real numbers.
   ═══════════════════════════════════════════════════════════════════════════ */

const MoscaSection: React.FC = () => {
  // Three real preset comparisons from the compliance sensitivity engine.
  // Same X = 5, Y = 3; the finding re-tiers as Z changes.
  const scenarios: { name: string; z: number; label: string }[] = [
    { name: 'CRQC estimate', z: 15, label: 'Mid-range expert survey' },
    { name: 'NIST IR 8547', z: 10, label: '2030 deprecation window' },
    { name: 'India CII 2027', z: 1, label: 'MeitY Category A deadline' },
  ];
  const [active, setActive] = useState(0);
  const s = scenarios[active];

  return (
    <section id="mosca" className="border-b border-[color:var(--color-border-subtle)] py-24">
      <div className="mx-auto max-w-7xl px-6 lg:px-8">
        <div className="grid gap-12 lg:grid-cols-[1fr_1.1fr] lg:items-center">
          <div>
            <SectionEyebrow accent="hndl">Mosca&apos;s inequality</SectionEyebrow>
            <h2 className="mt-4 text-3xl font-semibold leading-tight text-[color:var(--color-ink)] md:text-4xl">
              Urgency is not an opinion.
              <br />
              <span className="text-[color:var(--color-ink-muted)]">It&apos;s an inequality.</span>
            </h2>
            <p className="mt-4 text-sm leading-relaxed text-[color:var(--color-ink-muted)] md:text-base">
              For every finding we compute the sum of data lifetime (<span className="font-mono text-[color:var(--color-accent)]">X</span>) and migration
              time (<span className="font-mono text-[#B090F5]">Y</span>) against the assumed quantum horizon (<span className="font-mono text-[color:var(--color-ink)]">Z</span>). If the sum
              exceeds Z, the finding is overdue. Z is a policy choice — regulator, research
              estimate, or your own — and the same finding re-tiers as Z changes.
            </p>

            {/* Preset selector — real scenarios from the compliance engine. */}
            <div className="mt-6 flex flex-wrap gap-2">
              {scenarios.map((sc, idx) => {
                const isActive = idx === active;
                return (
                  <button
                    key={sc.name}
                    onClick={() => setActive(idx)}
                    className={`rounded-md border px-3 py-1.5 text-left transition-colors ${
                      isActive
                        ? 'border-[color:var(--color-accent)]/40 bg-[color:var(--color-accent-soft)] text-[color:var(--color-ink)]'
                        : 'border-[color:var(--color-border-subtle)] bg-[color:var(--color-panel)] text-[color:var(--color-ink-muted)] hover:border-[color:var(--color-border-strong)]'
                    }`}
                  >
                    <div className="font-mono text-[11px] font-semibold uppercase tracking-widest">
                      {sc.name}
                    </div>
                    <div className="mt-0.5 font-mono text-[10px] text-[color:var(--color-ink-faint)]">
                      Z = {sc.z}y
                    </div>
                  </button>
                );
              })}
            </div>

            <p className="mt-4 text-xs leading-relaxed text-[color:var(--color-ink-muted)]">
              Same asset. Different regulatory horizon. Different tier.{' '}
              <span className="text-[color:var(--color-ink)]">This is what compliance sensitivity means.</span>
            </p>
          </div>

          <div className="reveal-in rounded-2xl border border-[color:var(--color-border-subtle)] bg-[color:var(--color-panel)] p-6">
            <div className="mb-4 flex items-center justify-between">
              <div>
                <span className="eyebrow-muted">Example finding</span>
                <p className="mt-1 font-mono text-sm text-[color:var(--color-ink)]">
                  RSA-2048 · key establishment · auth.py:42
                </p>
                <p className="mt-0.5 text-[10px] uppercase tracking-widest text-[color:var(--color-ink-faint)]">
                  Illustrative · X = 5y · Y = 3y
                </p>
              </div>
              <RiskChip tier={s.z <= 8 ? 'overdue' : s.z <= 10 ? 'transitional' : 'low-risk'} size="md" />
            </div>
            <MoscaVisualiser x={5} y={3} z={s.z} zLabel={s.label} />
          </div>
        </div>
      </div>
    </section>
  );
};

/* ═══════════════════════════════════════════════════════════════════════════
   CBOM — real technical artefact
   ═══════════════════════════════════════════════════════════════════════════ */

const CbomSection: React.FC = () => (
  <section id="cbom" className="border-b border-[color:var(--color-border-subtle)] py-24">
    <div className="mx-auto max-w-7xl px-6 lg:px-8">
      <div className="grid gap-12 lg:grid-cols-[1fr_1fr] lg:items-start">
        <div>
          <SectionEyebrow>Portable output</SectionEyebrow>
          <h2 className="mt-4 text-3xl font-semibold leading-tight text-[color:var(--color-ink)] md:text-4xl">
            A CBOM your other tools already speak.
          </h2>
          <p className="mt-4 text-sm leading-relaxed text-[color:var(--color-ink-muted)] md:text-base">
            Every scan produces a schema-valid CycloneDX 1.6 <code className="font-mono text-[color:var(--color-accent)]">cryptographic-asset</code> document.
            Algorithm, parameter set, mode, OID, evidence path — the same shape a supply-chain
            or dependency tool would read. Export it, diff it against your last CBOM, feed it
            downstream. No proprietary format.
          </p>
          <div className="mt-6 grid grid-cols-2 gap-4">
            <KeyStat k="Schema" v="CycloneDX 1.6" />
            <KeyStat k="Validation" v="100% assertive" />
            <KeyStat k="Asset type" v="cryptographic-asset" />
            <KeyStat k="Export" v="Signed download" />
          </div>
        </div>

        <pre className="overflow-hidden rounded-xl border border-[color:var(--color-border-subtle)] bg-[color:var(--color-panel)] p-5 font-mono text-[11.5px] leading-relaxed text-[color:var(--color-ink-muted)]">
{`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "cryptographic-asset",
      "name": "RSA-2048",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "pke",
          "parameterSetIdentifier": "2048",
          "cryptoFunctions": ["encapsulate"],
          "nistQuantumSecurityLevel": 0
        }
      },
      "evidence": {
        "occurrences": [
          { "location": "auth.py:42" }
        ]
      }
    }
  ]
}`}
        </pre>
      </div>
    </div>
  </section>
);

const KeyStat: React.FC<{ k: string; v: string }> = ({ k, v }) => (
  <div className="rounded-md border border-[color:var(--color-border-subtle)] bg-[color:var(--color-panel)] px-3 py-2">
    <div className="eyebrow-muted">{k}</div>
    <div className="mt-1 font-mono text-sm text-[color:var(--color-ink)]">{v}</div>
  </div>
);

/* ═══════════════════════════════════════════════════════════════════════════
   Closing CTA
   ═══════════════════════════════════════════════════════════════════════════ */

const ClosingCta: React.FC<{ onOpenConsole: () => void }> = ({ onOpenConsole }) => (
  <section id="use-cases" className="border-b border-[color:var(--color-border-subtle)] py-24">
    <div className="mx-auto max-w-4xl px-6 text-center lg:px-8">
      <SectionEyebrow align="center">Ready when you are</SectionEyebrow>
      <h2 className="mt-4 text-3xl font-semibold leading-tight text-[color:var(--color-ink)] md:text-[42px]">
        Open the console. Scan a repository, a container, or a live host.
      </h2>
      <p className="mx-auto mt-4 max-w-xl text-sm leading-relaxed text-[color:var(--color-ink-muted)] md:text-base">
        Every finding on the dashboard is produced by a real scanner running on a real
        input. No fabricated numbers, no simulated data. That&apos;s the point.
      </p>
      <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
        <button
          onClick={onOpenConsole}
          className="inline-flex items-center gap-2 rounded-md bg-[color:var(--color-accent)] px-6 py-3 text-sm font-semibold text-[color:var(--color-canvas)] transition-colors hover:bg-[color:var(--color-accent-strong)]"
        >
          <Icon name="activity" size={16} />
          Open the console
          <Icon name="arrow-right" size={14} />
        </button>
      </div>
    </div>
  </section>
);

export default Landing;
