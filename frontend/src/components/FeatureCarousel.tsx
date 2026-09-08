import React, { useEffect, useState } from 'react';
import { Icon } from '@/components/Icon';
import { RiskBadge } from '@/components/RiskBadge';

interface CarouselSlide {
  id: string;
  stageNumber: string;
  stageTitle: string;
  badgeText: string;
  headline: string;
  description: string;
  metrics: { label: string; value: string }[];
  visualContent: React.ReactNode;
}

export const FeatureCarousel: React.FC = () => {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [isPaused, setIsPaused] = useState(false);

  const slides: CarouselSlide[] = [
    {
      id: 'scan-stage',
      stageNumber: '01',
      stageTitle: 'STAGE 1 — AST & DEPENDENCY SCANNER',
      badgeText: 'Semgrep + Manifest Parser',
      headline: 'Deep AST-aware discovery across source code & manifests',
      description:
        'Scans Python & Java source files with custom Semgrep rules while parsing lockfiles (requirements.txt, pom.xml). Detects RSA, ECC/ECDSA/ECDH, AES, DES/3DES, MD5, and SHA-1.',
      metrics: [
        { label: 'Language Support', value: 'Python & Java' },
        { label: 'Detection Method', value: 'AST + String Match' },
        { label: 'Confidence Score', value: '95% Average' },
      ],
      visualContent: (
        <div className="rounded-xl border border-[#222B35] bg-[#080B0F] p-4 font-mono text-xs space-y-3">
          <div className="flex items-center justify-between border-b border-[#222B35] pb-2 text-[11px] text-slate-400">
            <span className="flex items-center gap-2 text-[#7DB7E8]">
              <Icon name="file-code" size={14} />
              auth.py : Line 42
            </span>
            <span className="rounded bg-emerald-500/10 px-2 py-0.5 text-emerald-400 border border-emerald-500/30 text-[10px]">
              Semgrep Rule Matched
            </span>
          </div>
          <pre className="text-slate-300 bg-[#0C1117] p-3 rounded-lg overflow-x-auto text-[11px]">
            <span className="text-slate-500"># Security Module - Authentication & Key Exchange</span>{'\n'}
            <span className="text-purple-400">def</span> <span className="text-blue-400">initialize_session_keys</span>():{'\n'}
            {'    '}key = <span className="text-amber-300 font-bold bg-amber-500/10 px-1 rounded">RSA.generate(2048)</span>{'\n'}
            {'    '}private_key = key.export_key(){'\n'}
            {'    '}<span className="text-purple-400">return</span> private_key
          </pre>
          <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1">
            <span>Primitive: <strong className="text-slate-200">RSA-2048 (PKE)</strong></span>
            <span>Rule: <code className="text-[#7DB7E8]">blindspot.python.rsa</code></span>
          </div>
        </div>
      ),
    },
    {
      id: 'cbom-stage',
      stageNumber: '02',
      stageTitle: 'STAGE 2 — STANDARDIZED CBOM BUILDER',
      badgeText: 'CycloneDX v1.6 Cryptographic Spec',
      headline: 'Automated Cryptographic Bill of Materials generation',
      description:
        'Converts every discovered finding into schema-correct CycloneDX v1.6 cryptographic-asset objects. Standardizes primitives, parameter sets, OIDs, and code occurrences into cbom.json.',
      metrics: [
        { label: 'BOM Specification', value: 'CycloneDX v1.6' },
        { label: 'Asset Standard', value: 'cryptographic-asset' },
        { label: 'Schema Validation', value: '100% Compliant' },
      ],
      visualContent: (
        <div className="rounded-xl border border-[#222B35] bg-[#080B0F] p-4 font-mono text-xs space-y-3">
          <div className="flex items-center justify-between border-b border-[#222B35] pb-2 text-[11px] text-slate-400">
            <span className="flex items-center gap-2 text-emerald-400">
              <Icon name="check-circle" size={14} />
              cbom.json (Source of Truth)
            </span>
            <span className="rounded bg-[#7DB7E8]/10 px-2 py-0.5 text-[#7DB7E8] border border-[#7DB7E8]/30 text-[10px]">
              JSON Schema Validated
            </span>
          </div>
          <pre className="text-[#7DB7E8] bg-[#0C1117] p-3 rounded-lg overflow-x-auto text-[11px]">
{`{
  "type": "cryptographic-asset",
  "name": "RSA (2048-bit key establishment)",
  "bom-ref": "crypto-rsa-2048-001",
  "cryptoProperties": {
    "assetType": "key-exchange",
    "primitive": "pke",
    "algorithmProperties": {
      "variant": "RSA-2048",
      "parameterSetIdentifier": "2048"
    }
  }
}`}
          </pre>
        </div>
      ),
    },
    {
      id: 'classify-stage',
      stageNumber: '03',
      stageTitle: 'STAGE 3 — CRYPTOGRAPHIC CLASSIFIER',
      badgeText: 'Data Secrecy vs Authenticity Split',
      headline: 'Tags data lifetime (X) and business criticality',
      description:
        'Evaluates confidentiality vs authenticity requirements. Scores key exchange and encryption based on required secrecy lifetime (X years), flagging long-lived enterprise trust anchors.',
      metrics: [
        { label: 'Secrecy Lifetime (X)', value: '1 to 25+ Years' },
        { label: 'Criticality Levels', value: 'Low / Medium / High' },
        { label: 'Asset Taxonomy', value: '4 Core Categories' },
      ],
      visualContent: (
        <div className="rounded-xl border border-[#222B35] bg-[#080B0F] p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-[#222B35] pb-2 text-xs font-mono text-slate-400">
            <span>Artefact Categorization</span>
            <span className="text-[#C98A52] font-semibold">Security Goals</span>
          </div>
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="rounded-lg border border-[#7DB7E8]/30 bg-[#7DB7E8]/10 p-3">
              <span className="font-mono text-xs font-bold text-[#7DB7E8] block">Key Exchange & Encryption</span>
              <p className="mt-1 text-[11px] text-slate-300">Target for Store-Now-Decrypt-Later (SNDL) attacks. High secrecy lifetime X.</p>
            </div>
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3">
              <span className="font-mono text-xs font-bold text-amber-400 block">Signatures & Hashes</span>
              <p className="mt-1 text-[11px] text-slate-300">Ephemeral session signatures vs long-lived trust anchors (Code Signing).</p>
            </div>
          </div>
        </div>
      ),
    },
    {
      id: 'mosca-stage',
      stageNumber: '04',
      stageTitle: 'STAGE 4 — MOSCA RISK ENGINE',
      badgeText: "Michele Mosca's Inequality",
      headline: 'Evaluates quantum urgency against CRQC timelines',
      description:
        'Calculates X (data secrecy) + Y (migration lead time) vs Z (CRQC quantum horizon). Categorizes findings into Overdue, Transitional, Low-risk, or Weak Now.',
      metrics: [
        { label: 'Quantum Horizon (Z)', value: '2035 (10 Years)' },
        { label: 'Evaluation Model', value: 'X + Y > Z' },
        { label: 'Risk Tiers', value: '4 Tier Classifications' },
      ],
      visualContent: (
        <div className="rounded-xl border border-red-500/40 bg-red-500/10 p-4 font-mono space-y-3">
          <div className="flex items-center justify-between border-b border-red-500/30 pb-2 text-xs text-red-300">
            <span className="font-bold">Mosca Inequality Calculation</span>
            <RiskBadge tier="overdue" size="sm" />
          </div>
          <div className="text-center py-2">
            <div className="text-xl font-extrabold text-slate-100">
              <span className="text-[#7DB7E8]">15y</span> + <span className="text-[#C98A52]">3y</span> &gt; <span className="text-slate-300">10y</span>
            </div>
            <p className="mt-2 text-xs text-red-400 font-semibold">
              18 Years Total &gt; 10 Years Quantum Horizon $\implies$ OVERDUE
            </p>
          </div>
        </div>
      ),
    },
    {
      id: 'recommend-stage',
      stageNumber: '05',
      stageTitle: 'STAGE 5 — PQC RECOMMENDER',
      badgeText: 'Risk-Tiered Action Plan',
      headline: 'Deterministic PQC algorithm & strategy assignment',
      description:
        'Assigns actionable migration paths: Pure PQC (ML-KEM-768 / ML-DSA-65), Hybrid transition (X25519 + ML-KEM-768), Defer for low-risk session keys, or Immediate Remediation (SHA-256).',
      metrics: [
        { label: 'KEM Standard', value: 'NIST FIPS 203' },
        { label: 'Signature Standard', value: 'NIST FIPS 204' },
        { label: 'Hybrid Pattern', value: 'Dual-KEM Negotiation' },
      ],
      visualContent: (
        <div className="rounded-xl border border-[#222B35] bg-[#080B0F] p-4 text-xs space-y-2.5 font-mono">
          <div className="flex items-center justify-between border-b border-[#222B35] pb-2 text-slate-300">
            <span>Legacy Primitive</span>
            <span className="text-[#7DB7E8] font-bold">Recommended Action</span>
          </div>
          <div className="flex justify-between items-center bg-[#11171E] p-2 rounded border border-[#222B35]">
            <span className="text-slate-200 font-bold">RSA-2048</span>
            <span className="text-emerald-400 font-bold">Pure PQC: ML-KEM-768</span>
          </div>
          <div className="flex justify-between items-center bg-[#11171E] p-2 rounded border border-[#222B35]">
            <span className="text-slate-200 font-bold">X25519</span>
            <span className="text-amber-400 font-bold">Hybrid: X25519 + ML-KEM</span>
          </div>
          <div className="flex justify-between items-center bg-[#11171E] p-2 rounded border border-[#222B35]">
            <span className="text-slate-200 font-bold">MD5</span>
            <span className="text-rose-400 font-bold">Remediate: SHA-256</span>
          </div>
        </div>
      ),
    },
  ];

  // Auto-play feature every 5 seconds
  useEffect(() => {
    if (isPaused) return;
    const interval = setInterval(() => {
      setCurrentIndex((prev) => (prev + 1) % slides.length);
    }, 5000);
    return () => clearInterval(interval);
  }, [isPaused, slides.length]);

  const currentSlide = slides[currentIndex];

  const handlePrev = () => {
    setCurrentIndex((prev) => (prev === 0 ? slides.length - 1 : prev - 1));
  };

  const handleNext = () => {
    setCurrentIndex((prev) => (prev + 1) % slides.length);
  };

  return (
    <div
      onMouseEnter={() => setIsPaused(true)}
      onMouseLeave={() => setIsPaused(false)}
      className="relative mx-auto max-w-5xl rounded-2xl border border-[#7DB7E8]/40 bg-[#11171E] p-6 sm:p-8 shadow-[0_15px_40px_rgba(0,0,0,0.6)] transition-all hover:border-[#7DB7E8]/60"
    >
      {/* Top Banner Control Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#222B35] pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-[#7DB7E8]/30 bg-[#7DB7E8]/10 font-mono text-xs font-bold text-[#7DB7E8]">
            {currentSlide.stageNumber}
          </div>
          <div>
            <h3 className="font-mono text-xs font-bold tracking-wider text-[#7DB7E8] uppercase">
              {currentSlide.stageTitle}
            </h3>
            <span className="text-[11px] text-slate-400">{currentSlide.badgeText}</span>
          </div>
        </div>

        {/* Carousel Navigation Buttons */}
        <div className="flex items-center gap-2">
          <button
            onClick={handlePrev}
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-[#222B35] bg-[#0C1117] text-slate-400 transition-colors hover:border-[#7DB7E8] hover:text-white cursor-pointer"
            title="Previous Slide"
          >
            <Icon name="chevron-left" size={16} />
          </button>
          <span className="font-mono text-xs text-slate-400 px-2">
            {currentIndex + 1} / {slides.length}
          </span>
          <button
            onClick={handleNext}
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-[#222B35] bg-[#0C1117] text-slate-400 transition-colors hover:border-[#7DB7E8] hover:text-white cursor-pointer"
            title="Next Slide"
          >
            <Icon name="chevron-right" size={16} />
          </button>
        </div>
      </div>

      {/* Main Slide Content Grid */}
      <div className="mt-6 grid gap-8 md:grid-cols-2 items-center min-h-[280px]">
        {/* Left Side: Headline & Description */}
        <div className="space-y-4 animate-fade-in">
          <h2 className="text-2xl font-bold text-slate-100 tracking-tight leading-snug">
            {currentSlide.headline}
          </h2>
          <p className="text-xs text-slate-300 leading-relaxed font-sans">
            {currentSlide.description}
          </p>

          {/* Key Metrics */}
          <div className="grid grid-cols-3 gap-2 pt-2 border-t border-[#222B35]">
            {currentSlide.metrics.map((m, idx) => (
              <div key={idx} className="rounded border border-[#222B35] bg-[#080B0F] p-2 text-center">
                <span className="text-[10px] font-mono text-slate-500 block truncate">{m.label}</span>
                <span className="text-xs font-mono font-bold text-[#7DB7E8] block mt-0.5">{m.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Right Side: Interactive Visual Card */}
        <div className="transition-all duration-300 transform">
          {currentSlide.visualContent}
        </div>
      </div>

      {/* Bottom Indicator Dots & Auto-play Status */}
      <div className="mt-6 flex items-center justify-between border-t border-[#222B35] pt-4">
        <div className="flex items-center gap-2">
          {slides.map((_, idx) => (
            <button
              key={idx}
              onClick={() => setCurrentIndex(idx)}
              className={`h-2 rounded-full transition-all duration-300 cursor-pointer ${
                idx === currentIndex ? 'w-8 bg-[#7DB7E8]' : 'w-2 bg-[#222B35] hover:bg-slate-600'
              }`}
              title={`Go to slide ${idx + 1}`}
            />
          ))}
        </div>

        <span className="font-mono text-[11px] text-slate-500 flex items-center gap-1.5">
          <span className={`h-1.5 w-1.5 rounded-full ${isPaused ? 'bg-amber-400' : 'bg-emerald-400 animate-ping'}`} />
          {isPaused ? 'Paused (Hovering)' : 'Auto-playing (5s)'}
        </span>
      </div>
    </div>
  );
};
