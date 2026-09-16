import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { CBOMPreview } from '@/components/CBOMPreview';
import { CodeEvidence } from '@/components/CodeEvidence';
import { FeatureCarousel } from '@/components/FeatureCarousel';
import { Footer } from '@/components/Footer';
import { Icon } from '@/components/Icon';
import { MoscaCard } from '@/components/MoscaCard';
import { Navbar } from '@/components/Navbar';
import { RiskBadge } from '@/components/RiskBadge';
import { DEMO_PLANTED_FINDINGS } from '@/services/mockData';

export const Landing: React.FC = () => {
  const navigate = useNavigate();
  const [activeMoscaHover, setActiveMoscaHover] = useState<'x' | 'y' | 'z' | null>(null);
  const [targetRepo, setTargetRepo] = useState<string>('demo-repo');
  const [customPath, setCustomPath] = useState<string>('');

  const plantedOverdue = DEMO_PLANTED_FINDINGS[0];

  return (
    <div className="min-h-screen bg-[#080B0F] text-slate-100 font-sans selection:bg-[#7DB7E8]/30 selection:text-white">
      {/* Top Navbar */}
      <Navbar />

      {/* ---------------------------------------------------------------------
         HERO SECTION
         --------------------------------------------------------------------- */}
      <section className="relative overflow-hidden pt-32 pb-20 md:pt-40 md:pb-32">
        {/* Background subtle grid and ambient blue glow */}
        <div className="absolute inset-0 subtle-grid opacity-40 pointer-events-none" />
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 h-[400px] w-[600px] rounded-full bg-[#7DB7E8]/5 blur-[120px] pointer-events-none" />

        <div className="relative mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="mx-auto max-w-4xl text-center">
            {/* Eyebrow */}
            <div className="inline-flex items-center gap-2 rounded-full border border-[#7DB7E8]/30 bg-[#11171E] px-3.5 py-1 text-xs font-mono font-medium tracking-wider text-[#7DB7E8] mb-6">
              <span className="h-1.5 w-1.5 rounded-full bg-[#7DB7E8] animate-pulse" />
              ENTERPRISE CRYPTOGRAPHIC DISCOVERY
            </div>

            {/* Main Heading */}
            <h1 className="text-4xl font-extrabold tracking-tight text-slate-100 sm:text-6xl md:text-7xl leading-[1.1]">
              You cannot migrate <br className="hidden sm:inline" />
              cryptography{' '}
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#7DB7E8] via-[#9BC7EA] to-[#C98A52]">
                you cannot find.
              </span>
            </h1>

            {/* Supporting Copy */}
            <p className="mx-auto mt-6 max-w-2xl text-base text-slate-300 sm:text-lg leading-relaxed font-sans">
              Discover, assess, and fix quantum-vulnerable cryptography before it&apos;s too late.
            </p>

            {/* Target Repository Selector & Trigger Panel */}
            <div className="mx-auto mt-8 max-w-xl rounded-2xl border border-[#7DB7E8]/40 bg-[#11171E] p-6 shadow-2xl space-y-4">
              <div className="text-left">
                <label className="block text-xs font-mono font-bold uppercase tracking-wider text-slate-300 mb-2">
                  Select Target Repository for Discovery Scan
                </label>
                <div className="grid gap-3 sm:grid-cols-2">
                  <select
                    value={targetRepo}
                    onChange={(e) => {
                      setTargetRepo(e.target.value);
                      if (e.target.value !== 'custom') setCustomPath('');
                    }}
                    className="w-full rounded-xl border border-[#222B35] bg-[#080B0F] px-3.5 py-3 font-mono text-xs text-slate-100 focus:border-[#7DB7E8] focus:outline-none"
                  >
                    <option value="demo-repo">Seeded Demo Repo (Payments Vault)</option>
                    <option value="openssl-sample">OpenSSL 1.1.1 Sample Repository</option>
                    <option value="payments-microservice">Payments Microservice Core</option>
                    <option value="custom">Custom Repository Path…</option>
                  </select>

                  {targetRepo === 'custom' ? (
                    <input
                      type="text"
                      placeholder="/path/to/repository"
                      value={customPath}
                      onChange={(e) => setCustomPath(e.target.value)}
                      className="w-full rounded-xl border border-[#222B35] bg-[#080B0F] px-3.5 py-3 font-mono text-xs text-slate-100 placeholder:text-slate-600 focus:border-[#7DB7E8] focus:outline-none"
                    />
                  ) : (
                    <div className="flex items-center rounded-xl border border-[#222B35] bg-[#080B0F] px-3.5 py-3 font-mono text-xs text-slate-400">
                      <Icon name="check-circle" size={14} className="mr-2 text-emerald-400" />
                      <span>AST Rules Pre-configured</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Primary Action Button: Run Scan */}
              <button
                onClick={() => {
                  const path = targetRepo === 'custom' ? customPath : targetRepo;
                  navigate(`/scan?repo=${encodeURIComponent(path || 'demo-repo')}`);
                }}
                className="w-full flex items-center justify-center gap-3 rounded-xl border border-[#7DB7E8]/50 bg-[#7DB7E8] py-4 text-base font-bold text-[#080B0F] shadow-[0_0_30px_rgba(125,183,232,0.3)] transition-all hover:bg-[#9BC7EA] hover:shadow-[0_0_40px_rgba(125,183,232,0.5)] hover:scale-[1.01]"
              >
                <Icon name="play" size={18} />
                <span>Run Discovery Scan</span>
              </button>
            </div>

            {/* Three Compact Concepts */}
            <div className="mt-12 grid gap-4 sm:grid-cols-3 text-left">
              <div className="rounded-xl border border-[#222B35] bg-[#11171E]/80 p-4 backdrop-blur-sm">
                <div className="flex items-center gap-2 text-xs font-bold text-[#7DB7E8]">
                  <Icon name="search" size={15} />
                  <span>Discover</span>
                </div>
                <p className="mt-1 text-xs text-slate-400">Find cryptographic usage across code & dependencies</p>
              </div>

              <div className="rounded-xl border border-[#222B35] bg-[#11171E]/80 p-4 backdrop-blur-sm">
                <div className="flex items-center gap-2 text-xs font-bold text-[#C98A52]">
                  <Icon name="clock" size={15} />
                  <span>Assess</span>
                </div>
                <p className="mt-1 text-xs text-slate-400">Evaluate quantum risk using Mosca&apos;s inequality</p>
              </div>

              <div className="rounded-xl border border-[#222B35] bg-[#11171E]/80 p-4 backdrop-blur-sm">
                <div className="flex items-center gap-2 text-xs font-bold text-emerald-400">
                  <Icon name="target" size={15} />
                  <span>Prioritize</span>
                </div>
                <p className="mt-1 text-xs text-slate-400">Get clear PQC, Hybrid, or Defer recommendations</p>
              </div>
            </div>
          </div>

          {/* Hero Visual: Realistic ECDAT Product Visualization */}
          <div className="mt-14 relative mx-auto max-w-5xl rounded-2xl border border-[#222B35] bg-[#0C1117] p-2 shadow-[0_20px_50px_rgba(0,0,0,0.8)] animate-fade-in">
            {/* Top scanning animation line */}
            <div className="absolute inset-x-0 top-0 h-0.5 bg-gradient-to-r from-transparent via-[#7DB7E8] to-transparent animate-scanline" />

            <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-6">
              {/* Product Top Header */}
              <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#222B35] pb-4">
                <div className="flex items-center gap-3">
                  <div className="flex h-3 w-3 rounded-full bg-red-500/80" />
                  <div className="flex h-3 w-3 rounded-full bg-amber-500/80" />
                  <div className="flex h-3 w-3 rounded-full bg-emerald-500/80" />
                  <span className="font-mono text-xs text-slate-400 ml-2">
                    Blindspot ECDAT — Cryptographic Posture Overview
                  </span>
                </div>
                <span className="rounded bg-emerald-500/10 px-2.5 py-1 font-mono text-xs text-emerald-400 border border-emerald-500/30">
                  Live Posture: 5 Artefacts Analyzed
                </span>
              </div>

              {/* Product Cards Row */}
              <div className="my-6 grid gap-4 grid-cols-2 lg:grid-cols-5">
                <div className="rounded-lg border border-[#222B35] bg-[#080B0F] p-3.5">
                  <span className="text-[11px] font-semibold text-slate-400">Total Assets</span>
                  <p className="mt-1 font-mono text-2xl font-bold text-slate-100">5</p>
                </div>
                <div className="rounded-lg border border-[#222B35] bg-[#080B0F] p-3.5">
                  <span className="text-[11px] font-semibold text-slate-400">Findings</span>
                  <p className="mt-1 font-mono text-2xl font-bold text-[#7DB7E8]">5</p>
                </div>
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3.5">
                  <span className="text-[11px] font-semibold text-red-400">Overdue</span>
                  <p className="mt-1 font-mono text-2xl font-bold text-red-400">2</p>
                </div>
                <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3.5">
                  <span className="text-[11px] font-semibold text-amber-400">Transitional</span>
                  <p className="mt-1 font-mono text-2xl font-bold text-amber-400">1</p>
                </div>
                <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3.5">
                  <span className="text-[11px] font-semibold text-emerald-400">Low Risk</span>
                  <p className="mt-1 font-mono text-2xl font-bold text-emerald-400">1</p>
                </div>
              </div>

              {/* Planted Findings Table Mockup */}
              <div className="rounded-lg border border-[#222B35] bg-[#080B0F] overflow-hidden">
                <table className="w-full text-left font-mono text-xs">
                  <thead className="border-b border-[#222B35] bg-[#0C1117] text-[11px] text-slate-400">
                    <tr>
                      <th className="px-4 py-2.5">Algorithm</th>
                      <th className="px-4 py-2.5">Location</th>
                      <th className="px-4 py-2.5">Risk Tier</th>
                      <th className="px-4 py-2.5">Recommendation</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#222B35]">
                    <tr className="bg-[#11171E]/60">
                      <td className="px-4 py-3 font-bold text-slate-100">RSA-2048</td>
                      <td className="px-4 py-3 text-slate-400">auth.py:42</td>
                      <td className="px-4 py-3"><RiskBadge tier="overdue" size="sm" /></td>
                      <td className="px-4 py-3 text-[#7DB7E8]">ML-KEM-768</td>
                    </tr>
                    <tr className="bg-[#11171E]/30">
                      <td className="px-4 py-3 font-bold text-slate-100">X25519</td>
                      <td className="px-4 py-3 text-slate-400">tls.py:18</td>
                      <td className="px-4 py-3"><RiskBadge tier="transitional" size="sm" /></td>
                      <td className="px-4 py-3 text-amber-400">X25519 + ML-KEM-768</td>
                    </tr>
                    <tr className="bg-[#11171E]/60">
                      <td className="px-4 py-3 font-bold text-slate-100">MD5</td>
                      <td className="px-4 py-3 text-slate-400">legacy.py:91</td>
                      <td className="px-4 py-3"><RiskBadge tier="weak-now" size="sm" /></td>
                      <td className="px-4 py-3 text-rose-400">Replace with SHA-256</td>
                    </tr>
                    <tr className="bg-[#11171E]/30">
                      <td className="px-4 py-3 font-bold text-slate-100">ECDSA</td>
                      <td className="px-4 py-3 text-slate-400">signing.py:64</td>
                      <td className="px-4 py-3"><RiskBadge tier="low-risk" size="sm" /></td>
                      <td className="px-4 py-3 text-emerald-400">Defer / Monitor</td>
                    </tr>
                    <tr className="bg-[#11171E]/60">
                      <td className="px-4 py-3 font-bold text-slate-100">RSA (Dynamic)</td>
                      <td className="px-4 py-3 text-slate-400">config.py:27</td>
                      <td className="px-4 py-3">
                        <span className="rounded bg-amber-500/10 px-1.5 py-0.5 font-mono text-[10px] text-amber-400 border border-amber-500/30">
                          Unresolved
                        </span>
                      </td>
                      <td className="px-4 py-3 text-slate-300">Investigate / Audit</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ---------------------------------------------------------------------
         TRUST / METRICS STRIP
         --------------------------------------------------------------------- */}
      <section className="border-y border-[#222B35] bg-[#0C1117] py-10">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-2 gap-8 md:grid-cols-4 text-center">
            <div>
              <div className="font-mono text-3xl font-extrabold text-[#7DB7E8] md:text-4xl">5</div>
              <p className="mt-1 text-xs font-medium uppercase tracking-wider text-slate-400">Analysis Stages</p>
            </div>
            <div>
              <div className="font-mono text-3xl font-extrabold text-[#7DB7E8] md:text-4xl">1</div>
              <p className="mt-1 text-xs font-medium uppercase tracking-wider text-slate-400">Standardized CBOM</p>
            </div>
            <div>
              <div className="font-mono text-3xl font-extrabold text-[#7DB7E8] md:text-4xl">3</div>
              <p className="mt-1 text-xs font-medium uppercase tracking-wider text-slate-400">Migration Strategies</p>
            </div>
            <div>
              <div className="font-mono text-3xl font-extrabold text-emerald-400 md:text-4xl">100%</div>
              <p className="mt-1 text-xs font-medium uppercase tracking-wider text-slate-400">Evidence-Driven Findings</p>
            </div>
          </div>
        </div>
      </section>

      {/* ---------------------------------------------------------------------
         PROBLEM SECTION
         --------------------------------------------------------------------- */}
      <section id="product" className="py-24 bg-[#080B0F]">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="mx-auto max-w-3xl text-center">
            <span className="font-mono text-xs font-semibold uppercase tracking-wider text-[#C98A52]">The Problem</span>
            <h2 className="mt-2 text-3xl font-extrabold text-slate-100 sm:text-4xl">
              Cryptography is everywhere. <br className="hidden sm:inline" />
              Visibility isn&apos;t.
            </h2>
            <p className="mt-4 text-slate-400 text-sm sm:text-base">
              Legacy classical algorithms (RSA, ECC, Diffie-Hellman) permeate enterprise codebases and third-party dependencies. Without automated discovery, migration to Post-Quantum Cryptography (PQC) is impossible.
            </p>
          </div>

          <div className="mt-16 grid gap-6 md:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-6 shadow-lg">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-[#7DB7E8]/30 bg-[#7DB7E8]/10 text-[#7DB7E8]">
                <Icon name="search" size={20} />
              </div>
              <h3 className="mt-4 text-base font-semibold text-slate-100">Where is cryptography used?</h3>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                Hidden deep within dependencies, hardcoded keys, legacy wrappers, and unindexed source code.
              </p>
            </div>

            <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-6 shadow-lg">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-red-500/30 bg-red-500/10 text-red-400">
                <Icon name="alert-triangle" size={20} />
              </div>
              <h3 className="mt-4 text-base font-semibold text-slate-100">Which algorithms are vulnerable?</h3>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                Shor&apos;s algorithm will break RSA and ECC completely. Store-Now-Decrypt-Later (SNDL) attacks threaten data today.
              </p>
            </div>

            <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-6 shadow-lg">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-amber-500/30 bg-amber-500/10 text-amber-400">
                <Icon name="clock" size={20} />
              </div>
              <h3 className="mt-4 text-base font-semibold text-slate-100">How urgent is the problem?</h3>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                If secrecy lifetime plus migration lead time exceeds quantum horizon ($X + Y &gt; Z$), you are already overdue.
              </p>
            </div>

            <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-6 shadow-lg">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-400">
                <Icon name="cpu" size={20} />
              </div>
              <h3 className="mt-4 text-base font-semibold text-slate-100">What should replace it?</h3>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                Selecting NIST-approved algorithms (ML-KEM, ML-DSA) or hybrid arrangements based on risk tier.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ---------------------------------------------------------------------
         ECDAT SOLUTION SECTION
         --------------------------------------------------------------------- */}
      <section id="features" className="py-24 bg-[#0C1117] border-t border-[#222B35]">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="mx-auto max-w-3xl text-center">
            <span className="font-mono text-xs font-semibold uppercase tracking-wider text-[#7DB7E8]">The Solution</span>
            <h2 className="mt-2 text-3xl font-extrabold text-slate-100 sm:text-4xl">
              From cryptographic discovery <br /> to migration priority.
            </h2>
            <p className="mt-4 text-slate-400 text-sm">
              ECDAT (Enterprise Cryptographic Discovery & Analysis Tool) helps organizations discover, inventory, assess and prioritize cryptographic assets for a post-quantum future.
            </p>
          </div>

          <div className="mt-16 grid gap-6 md:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-6 transition-all hover:border-[#7DB7E8]">
              <div className="font-mono text-xs font-bold text-[#7DB7E8]">01 / DISCOVER</div>
              <h3 className="mt-3 text-lg font-semibold text-slate-100">Source & Dependency Scan</h3>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                AST-aware Semgrep rules and manifest parsers scan source code, lockfiles, and configuration files.
              </p>
            </div>

            <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-6 transition-all hover:border-[#7DB7E8]">
              <div className="font-mono text-xs font-bold text-[#7DB7E8]">02 / INVENTORY</div>
              <h3 className="mt-3 text-lg font-semibold text-slate-100">Standardized CBOM</h3>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                Converts every finding into a schema-valid CycloneDX cryptographic-asset inventory (`cbom.json`).
              </p>
            </div>

            <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-6 transition-all hover:border-[#7DB7E8]">
              <div className="font-mono text-xs font-bold text-[#7DB7E8]">03 / ANALYZE</div>
              <h3 className="mt-3 text-lg font-semibold text-slate-100">Quantum Urgency Math</h3>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                Classifies data secrecy lifetime ($X$), migration lead time ($Y$), and evaluates Mosca&apos;s inequality against $Z$.
              </p>
            </div>

            <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-6 transition-all hover:border-[#7DB7E8]">
              <div className="font-mono text-xs font-bold text-[#7DB7E8]">04 / PRIORITIZE</div>
              <h3 className="mt-3 text-lg font-semibold text-slate-100">PQC / Hybrid Action</h3>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                Generates deterministic recommendations: Pure PQC (ML-KEM/ML-DSA), Hybrid, or Defer strategies.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ---------------------------------------------------------------------
         HOW IT WORKS (6-Stage Horizontal Workflow)
         --------------------------------------------------------------------- */}
      <section id="how-it-works" className="py-24 bg-[#080B0F]">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <span className="font-mono text-xs font-semibold uppercase tracking-wider text-[#7DB7E8]">6-Stage Pipeline</span>
            <h2 className="mt-2 text-3xl font-extrabold text-slate-100 sm:text-4xl">
              From discovery to migration decision.
            </h2>
          </div>

          <div className="mt-16 relative">
            {/* Connecting progress line */}
            <div className="hidden lg:block absolute top-1/2 left-0 right-0 h-0.5 bg-[#222B35] -translate-y-1/2 z-0" />

            <div className="grid gap-6 grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 relative z-10">
              {/* Stage 1 */}
              <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-5 shadow-lg">
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-[#7DB7E8]/10 text-[#7DB7E8] font-mono text-xs font-bold border border-[#7DB7E8]/30">
                  01
                </div>
                <h4 className="mt-4 font-bold text-slate-100 text-sm">SCAN</h4>
                <p className="mt-1 text-xs text-slate-400">Source code &amp; dependencies using Semgrep and parsers.</p>
              </div>

              {/* Stage 2 */}
              <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-5 shadow-lg">
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-[#7DB7E8]/10 text-[#7DB7E8] font-mono text-xs font-bold border border-[#7DB7E8]/30">
                  02
                </div>
                <h4 className="mt-4 font-bold text-slate-100 text-sm">BUILD CBOM</h4>
                <p className="mt-1 text-xs text-slate-400">Convert findings to CycloneDX cryptographic assets.</p>
              </div>

              {/* Stage 3 */}
              <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-5 shadow-lg">
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-[#7DB7E8]/10 text-[#7DB7E8] font-mono text-xs font-bold border border-[#7DB7E8]/30">
                  03
                </div>
                <h4 className="mt-4 font-bold text-slate-100 text-sm">CLASSIFY</h4>
                <p className="mt-1 text-xs text-slate-400">Type, secrecy lifetime, and business criticality.</p>
              </div>

              {/* Stage 4 */}
              <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-5 shadow-lg">
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-[#7DB7E8]/10 text-[#7DB7E8] font-mono text-xs font-bold border border-[#7DB7E8]/30">
                  04
                </div>
                <h4 className="mt-4 font-bold text-slate-100 text-sm">ASSESS RISK</h4>
                <p className="mt-1 text-xs text-slate-400">
                  Mosca&apos;s inequality: <code className="text-[#7DB7E8]">X + Y &gt; Z</code>. Flags HNDL exposure; evaluates against India CII, NIST, or CRQC presets.
                </p>
              </div>

              {/* Stage 5 */}
              <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-5 shadow-lg">
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-[#7DB7E8]/10 text-[#7DB7E8] font-mono text-xs font-bold border border-[#7DB7E8]/30">
                  05
                </div>
                <h4 className="mt-4 font-bold text-slate-100 text-sm">RECOMMEND</h4>
                <p className="mt-1 text-xs text-slate-400">Pure PQC / Hybrid / Defer strategy determination.</p>
              </div>

              {/* Stage 6 */}
              <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-5 shadow-lg">
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-[#7DB7E8]/10 text-[#7DB7E8] font-mono text-xs font-bold border border-[#7DB7E8]/30">
                  06
                </div>
                <h4 className="mt-4 font-bold text-slate-100 text-sm">PLAN</h4>
                <p className="mt-1 text-xs text-slate-400">Groups findings into a sequenced migration roadmap: Remediate Now, Wave 1–3.</p>
              </div>
            </div>

            {/* Interactive Feature Carousel Showcase */}
            <div className="mt-14">
              <FeatureCarousel />
            </div>
          </div>
        </div>
      </section>

      {/* ---------------------------------------------------------------------
         MOSCA SECTION (Interactive Equation)
         --------------------------------------------------------------------- */}
      <section id="mosca" className="py-24 bg-[#0C1117] border-t border-[#222B35]">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="grid gap-12 lg:grid-cols-2 items-center">
            <div>
              <span className="font-mono text-xs font-semibold uppercase tracking-wider text-[#C98A52]">
                Mosca&apos;s Risk Inequality
              </span>
              <h2 className="mt-2 text-3xl font-extrabold text-slate-100 sm:text-4xl leading-tight">
                When does quantum risk become an urgent issue?
              </h2>
              <p className="mt-4 text-slate-400 text-sm leading-relaxed">
                Michele Mosca&apos;s inequality evaluates whether an organization must migrate cryptography immediately to prevent Store-Now-Decrypt-Later (SNDL) attacks against long-lived confidential data.
              </p>

              {/* Interactive Equation Breakdown Box */}
              <div className="mt-8 rounded-xl border border-[#222B35] bg-[#080B0F] p-6 font-mono">
                <div className="text-center">
                  <div className="inline-flex items-center gap-3 text-lg sm:text-xl font-bold">
                    <span
                      onMouseEnter={() => setActiveMoscaHover('x')}
                      onMouseLeave={() => setActiveMoscaHover(null)}
                      className={`cursor-pointer rounded px-2.5 py-1 transition-colors ${
                        activeMoscaHover === 'x' ? 'bg-[#7DB7E8] text-[#080B0F]' : 'text-[#7DB7E8] bg-[#7DB7E8]/10'
                      }`}
                    >
                      X = 15y
                    </span>
                    <span className="text-slate-500">+</span>
                    <span
                      onMouseEnter={() => setActiveMoscaHover('y')}
                      onMouseLeave={() => setActiveMoscaHover(null)}
                      className={`cursor-pointer rounded px-2.5 py-1 transition-colors ${
                        activeMoscaHover === 'y' ? 'bg-[#C98A52] text-[#080B0F]' : 'text-[#C98A52] bg-[#C98A52]/10'
                      }`}
                    >
                      Y = 3y
                    </span>
                    <span className="text-slate-500">&gt;</span>
                    <span
                      onMouseEnter={() => setActiveMoscaHover('z')}
                      onMouseLeave={() => setActiveMoscaHover(null)}
                      className={`cursor-pointer rounded px-2.5 py-1 transition-colors ${
                        activeMoscaHover === 'z' ? 'bg-slate-200 text-[#080B0F]' : 'text-slate-300 bg-slate-800'
                      }`}
                    >
                      Z = 10y
                    </span>
                  </div>

                  <div className="mt-4 text-sm font-semibold text-red-400 border-t border-[#222B35] pt-3">
                    18 years &gt; 10 years $\implies$ OVERDUE
                  </div>
                </div>

                <div className="mt-4 text-xs text-slate-400 text-center">
                  {activeMoscaHover === 'x' && 'X = Data secrecy lifetime (years sensitive data must remain secret)'}
                  {activeMoscaHover === 'y' && 'Y = Migration lead time (years required to migrate cryptography)'}
                  {activeMoscaHover === 'z' && 'Z = Quantum horizon (years until CRQC availability)'}
                  {!activeMoscaHover && 'Hover over X, Y, or Z above to inspect definition.'}
                </div>
              </div>
            </div>

            {/* Mosca Card Component */}
            <div>
              <MoscaCard mosca={plantedOverdue.mosca} />
            </div>
          </div>
        </div>
      </section>

      {/* ---------------------------------------------------------------------
         EVIDENCE / EXPLAINABILITY SECTION
         --------------------------------------------------------------------- */}
      <section className="py-24 bg-[#080B0F]">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="mx-auto max-w-3xl text-center">
            <span className="font-mono text-xs font-semibold uppercase tracking-wider text-[#7DB7E8]">Explainability</span>
            <h2 className="mt-2 text-3xl font-extrabold text-slate-100 sm:text-4xl">
              Every finding has evidence.
            </h2>
            <p className="mt-4 text-slate-400 text-sm">
              Blindspot doesn&apos;t just say &quot;RSA found&quot;. It shows where it was detected, how it was detected, how confident the detection is, and why it matters.
            </p>
          </div>

          <div className="mt-14 max-w-4xl mx-auto">
            <CodeEvidence evidence={plantedOverdue.evidence} />
          </div>
        </div>
      </section>

      {/* ---------------------------------------------------------------------
         CBOM SECTION
         --------------------------------------------------------------------- */}
      <section id="cbom" className="py-24 bg-[#0C1117] border-t border-[#222B35]">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="mx-auto max-w-3xl text-center">
            <span className="font-mono text-xs font-semibold uppercase tracking-wider text-emerald-400">CycloneDX Standard</span>
            <h2 className="mt-2 text-3xl font-extrabold text-slate-100 sm:text-4xl">
              Turn cryptographic usage into a standardized inventory.
            </h2>
            <p className="mt-4 text-slate-400 text-sm">
              Generates schema-valid CycloneDX v1.6 <code className="text-[#7DB7E8]">cryptographic-asset</code> Bill of Materials (CBOM) for interoperability and regulatory compliance.
            </p>
          </div>

          <div className="mt-14 max-w-4xl mx-auto">
            <CBOMPreview scanId="demo-repo" />
          </div>
        </div>
      </section>

      {/* ---------------------------------------------------------------------
         USE CASES SECTION
         --------------------------------------------------------------------- */}
      <section id="use-cases" className="py-24 bg-[#080B0F]">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="mx-auto max-w-3xl text-center">
            <span className="font-mono text-xs font-semibold uppercase tracking-wider text-[#C98A52]">Enterprise Applications</span>
            <h2 className="mt-2 text-3xl font-extrabold text-slate-100 sm:text-4xl">
              Built for security engineering teams.
            </h2>
          </div>

          <div className="mt-16 grid gap-6 md:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-6">
              <h3 className="font-semibold text-slate-100">Government & Defense</h3>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                Secure critical infrastructure against post-quantum Store-Now-Decrypt-Later threats and enforce CNSA 2.0 timelines.
              </p>
            </div>

            <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-6">
              <h3 className="font-semibold text-slate-100">Financial Services</h3>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                Discover and prioritize cryptographic vulnerabilities across transaction gateways and core banking applications.
              </p>
            </div>

            <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-6">
              <h3 className="font-semibold text-slate-100">Enterprise IT</h3>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                Gain continuous visibility into cryptographic usage across distributed codebases, microservices, and dependencies.
              </p>
            </div>

            <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-6">
              <h3 className="font-semibold text-slate-100">Compliance & Audit</h3>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                Generate evidence-backed CycloneDX CBOMs and executive audit trails for regulatory reporting.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ---------------------------------------------------------------------
         FINAL CTA
         --------------------------------------------------------------------- */}
      <section className="py-20 bg-[#0C1117] border-t border-[#222B35] text-center">
        <div className="mx-auto max-w-4xl px-4 sm:px-6 lg:px-8">
          <h2 className="text-3xl font-extrabold text-slate-100 sm:text-5xl leading-tight">
            Your cryptographic inventory starts here.
          </h2>
          <p className="mt-4 text-base text-slate-400 max-w-xl mx-auto">
            Discover what you&apos;re using. Understand what is at risk. Plan what comes next.
          </p>

          <div className="mt-8 flex justify-center">
            <button
              onClick={() => navigate('/dashboard')}
              className="flex items-center gap-2.5 rounded-xl border border-[#7DB7E8]/40 bg-[#7DB7E8] px-8 py-4 text-base font-bold text-[#080B0F] shadow-[0_0_30px_rgba(125,183,232,0.3)] transition-all hover:bg-[#9BC7EA] hover:scale-105"
            >
              <span>Launch ECDAT</span>
              <Icon name="arrow-right" size={18} />
            </button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <Footer />
    </div>
  );
};
