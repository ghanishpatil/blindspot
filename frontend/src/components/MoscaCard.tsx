import React from 'react';

import { Icon } from '@/components/Icon';
import { RiskBadge } from '@/components/RiskBadge';
import type { MoscaAssessment } from '@/types';

interface MoscaCardProps {
  mosca: MoscaAssessment | null;
  interactive?: boolean;
  className?: string;
}

export const MoscaCard: React.FC<MoscaCardProps> = ({ mosca, className = '' }) => {
  if (!mosca) {
    return (
      <div className={`rounded-xl border border-slate-800 bg-slate-900/60 p-5 ${className}`}>
        <p className="text-xs text-slate-400">Mosca analysis not applicable or unavailable.</p>
      </div>
    );
  }

  const { x, y, z, result, tier, zSource, notes } = mosca;
  const totalNeed = x + y;

  return (
    <div className={`rounded-xl border border-[#222B35] bg-[#11171E] p-6 shadow-xl ${className}`}>
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#222B35] pb-4">
        <div>
          <div className="flex items-center gap-2">
            <Icon name="clock" className="text-[#7DB7E8]" size={20} />
            <h3 className="text-lg font-bold tracking-tight text-slate-100">Mosca&apos;s Risk Inequality Evaluation</h3>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Quantum Security Condition: If <strong className="text-slate-200">X (Data Secrecy) + Y (Migration Time) &gt; Z (Quantum Horizon)</strong>, data is exposed to harvest-now-decrypt-later attacks.
          </p>
        </div>
        <RiskBadge tier={tier} size="lg" />
      </div>

      {/* Large Projector-Legible X, Y, Z Stat Grid */}
      <div className="my-6 grid gap-4 sm:grid-cols-3">
        {/* X: Data Lifetime */}
        <div className="rounded-xl border border-[#7DB7E8]/30 bg-[#080B0F] p-4 text-center">
          <span className="font-mono text-xs font-bold uppercase tracking-wider text-[#7DB7E8]">
            X — Data Lifetime
          </span>
          <div className="mt-2 font-mono text-4xl font-extrabold text-slate-100 sm:text-5xl">
            {x} <span className="text-base font-normal text-slate-400">yrs</span>
          </div>
          <span className="mt-1 block text-[11px] text-slate-400">Required secrecy window</span>
        </div>

        {/* Y: Migration Lead Time */}
        <div className="rounded-xl border border-[#C98A52]/30 bg-[#080B0F] p-4 text-center">
          <span className="font-mono text-xs font-bold uppercase tracking-wider text-[#C98A52]">
            Y — Migration Time
          </span>
          <div className="mt-2 font-mono text-4xl font-extrabold text-slate-100 sm:text-5xl">
            {y} <span className="text-base font-normal text-slate-400">yrs</span>
          </div>
          <span className="mt-1 block text-[11px] text-slate-400">Lead time to replace crypto</span>
        </div>

        {/* Z: Quantum Horizon */}
        <div className="rounded-xl border border-slate-700 bg-[#080B0F] p-4 text-center">
          <span className="font-mono text-xs font-bold uppercase tracking-wider text-slate-300">
            Z — Quantum Horizon
          </span>
          <div className="mt-2 font-mono text-4xl font-extrabold text-slate-100 sm:text-5xl">
            {z} <span className="text-base font-normal text-slate-400">yrs</span>
          </div>
          <span className="mt-1 block text-[11px] text-slate-400">{zSource || 'Estimated CRQC time'}</span>
        </div>
      </div>

      {/* Evaluated Inequality Banner — High Contrast Projector Visual */}
      <div
        className={`rounded-xl border p-5 font-mono shadow-2xl transition-all ${
          result
            ? 'border-red-500/50 bg-red-500/10 text-red-300 shadow-red-950/20'
            : 'border-emerald-500/50 bg-emerald-500/10 text-emerald-300 shadow-emerald-950/20'
        }`}
      >
        <div className="flex flex-col items-center justify-between gap-4 md:flex-row">
          <div className="flex flex-wrap items-center gap-3 text-2xl font-black sm:text-3xl md:text-4xl tracking-tight">
            <span className="text-[#7DB7E8]">{x}</span>
            <span className="text-slate-500">+</span>
            <span className="text-[#C98A52]">{y}</span>
            <span className={result ? 'text-red-400 font-extrabold' : 'text-emerald-400 font-extrabold'}>
              {result ? '>' : '≤'}
            </span>
            <span className="text-slate-200">{z}</span>
            <span className="text-slate-500 text-lg font-normal">
              ({totalNeed} yrs {result ? '>' : '≤'} {z} yrs)
            </span>
          </div>

          <div
            className={`rounded-lg px-4 py-2 text-center text-xs sm:text-sm font-extrabold uppercase tracking-widest border ${
              result
                ? 'bg-red-500 text-white border-red-400 shadow-[0_0_20px_rgba(239,68,68,0.4)]'
                : 'bg-emerald-500 text-slate-950 border-emerald-400 shadow-[0_0_20px_rgba(16,185,129,0.4)]'
            }`}
          >
            {result ? '⚠️ OVERDUE (ACTION REQUIRED)' : '✅ SAFE FOR NOW'}
          </div>
        </div>
      </div>

      {/* Notes & Explanation */}
      {notes ? (
        <div className="mt-4 rounded-lg border border-[#222B35] bg-[#080B0F] p-3 text-xs text-slate-300">
          <span className="font-mono font-bold text-slate-400">Analysis Rationale: </span>
          {notes}
        </div>
      ) : null}
    </div>
  );
};

