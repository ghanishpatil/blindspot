import React from 'react';

import { Icon } from '@/components/Icon';
import type { Recommendation } from '@/types';

interface RecommendationCardProps {
  recommendation: Recommendation | null;
  className?: string;
}

export const RecommendationCard: React.FC<RecommendationCardProps> = ({ recommendation, className = '' }) => {
  if (!recommendation) {
    return (
      <div className={`rounded-xl border border-[#222B35] bg-[#11171E] p-6 text-slate-400 ${className}`}>
        No recommendation generated.
      </div>
    );
  }

  const { strategy, algorithm, parameterSet, rationale, replaces, priority, effort, migrationNotes, references, costProfile } = recommendation;

  const costBandClass =
    costProfile?.relativeCost === 'high'
      ? 'border-red-500/30 bg-red-500/10 text-red-400'
      : costProfile?.relativeCost === 'moderate'
        ? 'border-amber-500/30 bg-amber-500/10 text-amber-400'
        : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400';

  const fmtBytes = (n: number | null | undefined): string =>
    n == null ? '—' : n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`;

  let strategyBadgeClass = 'border-blue-500/30 bg-blue-500/10 text-blue-400';
  let strategyLabel: string = strategy;

  if (strategy === 'PQC') {
    strategyBadgeClass = 'border-[#7DB7E8]/40 bg-[#7DB7E8]/10 text-[#7DB7E8] shadow-[0_0_12px_rgba(125,183,232,0.15)]';
    strategyLabel = 'Pure PQC Migration';
  } else if (strategy === 'HYBRID') {
    strategyBadgeClass = 'border-amber-500/40 bg-amber-500/10 text-amber-400';
    strategyLabel = 'Hybrid (Classical + PQC)';
  } else if (strategy === 'DEFER') {
    strategyBadgeClass = 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400';
    strategyLabel = 'Defer & Monitor';
  } else if (strategy === 'REMEDIATE_NOW') {
    strategyBadgeClass = 'border-rose-500/40 bg-rose-500/10 text-rose-400';
    strategyLabel = 'Remediate Immediately';
  }

  return (
    <div className={`rounded-xl border border-[#222B35] bg-[#11171E] p-6 shadow-xl ${className}`}>
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#222B35] pb-4">
        <div className="flex items-center gap-2.5">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-[#7DB7E8]/30 bg-[#7DB7E8]/10 text-[#7DB7E8]">
            <Icon name="cpu" size={20} />
          </div>
          <div>
            <h3 className="font-semibold text-slate-100">Cryptographic Migration Recommendation</h3>
            <p className="text-xs text-slate-400">Post-Quantum Cryptography (PQC) & Hybrid Strategy</p>
          </div>
        </div>

        <span className={`rounded-full border px-3 py-1 font-mono text-xs font-semibold ${strategyBadgeClass}`}>
          {strategyLabel}
        </span>
      </div>

      {/* Target Algorithm Banner */}
      <div className="my-5 rounded-lg border border-[#222B35] bg-[#0C1117] p-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Recommended Target Algorithm</span>
            <div className="mt-1 flex items-center gap-2">
              <span className="font-mono text-lg font-bold text-[#7DB7E8]">{algorithm}</span>
              {parameterSet ? (
                <span className="rounded border border-slate-700 bg-slate-800 px-2 py-0.5 font-mono text-xs text-slate-300">
                  {parameterSet}
                </span>
              ) : null}
            </div>
          </div>

          {replaces ? (
            <div className="text-right">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Replaces Primitive</span>
              <p className="mt-1 font-mono text-sm text-slate-400 line-through">{replaces}</p>
            </div>
          ) : null}
        </div>
      </div>

      {/* Rationale Section */}
      <div className="mb-4">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Migration Rationale</h4>
        <p className="mt-1.5 text-sm text-slate-200 leading-relaxed bg-[#080B0F] p-3.5 rounded-lg border border-[#222B35]">
          {rationale}
        </p>
      </div>

      {/* Cost & Size Profile (published FIPS sizes, not fabricated latency) */}
      {costProfile ? (
        <div className="mb-4">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Cost &amp; Size Profile
            </h4>
            <span className={`rounded-full border px-2.5 py-0.5 font-mono text-[11px] font-semibold capitalize ${costBandClass}`}>
              {costProfile.relativeCost} cost
            </span>
          </div>

          <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-4">
            <div className="rounded-lg border border-[#222B35] bg-[#0C1117] p-2.5">
              <span className="block text-[10px] uppercase tracking-wider text-slate-500">Public key</span>
              <span className="font-mono text-sm text-slate-200">{fmtBytes(costProfile.publicKeyBytes)}</span>
              {costProfile.classicalPublicKeyBytes != null ? (
                <span className="block text-[10px] text-slate-500">vs ~{fmtBytes(costProfile.classicalPublicKeyBytes)} classical</span>
              ) : null}
            </div>
            {costProfile.ciphertextBytes != null ? (
              <div className="rounded-lg border border-[#222B35] bg-[#0C1117] p-2.5">
                <span className="block text-[10px] uppercase tracking-wider text-slate-500">Ciphertext</span>
                <span className="font-mono text-sm text-slate-200">{fmtBytes(costProfile.ciphertextBytes)}</span>
              </div>
            ) : null}
            {costProfile.signatureBytes != null ? (
              <div className="rounded-lg border border-[#222B35] bg-[#0C1117] p-2.5">
                <span className="block text-[10px] uppercase tracking-wider text-slate-500">Signature</span>
                <span className="font-mono text-sm text-slate-200">{fmtBytes(costProfile.signatureBytes)}</span>
                {costProfile.classicalSignatureBytes != null ? (
                  <span className="block text-[10px] text-slate-500">vs ~{fmtBytes(costProfile.classicalSignatureBytes)} classical</span>
                ) : null}
              </div>
            ) : null}
            {costProfile.privateKeyBytes != null ? (
              <div className="rounded-lg border border-[#222B35] bg-[#0C1117] p-2.5">
                <span className="block text-[10px] uppercase tracking-wider text-slate-500">Private key</span>
                <span className="font-mono text-sm text-slate-200">{fmtBytes(costProfile.privateKeyBytes)}</span>
              </div>
            ) : null}
          </div>

          <p className="mt-2 text-xs leading-relaxed text-slate-300">{costProfile.sizeSummary}</p>
          <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[10px] text-slate-500">
            <span className="italic">{costProfile.basis}</span>
            {costProfile.sources.map((src, idx) => (
              <span key={idx} className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-slate-300">{src}</span>
            ))}
          </div>
        </div>
      ) : null}

      {/* Migration Notes Checklist */}
      {migrationNotes && migrationNotes.length > 0 ? (
        <div className="mb-4">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Implementation Action Items</h4>
          <ul className="mt-2 space-y-2 text-xs text-slate-300">
            {migrationNotes.map((note, idx) => (
              <li key={idx} className="flex items-start gap-2 rounded border border-[#222B35] bg-[#0C1117] p-2.5">
                <Icon name="check-circle" size={15} className="mt-0.5 text-[#7DB7E8] shrink-0" />
                <span>{note}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {/* Footer Info */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[#222B35] pt-4 text-xs text-slate-400">
        <div className="flex items-center gap-4">
          <span>Priority: <strong className="text-slate-200">P{priority}</strong></span>
          {effort ? <span>Estimated Effort: <strong className="text-slate-200">{effort}</strong></span> : null}
        </div>

        {references && references.length > 0 ? (
          <div className="flex items-center gap-2">
            <span className="text-slate-400">Ref:</span>
            {references.map((ref, idx) => (
              <span key={idx} className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[11px] text-slate-300">
                {ref}
              </span>
            ))}
          </div>
        ) : null}
      </div>
    </div>
  );
};
