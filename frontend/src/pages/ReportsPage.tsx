import React, { useEffect, useState } from 'react';

import { Icon } from '@/components/Icon';
import { RiskBadge } from '@/components/RiskBadge';
import { fetchFindings } from '@/services/api';
import type { Finding } from '@/types';

export const ReportsPage: React.FC = () => {
  const [findings, setFindings] = useState<Finding[]>([]);

  useEffect(() => {
    fetchFindings().then(setFindings).catch(console.error);
  }, []);

  const overdue = findings.filter((f) => f.riskTier === 'overdue');
  const transitional = findings.filter((f) => f.riskTier === 'transitional');
  const lowRisk = findings.filter((f) => f.riskTier === 'low-risk');

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">
            Post-Quantum Migration Executive Report
          </h1>
          <p className="mt-1 text-xs text-slate-400">
            Strategic breakdown of quantum exposure, replacement algorithm matrix, and regulatory posture.
          </p>
        </div>

        <button
          onClick={() => window.print()}
          className="flex items-center gap-2 rounded-lg border border-[#222B35] bg-[#11171E] px-4 py-2 text-xs font-semibold text-slate-200 hover:border-slate-600"
        >
          <Icon name="download" size={14} />
          <span>Export PDF / Print Report</span>
        </button>
      </div>

      {/* Report Summary Metric Grid */}
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-5">
          <span className="text-xs font-semibold text-red-400 uppercase tracking-wider font-mono">Immediate PQC Replacement</span>
          <p className="mt-2 font-mono text-3xl font-extrabold text-red-400">{overdue.length}</p>
          <p className="mt-1 text-xs text-slate-400">Artefacts where secrecy lifetime exceeds quantum horizon.</p>
        </div>

        <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-5">
          <span className="text-xs font-semibold text-amber-400 uppercase tracking-wider font-mono">Hybrid Transition Path</span>
          <p className="mt-2 font-mono text-3xl font-extrabold text-amber-400">{transitional.length}</p>
          <p className="mt-1 text-xs text-slate-400">Dual classical + PQC key-agreement recommended.</p>
        </div>

        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-5">
          <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider font-mono">Monitored / Deferred</span>
          <p className="mt-2 font-mono text-3xl font-extrabold text-emerald-400">{lowRisk.length}</p>
          <p className="mt-1 text-xs text-slate-400">Short-lived session signatures scheduled for future roadmap.</p>
        </div>
      </div>

      {/* Migration Target Matrix */}
      <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-6 shadow-xl space-y-4">
        <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-slate-300 border-b border-[#222B35] pb-3">
          Post-Quantum Migration Matrix (NIST FIPS 203 / 204 Standards)
        </h3>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="border-b border-[#222B35] bg-[#0C1117] text-[11px] text-slate-400">
              <tr>
                <th className="px-4 py-3">Legacy Primitive</th>
                <th className="px-4 py-3">Detected Usage</th>
                <th className="px-4 py-3">Urgency Tier</th>
                <th className="px-4 py-3">Recommended Replacement</th>
                <th className="px-4 py-3">Target Standard</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#222B35]">
              {findings.map((f) => (
                <tr key={f.id} className="hover:bg-[#151C24]">
                  <td className="px-4 py-3 font-bold text-slate-100">{f.algorithm}</td>
                  <td className="px-4 py-3 text-slate-400 capitalize">{f.artefactType}</td>
                  <td className="px-4 py-3"><RiskBadge tier={f.riskTier} size="sm" /></td>
                  <td className="px-4 py-3 font-bold text-[#7DB7E8]">{f.recommendation?.algorithm}</td>
                  <td className="px-4 py-3 text-slate-300">{f.recommendation?.parameterSet || 'NIST FIPS'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
