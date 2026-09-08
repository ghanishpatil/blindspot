import React from 'react';
import { useNavigate } from 'react-router-dom';

import { Icon } from '@/components/Icon';

export const ProjectsPage: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">Project Workspaces</h1>
          <p className="mt-1 text-xs text-slate-400">
            Registered target repositories and continuous discovery scan profiles.
          </p>
        </div>

        <button
          onClick={() => navigate('/scan')}
          className="flex items-center gap-2 rounded-lg border border-[#7DB7E8]/40 bg-[#7DB7E8] px-4 py-2 text-xs font-semibold text-[#080B0F]"
        >
          <Icon name="search" size={14} />
          <span>New Target Scan</span>
        </button>
      </div>

      {/* Projects List */}
      <div className="grid gap-6 md:grid-cols-2">
        <div className="rounded-xl border border-[#7DB7E8]/40 bg-[#11171E] p-6 shadow-xl space-y-4">
          <div className="flex items-center justify-between border-b border-[#222B35] pb-3">
            <div className="flex items-center gap-2.5">
              <div className="flex h-8 w-8 items-center justify-center rounded bg-[#7DB7E8]/10 text-[#7DB7E8]">
                <Icon name="layers" size={18} />
              </div>
              <div>
                <h3 className="font-mono font-bold text-slate-100 text-sm">demo-repo</h3>
                <span className="text-[11px] text-slate-500 font-mono">f:/blindspot/demo-repo</span>
              </div>
            </div>

            <span className="rounded bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 font-mono text-[11px] text-emerald-400">
              Active Target
            </span>
          </div>

          <div className="grid grid-cols-3 gap-2 font-mono text-xs text-center">
            <div className="rounded border border-[#222B35] bg-[#0C1117] p-2">
              <span className="text-[10px] text-slate-500 block">Artefacts</span>
              <span className="font-bold text-slate-200">5 Planted</span>
            </div>
            <div className="rounded border border-[#222B35] bg-[#0C1117] p-2">
              <span className="text-[10px] text-slate-500 block">Overdue Risk</span>
              <span className="font-bold text-red-400">2 Critical</span>
            </div>
            <div className="rounded border border-[#222B35] bg-[#0C1117] p-2">
              <span className="text-[10px] text-slate-500 block">CBOM Status</span>
              <span className="font-bold text-emerald-400">Valid 1.6</span>
            </div>
          </div>

          <div className="flex justify-end gap-3 pt-2">
            <button
              onClick={() => navigate('/scan')}
              className="flex items-center gap-1.5 rounded border border-[#7DB7E8]/40 bg-[#7DB7E8]/10 px-3 py-1.5 text-xs font-semibold text-[#7DB7E8]"
            >
              <Icon name="search" size={14} />
              <span>Run AST Scan →</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
