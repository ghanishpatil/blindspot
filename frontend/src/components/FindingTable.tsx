import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { Icon } from '@/components/Icon';
import { RiskBadge } from '@/components/RiskBadge';
import type { Finding } from '@/types';

interface FindingTableProps {
  findings: Finding[];
  onSelectFinding?: (finding: Finding) => void;
  className?: string;
  showFilters?: boolean;
}

export const FindingTable: React.FC<FindingTableProps> = ({
  findings,
  onSelectFinding,
  className = '',
  showFilters = true,
}) => {
  const navigate = useNavigate();
  const [search, setSearch] = useState('');
  const [tierFilter, setTierFilter] = useState<string>('all');
  const [typeFilter, setTypeFilter] = useState<string>('all');

  const filtered = findings.filter((f) => {
    const matchesSearch =
      search === '' ||
      f.algorithm.toLowerCase().includes(search.toLowerCase()) ||
      f.filePath.toLowerCase().includes(search.toLowerCase()) ||
      (f.recommendation?.algorithm || '').toLowerCase().includes(search.toLowerCase());

    const matchesTier =
      tierFilter === 'all' || (f.riskTier || '').toLowerCase() === tierFilter.toLowerCase();

    const matchesType =
      typeFilter === 'all' || (f.artefactType || '').toLowerCase() === typeFilter.toLowerCase();

    return matchesSearch && matchesTier && matchesType;
  });

  const handleRowClick = (finding: Finding) => {
    if (onSelectFinding) {
      onSelectFinding(finding);
    } else {
      navigate(`/findings/${finding.id}`);
    }
  };

  return (
    <div className={`rounded-xl border border-[#222B35] bg-[#11171E] shadow-xl overflow-hidden ${className}`}>
      {/* Table Filter Controls */}
      {showFilters ? (
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#222B35] bg-[#0C1117] p-4">
          {/* Search Box */}
          <div className="relative min-w-[240px] flex-1">
            <Icon name="search" size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search algorithm, file path, recommendation..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full rounded-lg border border-[#222B35] bg-[#151C24] py-2 pl-9 pr-3 text-xs text-slate-200 placeholder-slate-500 focus:border-[#7DB7E8] focus:outline-none"
            />
          </div>

          {/* Segmented Control Tier Filter Tabs */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center rounded-lg border border-[#222B35] bg-[#151C24] p-1 font-mono text-xs">
              {[
                { id: 'all', label: 'All' },
                { id: 'overdue', label: 'Overdue', badgeClass: 'bg-red-500/20 text-red-400' },
                { id: 'transitional', label: 'Transitional', badgeClass: 'bg-amber-500/20 text-amber-400' },
                { id: 'low-risk', label: 'Low-risk', badgeClass: 'bg-emerald-500/20 text-emerald-400' },
              ].map((tab) => {
                const isActive = tierFilter === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setTierFilter(tab.id)}
                    className={`rounded-md px-3 py-1.5 font-semibold transition-all ${
                      isActive
                        ? 'border border-[#7DB7E8]/40 bg-[#7DB7E8]/20 text-[#7DB7E8] shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {tab.label}
                  </button>
                );
              })}
            </div>

            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="rounded-lg border border-[#222B35] bg-[#151C24] px-3 py-2 text-xs text-slate-300 focus:border-[#7DB7E8] focus:outline-none"
            >
              <option value="all">All Artefact Types</option>
              <option value="key-exchange">Key Exchange</option>
              <option value="signature">Signature</option>
              <option value="hash">Hash</option>
              <option value="encryption">Encryption</option>
            </select>
          </div>
        </div>
      ) : null}

      {/* Grid Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="border-b border-[#222B35] bg-[#0C1117] font-mono uppercase text-[11px] tracking-wider text-slate-400">
            <tr>
              <th className="px-4 py-3 font-medium">Algorithm</th>
              <th className="px-4 py-3 font-medium">Location</th>
              <th className="px-4 py-3 font-medium">Artefact Type</th>
              <th className="px-4 py-3 font-medium">Confidence</th>
              <th className="px-4 py-3 font-medium">Risk Tier</th>
              <th className="px-4 py-3 font-medium">Recommendation</th>
              <th className="px-4 py-3 text-right font-medium">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#222B35]">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={7} className="p-8 text-center text-slate-500">
                  No cryptographic findings match the selected filters.
                </td>
              </tr>
            ) : (
              filtered.map((finding) => {
                const confPercent = Math.round((finding.evidence?.confidence || 0.9) * 100);
                return (
                  <tr
                    key={finding.id}
                    onClick={() => handleRowClick(finding)}
                    className="group cursor-pointer bg-[#11171E] transition-colors hover:bg-[#151C24]"
                  >
                    {/* Algorithm */}
                    <td className="px-4 py-3.5">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-slate-100 group-hover:text-[#7DB7E8]">
                          {finding.algorithm}
                        </span>
                        {finding.parameterStatus === 'unresolved' ? (
                          <span className="rounded bg-amber-500/10 px-1.5 py-0.5 font-mono text-[10px] text-amber-400 border border-amber-500/30">
                            Unresolved
                          </span>
                        ) : null}
                      </div>
                      <span className="text-[11px] text-slate-400 block truncate max-w-[180px]">
                        {finding.displayName}
                      </span>
                    </td>

                    {/* Location */}
                    <td className="px-4 py-3.5 font-mono text-slate-300">
                      <div className="flex items-center gap-1.5">
                        <Icon name="file-code" size={13} className="text-[#7DB7E8]" />
                        <span>{finding.filePath}</span>
                        {finding.lineNumber ? <span className="text-slate-400">:L{finding.lineNumber}</span> : null}
                      </div>
                    </td>

                    {/* Artefact Type */}
                    <td className="px-4 py-3.5 capitalize text-slate-300">
                      <span className="inline-flex items-center rounded border border-[#222B35] bg-[#0C1117] px-2 py-0.5 font-mono text-[11px]">
                        {finding.artefactType}
                      </span>
                    </td>

                    {/* Confidence */}
                    <td className="px-4 py-3.5 font-mono text-slate-300">
                      <span
                        className={`inline-flex items-center gap-1 font-semibold ${
                          confPercent >= 90 ? 'text-emerald-400' : 'text-amber-400'
                        }`}
                      >
                        {confPercent}%
                      </span>
                    </td>

                    {/* Risk Tier */}
                    <td className="px-4 py-3.5">
                      <RiskBadge tier={finding.riskTier} size="sm" />
                    </td>

                    {/* Recommendation */}
                    <td className="px-4 py-3.5 font-mono font-medium text-[#7DB7E8]">
                      {finding.recommendation?.algorithm || 'Investigate'}
                    </td>

                    {/* Action */}
                    <td className="px-4 py-3.5 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleRowClick(finding);
                        }}
                        className="inline-flex items-center gap-1 rounded border border-[#222B35] bg-[#0C1117] px-2.5 py-1 text-xs text-slate-300 transition-colors group-hover:border-[#7DB7E8]/40 group-hover:text-white"
                      >
                        <span>Drill Down</span>
                        <Icon name="chevron-right" size={13} />
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
