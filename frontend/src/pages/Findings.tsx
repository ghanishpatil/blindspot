import { useEffect, useState } from 'react';

import { ExportReportButtons } from '@/components/ExportReportButtons';
import { FindingTable } from '@/components/FindingTable';
import { Icon } from '@/components/Icon';
import { downloadCbom, fetchFindings } from '@/services/api';
import { DEMO_PLANTED_FINDINGS } from '@/services/mockData';
import type { Finding } from '@/types';

export default function Findings() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchFindings({ projectId: 'demo' })
      .then((data) => setFindings(data && data.length > 0 ? data : DEMO_PLANTED_FINDINGS))
      .catch((_err) => setFindings(DEMO_PLANTED_FINDINGS))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">Cryptographic Findings</h1>
          <p className="mt-1 text-xs text-slate-400">
            Full list of detected cryptographic primitives, AST evidence, Mosca risk tiers, and PQC recommendations.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={() => void downloadCbom()}
            className="flex items-center gap-2 rounded-lg border border-[#7DB7E8]/40 bg-[#7DB7E8]/10 px-4 py-2 text-xs font-semibold text-[#7DB7E8] transition-colors hover:bg-[#7DB7E8]/20"
          >
            <Icon name="download" size={14} />
            <span>Export CBOM</span>
          </button>
          <ExportReportButtons />
        </div>
      </div>

      {loading ? (
        <div className="flex h-64 items-center justify-center space-y-2">
          <Icon name="refresh" size={24} className="animate-spin text-[#7DB7E8]" />
          <span className="text-xs font-mono text-slate-400">Loading findings...</span>
        </div>
      ) : (
        <FindingTable findings={findings} showFilters={true} />
      )}
    </div>
  );
}
