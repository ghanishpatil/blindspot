import React, { useState } from 'react';

import { ExportReportButtons } from '@/components/ExportReportButtons';
import { Icon } from '@/components/Icon';
import { downloadCbom } from '@/services/api';

interface CBOMPreviewProps {
  cbomData?: unknown;
  scanId?: string;
  className?: string;
}

export const CBOMPreview: React.FC<CBOMPreviewProps> = ({ cbomData, scanId, className = '' }) => {
  const [copied, setCopied] = useState(false);

  const hasData = cbomData != null;
  const formattedJson = hasData
    ? JSON.stringify(cbomData, null, 2)
    : 'No CBOM available yet. Run a scan to generate the CycloneDX Cryptographic Bill of Materials.';

  const handleCopy = () => {
    navigator.clipboard.writeText(formattedJson);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([formattedJson], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `blindspot-cbom-${scanId || 'demo'}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className={`rounded-xl border border-[#222B35] bg-[#11171E] shadow-xl overflow-hidden ${className}`}>
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#222B35] bg-[#0C1117] px-4 py-3">
        <div className="flex items-center gap-2 font-mono text-xs">
          <Icon name="file-json" size={18} className="text-[#7DB7E8]" />
          <span className="font-semibold text-slate-200">CycloneDX CBOM Specification v1.6</span>
          {hasData ? (
            <span className="rounded bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium text-emerald-400 border border-emerald-500/30">
              Schema Valid
            </span>
          ) : (
            <span className="rounded bg-slate-500/10 px-2 py-0.5 text-[10px] font-medium text-slate-400 border border-slate-500/30">
              No Scan Yet
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          {/* Copy Button */}
          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 rounded border border-[#222B35] bg-[#151C24] px-3 py-1.5 text-xs text-slate-300 transition-colors hover:border-slate-600 hover:text-white"
          >
            <Icon name={copied ? 'check' : 'copy'} size={14} className={copied ? 'text-emerald-400' : ''} />
            <span>{copied ? 'Copied' : 'Copy JSON'}</span>
          </button>

          {/* Export Action */}
          <button
            onClick={handleDownload}
            className="flex items-center gap-1.5 rounded border border-[#7DB7E8]/40 bg-[#7DB7E8]/10 px-3.5 py-1.5 text-xs font-semibold text-[#7DB7E8] transition-colors hover:bg-[#7DB7E8]/20"
          >
            <Icon name="download" size={14} />
            <span>Export CBOM →</span>
          </button>

          <ExportReportButtons scanId={scanId} />
        </div>
      </div>

      {/* Code Viewer Body */}
      <div className="max-h-[500px] overflow-auto bg-[#080B0F] p-4 font-mono text-xs text-slate-300">
        <pre className="whitespace-pre-wrap">{formattedJson}</pre>
      </div>

      {/* Footer Info */}
      <div className="flex items-center justify-between border-t border-[#222B35] bg-[#0C1117] px-4 py-2.5 text-[11px] text-slate-400">
        <span>CycloneDX Standardized Cryptographic Bill of Materials</span>
        <button
          type="button"
          onClick={() => void downloadCbom(scanId)}
          className="text-[#7DB7E8] hover:underline"
        >
          Download CBOM
        </button>
      </div>
    </div>
  );
};
