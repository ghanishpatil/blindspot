import React, { useState } from 'react';

import { Icon } from '@/components/Icon';
import type { Evidence } from '@/types';

interface CodeEvidenceProps {
  evidence: Evidence | null;
  className?: string;
}

export const CodeEvidence: React.FC<CodeEvidenceProps> = ({ evidence, className = '' }) => {
  const [copied, setCopied] = useState(false);

  if (!evidence) {
    return (
      <div className={`rounded-xl border border-[#222B35] bg-[#11171E] p-6 text-center text-slate-400 ${className}`}>
        No evidence snippet recorded for this finding.
      </div>
    );
  }

  const { filePath, lineNumber, codeSnippet, contextLines, detectionMethod, confidence, confidenceLevel, ruleId } = evidence;

  const handleCopy = () => {
    navigator.clipboard.writeText(codeSnippet || contextLines.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const confidencePercentage = Math.round(confidence * 100);

  return (
    <div className={`rounded-xl border border-[#222B35] bg-[#11171E] shadow-xl overflow-hidden ${className}`}>
      {/* Evidence Topbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#222B35] bg-[#0C1117] px-4 py-3">
        <div className="flex items-center gap-2 font-mono text-xs">
          <Icon name="file-code" size={16} className="text-[#7DB7E8]" />
          <span className="font-semibold text-slate-200">{filePath}</span>
          {lineNumber ? <span className="text-slate-400">:L{lineNumber}</span> : null}
        </div>

        <div className="flex items-center gap-3">
          {/* Detection Method Tag */}
          <span className="inline-flex items-center gap-1 rounded border border-slate-700 bg-slate-800/80 px-2 py-0.5 font-mono text-[11px] text-slate-300">
            <Icon name="search" size={12} className="text-[#7DB7E8]" />
            {detectionMethod}
          </span>

          {/* Confidence Badge */}
          <span
            className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 font-mono text-[11px] font-medium ${
              confidenceLevel === 'high'
                ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
                : confidenceLevel === 'medium'
                ? 'border-amber-500/30 bg-amber-500/10 text-amber-400'
                : 'border-slate-700 bg-slate-800 text-slate-400'
            }`}
          >
            Confidence: {confidencePercentage}%
          </span>

          {/* Copy Snippet Button */}
          <button
            onClick={handleCopy}
            className="flex items-center gap-1 rounded border border-[#222B35] bg-[#151C24] px-2.5 py-1 text-xs text-slate-300 transition-colors hover:border-slate-600 hover:text-white"
            title="Copy code snippet"
          >
            <Icon name={copied ? 'check' : 'copy'} size={13} className={copied ? 'text-emerald-400' : ''} />
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </div>
      </div>

      {/* Code Editor Body */}
      <div className="overflow-x-auto bg-[#080B0F] p-4 font-mono text-xs text-slate-200">
        {contextLines && contextLines.length > 0 ? (
          <div className="space-y-1">
            {contextLines.map((line, idx) => {
              const isTargetLine = codeSnippet && line.includes(codeSnippet.trim());
              return (
                <div
                  key={idx}
                  className={`flex items-start gap-4 rounded px-2 py-0.5 ${
                    isTargetLine ? 'border-l-2 border-[#7DB7E8] bg-[#7DB7E8]/10 text-white font-medium' : 'text-slate-400'
                  }`}
                >
                  <span className="w-8 shrink-0 select-none text-right text-slate-600">
                    {lineNumber ? lineNumber - Math.floor(contextLines.length / 2) + idx : idx + 1}
                  </span>
                  <span className="whitespace-pre">{line}</span>
                </div>
              );
            })}
          </div>
        ) : (
          <pre className="whitespace-pre-wrap text-emerald-300">{codeSnippet}</pre>
        )}
      </div>

      {/* Footer Rule Metadata */}
      {ruleId ? (
        <div className="flex items-center justify-between border-t border-[#222B35] bg-[#0C1117] px-4 py-2 text-[11px] text-slate-400">
          <span>
            Semgrep Rule ID: <code className="text-[#7DB7E8]">{ruleId}</code>
          </span>
          <span className="text-slate-500">AST Static Rule Match</span>
        </div>
      ) : null}
    </div>
  );
};
