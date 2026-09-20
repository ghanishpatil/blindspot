import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { Icon } from '@/components/Icon';
import { RiskBadge } from '@/components/RiskBadge';
import {
  type ScanHistoryEntry,
  clearScanHistory,
  describeTarget,
  removeScanFromHistory,
} from '@/services/scanHistory';

interface ScanHistoryProps {
  entries: ScanHistoryEntry[];
  onChange: (next: ScanHistoryEntry[]) => void;
}

export const ScanHistory: React.FC<ScanHistoryProps> = ({ entries, onChange }) => {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  if (entries.length === 0) {
    return (
      <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-6 shadow-xl">
        <div className="flex items-center gap-2">
          <Icon name="clock" size={16} className="text-slate-500" />
          <h3 className="text-sm font-bold text-slate-200">Recent Scans</h3>
        </div>
        <p className="mt-2 text-xs text-slate-500">
          No scans yet. Run a discovery scan and it will appear here for review.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-[#222B35] bg-[#11171E] shadow-xl">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[#222B35] px-5 py-3.5">
        <div className="flex items-center gap-2">
          <Icon name="clock" size={16} className="text-[#7DB7E8]" />
          <h3 className="text-sm font-bold text-slate-200">Recent Scans</h3>
          <span className="rounded bg-[#7DB7E8]/10 px-2 py-0.5 font-mono text-[10px] text-[#7DB7E8]">
            {entries.length}
          </span>
        </div>
        <button
          onClick={() => onChange(clearScanHistory())}
          className="flex items-center gap-1.5 rounded border border-[#222B35] px-2.5 py-1 font-mono text-[11px] text-slate-400 transition-colors hover:border-red-500/40 hover:text-red-400"
        >
          <Icon name="close" size={12} />
          Clear All
        </button>
      </div>

      {/* Rows */}
      <div className="divide-y divide-[#181F27]">
        {entries.map((entry) => (
          <ScanHistoryRow
            key={entry.localId}
            entry={entry}
            expanded={expandedId === entry.localId}
            onToggle={() =>
              setExpandedId((cur) => (cur === entry.localId ? null : entry.localId))
            }
            onRemove={() => onChange(removeScanFromHistory(entry.localId))}
          />
        ))}
      </div>
    </div>
  );
};

// ── Row ────────────────────────────────────────────────────────────────

interface ScanHistoryRowProps {
  entry: ScanHistoryEntry;
  expanded: boolean;
  onToggle: () => void;
  onRemove: () => void;
}

const EMPTY_SUMMARY = {
  totalFindings: 0,
  quantumSensitive: 0,
  overdue: 0,
  transitional: 0,
  lowRisk: 0,
  currentWeakCrypto: 0,
  hndlExposed: 0,
  needsVerification: 0,
  unresolvedParameters: 0,
  byAlgorithm: {},
  byArtefactType: {},
  byConfidenceLevel: {},
  filesScanned: 0,
} as const;

const ScanHistoryRow: React.FC<ScanHistoryRowProps> = ({
  entry,
  expanded,
  onToggle,
  onRemove,
}) => {
  const { response } = entry;
  const summary = response?.summary ?? EMPTY_SUMMARY;
  const when = new Date(entry.timestamp);

  return (
    <div>
      {/* Collapsed summary — the whole row toggles */}
      <button
        onClick={onToggle}
        aria-expanded={expanded}
        className="flex w-full items-center gap-3 px-5 py-3.5 text-left transition-colors hover:bg-[#151C24]"
      >
        <Icon
          name="chevron-right"
          size={16}
          className={`shrink-0 text-slate-500 transition-transform ${expanded ? 'rotate-90' : ''}`}
        />

        <Icon
          name={entry.targetType === 'image' ? 'layers' : 'database'}
          size={15}
          className="shrink-0 text-[#7DB7E8]"
        />

        <div className="min-w-0 flex-1">
          <div className="truncate font-mono text-xs text-slate-200" title={describeTarget(entry)}>
            {describeTarget(entry)}
          </div>
          <div className="mt-0.5 flex items-center gap-2 text-[10px] text-slate-500">
            <span>{when.toLocaleString()}</span>
            <span className="text-slate-700">·</span>
            <span className="uppercase">{entry.mode}</span>
            <span className="text-slate-700">·</span>
            <span>{targetKindLabel(entry.targetKind)}</span>
          </div>
        </div>

        {/* Compact stat chips */}
        <div className="hidden shrink-0 items-center gap-1.5 font-mono text-[10px] sm:flex">
          <StatChip label="findings" value={response.findingCount} tone="neutral" />
          {summary.overdue > 0 ? (
            <StatChip label="overdue" value={summary.overdue} tone="red" />
          ) : null}
          {summary.transitional > 0 ? (
            <StatChip label="transitional" value={summary.transitional} tone="amber" />
          ) : null}
          {summary.currentWeakCrypto > 0 ? (
            <StatChip label="weak now" value={summary.currentWeakCrypto} tone="red" />
          ) : null}
        </div>
      </button>

      {/* Expanded detail */}
      {expanded ? <ScanHistoryDetail entry={entry} onRemove={onRemove} /> : null}
    </div>
  );
};

// ── Expanded detail ──────────────────────────────────────────────────────

const ScanHistoryDetail: React.FC<{ entry: ScanHistoryEntry; onRemove: () => void }> = ({
  entry,
  onRemove,
}) => {
  const navigate = useNavigate();
  const { response, findings } = entry;
  const summary = response?.summary ?? EMPTY_SUMMARY;

  // "Important" findings: overdue first, then transitional, then currently
  // weak, capped so the row stays readable. Falls back to first few findings.
  const important = pickImportantFindings(findings);

  return (
    <div className="space-y-5 border-t border-[#181F27] bg-[#0C1117] px-5 py-4">
      {/* Input given */}
      <Section title="Scan Input" icon="terminal">
        <dl className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-2">
          <Field label="Target type" value={entry.targetType === 'image' ? 'Container image' : 'Repository'} />
          <Field label="Interpreted as" value={targetKindLabel(entry.targetKind)} />
          <Field label="Target" value={describeTarget(entry)} mono wide />
          <Field label="Execution mode" value={entry.mode} />
          <Field label="Backend scan id" value={response.scanId} mono />
          <Field label="Repository (server)" value={response.repository} mono wide />
        </dl>
      </Section>

      {/* Result summary */}
      <Section title="Result Summary" icon="barchart">
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-6">
          <SummaryStat label="Findings" value={response.findingCount} />
          <SummaryStat label="Quantum-sensitive" value={summary.quantumSensitive} />
          <SummaryStat label="Overdue" value={summary.overdue} tone="red" />
          <SummaryStat label="Transitional" value={summary.transitional} tone="amber" />
          <SummaryStat label="Low-risk" value={summary.lowRisk} tone="green" />
          <SummaryStat label="Weak today" value={summary.currentWeakCrypto} tone="red" />
          <SummaryStat label="HNDL exposed" value={summary.hndlExposed} tone="red" />
          <SummaryStat label="Needs review" value={summary.needsVerification} />
          <SummaryStat label="Unresolved params" value={summary.unresolvedParameters} />
          <SummaryStat label="Files scanned" value={summary.filesScanned} />
          {response.durationSeconds != null ? (
            <SummaryStat label="Duration" value={`${response.durationSeconds.toFixed(1)}s`} />
          ) : null}
        </div>
      </Section>

      {/* Important findings */}
      <Section title={`Important Findings (${important.length} of ${findings.length})`} icon="alert-triangle">
        {important.length === 0 ? (
          <p className="text-xs text-slate-500">No findings recorded for this scan.</p>
        ) : (
          <div className="overflow-hidden rounded-lg border border-[#222B35]">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#11171E] text-[10px] uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="px-3 py-2 font-medium">Algorithm</th>
                  <th className="px-3 py-2 font-medium">Location</th>
                  <th className="px-3 py-2 font-medium">Tier</th>
                  <th className="px-3 py-2 font-medium">Recommendation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#181F27]">
                {important.map((f) => (
                  <tr
                    key={f.id}
                    className="cursor-pointer transition-colors hover:bg-[#151C24]"
                    onClick={() => navigate(`/findings/${encodeURIComponent(f.id)}`)}
                  >
                    <td className="px-3 py-2 font-mono font-semibold text-slate-100">
                      {f.displayName || f.algorithm}
                    </td>
                    <td className="px-3 py-2 font-mono text-[#7DB7E8]">
                      {fileName(f.filePath)}
                      {f.lineNumber != null ? `:${f.lineNumber}` : ''}
                    </td>
                    <td className="px-3 py-2">
                      <RiskBadge tier={f.riskTier} size="sm" />
                    </td>
                    <td className="px-3 py-2 text-slate-300">
                      {f.recommendation?.algorithm ?? '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      {/* CBOM */}
      <Section title="CBOM" icon="file-json">
        {entry.cbom ? (
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-400">
              <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 font-mono text-emerald-400">
                {cbomFormat(entry.cbom)}
              </span>
              <span className="font-mono">{cbomComponentCount(entry.cbom)} cryptographic assets</span>
            </div>
            <pre className="max-h-52 overflow-auto rounded-lg border border-[#222B35] bg-[#080B0F] p-3 font-mono text-[11px] leading-relaxed text-slate-300">
              {JSON.stringify(entry.cbom, null, 2)}
            </pre>
          </div>
        ) : (
          <p className="text-xs text-slate-500">
            CBOM was not captured for this scan (large payloads are dropped to stay within browser storage limits).
          </p>
        )}
      </Section>

      {/* Actions */}
      <div className="flex flex-wrap items-center justify-end gap-2 border-t border-[#181F27] pt-3">
        <button
          onClick={() => navigate('/cbom')}
          className="flex items-center gap-1.5 rounded border border-[#7DB7E8]/40 bg-[#7DB7E8]/10 px-3 py-1.5 text-[11px] font-semibold text-[#7DB7E8] transition-colors hover:bg-[#7DB7E8]/20"
        >
          <Icon name="file-json" size={13} />
          Inspect CBOM
        </button>
        <button
          onClick={() => navigate('/findings')}
          className="flex items-center gap-1.5 rounded border border-[#222B35] bg-[#11171E] px-3 py-1.5 text-[11px] font-semibold text-slate-300 transition-colors hover:border-slate-600"
        >
          <Icon name="layers" size={13} />
          All Findings
        </button>
        <button
          onClick={onRemove}
          className="flex items-center gap-1.5 rounded border border-[#222B35] px-3 py-1.5 text-[11px] font-semibold text-slate-400 transition-colors hover:border-red-500/40 hover:text-red-400"
        >
          <Icon name="close" size={13} />
          Remove
        </button>
      </div>
    </div>
  );
};

// ── Small presentational helpers ──────────────────────────────────────────

const Section: React.FC<{
  title: string;
  icon: React.ComponentProps<typeof Icon>['name'];
  children: React.ReactNode;
}> = ({ title, icon, children }) => (
  <div>
    <div className="mb-2 flex items-center gap-1.5">
      <Icon name={icon} size={13} className="text-slate-500" />
      <h4 className="font-mono text-[11px] font-bold uppercase tracking-wider text-slate-400">
        {title}
      </h4>
    </div>
    {children}
  </div>
);

const Field: React.FC<{ label: string; value: string; mono?: boolean; wide?: boolean }> = ({
  label,
  value,
  mono,
  wide,
}) => (
  <div className={wide ? 'sm:col-span-2' : ''}>
    <dt className="text-[10px] uppercase tracking-wider text-slate-500">{label}</dt>
    <dd className={`mt-0.5 break-all text-xs text-slate-200 ${mono ? 'font-mono' : ''}`}>
      {value || '—'}
    </dd>
  </div>
);

type Tone = 'neutral' | 'red' | 'amber' | 'green';

const TONE_TEXT: Record<Tone, string> = {
  neutral: 'text-slate-100',
  red: 'text-red-400',
  amber: 'text-amber-400',
  green: 'text-emerald-400',
};

const SummaryStat: React.FC<{ label: string; value: number | string; tone?: Tone }> = ({
  label,
  value,
  tone = 'neutral',
}) => (
  <div className="rounded-lg border border-[#222B35] bg-[#11171E] p-2.5">
    <div className={`font-mono text-lg font-bold ${TONE_TEXT[tone]}`}>{value}</div>
    <div className="mt-0.5 text-[10px] uppercase tracking-wider text-slate-500">{label}</div>
  </div>
);

const CHIP_TONE: Record<Tone, string> = {
  neutral: 'border-[#222B35] bg-[#0C1117] text-slate-300',
  red: 'border-red-500/30 bg-red-500/10 text-red-400',
  amber: 'border-amber-500/30 bg-amber-500/10 text-amber-400',
  green: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400',
};

const StatChip: React.FC<{ label: string; value: number; tone: Tone }> = ({
  label,
  value,
  tone,
}) => (
  <span className={`rounded border px-1.5 py-0.5 ${CHIP_TONE[tone]}`}>
    {value} {label}
  </span>
);

// ── Data helpers ───────────────────────────────────────────────────────

function targetKindLabel(kind: ScanHistoryEntry['targetKind']): string {
  switch (kind) {
    case 'git-url':
      return 'Git URL (cloned)';
    case 'local-path':
      return 'Local path';
    case 'image-ref':
      return 'Container image';
    case 'demo-repo':
      return 'Demo repo';
    default:
      return kind;
  }
}

function fileName(path: string): string {
  if (!path) {
    return '';
  }
  const normalized = path.replace(/\\/g, '/');
  return normalized.substring(normalized.lastIndexOf('/') + 1);
}

const TIER_ORDER: Record<string, number> = {
  overdue: 0,
  transitional: 1,
  'low-risk': 2,
};

function pickImportantFindings(findings: import('@/types').Finding[]): import('@/types').Finding[] {
  const ranked = [...findings].sort((a, b) => {
    // Currently-weak crypto is a present-day problem — surface it high.
    const weakA = a.isCurrentlyWeak ? 0 : 1;
    const weakB = b.isCurrentlyWeak ? 0 : 1;
    if (weakA !== weakB) {
      return weakA - weakB;
    }
    const ta = a.riskTier ? (TIER_ORDER[a.riskTier] ?? 3) : 3;
    const tb = b.riskTier ? (TIER_ORDER[b.riskTier] ?? 3) : 3;
    return ta - tb;
  });
  return ranked.slice(0, 8);
}

function cbomFormat(cbom: unknown): string {
  if (cbom && typeof cbom === 'object') {
    const record = cbom as Record<string, unknown>;
    const format = typeof record.bomFormat === 'string' ? record.bomFormat : 'CBOM';
    const version = typeof record.specVersion === 'string' ? ` ${record.specVersion}` : '';
    return `${format}${version}`;
  }
  return 'CBOM';
}

function cbomComponentCount(cbom: unknown): number {
  if (cbom && typeof cbom === 'object') {
    const components = (cbom as Record<string, unknown>).components;
    if (Array.isArray(components)) {
      return components.length;
    }
  }
  return 0;
}
