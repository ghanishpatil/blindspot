import React, { useState } from 'react';

import { Icon } from '@/components/Icon';
import { downloadReport, type ReportFormat } from '@/services/api';

interface ExportReportButtonsProps {
  /** Optional scan-id to embed in the report request. */
  scanId?: string;
  /** Optional class override for the outer wrapper. */
  className?: string;
}

/**
 * Compact three-format export button-group.
 *
 * Renders "Report:  HTML  ·  PDF  ·  CSV" — matching the visual weight of
 * the existing "Export CBOM" button so the two live comfortably side-by-side
 * in headers and toolbars.
 *
 * Each format maps to `GET /api/report?format=<fmt>` and is fetched
 * authenticated (via `downloadReport` in the API service), which is the
 * honest way to satisfy the owner-scoping the backend enforces.
 *
 * PS deliverable line "produce a report displaying all cryptographic assets
 * including versions/modes in **standardised formats**" reads as plural, so
 * the GUI surfaces all three formats plus the CBOM standard next to it.
 */
export const ExportReportButtons: React.FC<ExportReportButtonsProps> = ({
  scanId,
  className = '',
}) => {
  const [pending, setPending] = useState<ReportFormat | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = async (format: ReportFormat): Promise<void> => {
    setPending(format);
    setError(null);
    try {
      await downloadReport(scanId, format);
    } catch (err) {
      // Keep the error inline rather than throwing a toast library into the
      // dependency graph. The 503-with-detail case (headless Chrome missing)
      // then shows verbatim.
      setError(err instanceof Error ? err.message : 'Report download failed.');
    } finally {
      setPending(null);
    }
  };

  const chip = (format: ReportFormat, label: string): React.ReactElement => (
    <button
      key={format}
      type="button"
      onClick={() => void run(format)}
      disabled={pending !== null}
      className={
        'rounded px-2 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wide ' +
        'text-[#7DB7E8] transition-colors hover:bg-[#7DB7E8]/15 ' +
        'disabled:cursor-not-allowed disabled:opacity-40'
      }
      aria-label={`Download report as ${label}`}
      title={
        format === 'html'
          ? 'Interactive HTML — opens in a new tab'
          : format === 'pdf'
            ? 'PDF via headless Chrome (503 if unavailable on the server)'
            : 'RFC 4180 CSV inventory — one row per finding'
      }
    >
      {pending === format ? '…' : label}
    </button>
  );

  return (
    <div className={`inline-flex flex-col items-end gap-1 ${className}`}>
      <div
        className={
          'inline-flex items-center gap-1 rounded-lg border border-[#7DB7E8]/40 ' +
          'bg-[#7DB7E8]/5 px-2.5 py-1.5 text-xs text-[#7DB7E8]'
        }
      >
        <Icon name="file" size={14} className="text-[#7DB7E8]" />
        <span className="font-mono text-[11px] uppercase tracking-wide text-slate-300">Report</span>
        <span className="text-slate-500">·</span>
        {chip('html', 'HTML')}
        <span className="text-slate-500">·</span>
        {chip('pdf', 'PDF')}
        <span className="text-slate-500">·</span>
        {chip('csv', 'CSV')}
      </div>

      {error ? (
        <span
          role="alert"
          className="max-w-xs text-right text-[10px] font-mono text-rose-400"
        >
          {error}
        </span>
      ) : null}
    </div>
  );
};
