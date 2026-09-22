import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';

import { FindingTable } from '@/components/FindingTable';
import { Icon } from '@/components/Icon';
import { ScanHistory } from '@/components/ScanHistory';
import { fetchCbom, fetchFindings, startScan } from '@/services/api';
import {
  type ScanHistoryEntry,
  addScanToHistory,
  getScanHistory,
} from '@/services/scanHistory';
import { parseTlsTargets } from '@/services/tlsTargets';
import type { Finding, ScanResponse } from '@/types';

const PIPELINE_STEPS = [
  { label: 'Scanning source code...', icon: 'code' },
  { label: 'Building CBOM...', icon: 'file-json' },
  { label: 'Classifying artefacts...', icon: 'filter' },
  { label: 'Computing risk scores...', icon: 'clock' },
  { label: 'Generating recommendations...', icon: 'cpu' },
];

export const ScanPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const repoParam = searchParams.get('repo') || '';

  const [repositoryPath, setRepositoryPath] = useState(repoParam);
  const [targetType, setTargetType] = useState<'repo' | 'image'>('repo');
  const [mode, setMode] = useState<'live' | 'cached'>('live');
  const [tlsTargetsInput, setTlsTargetsInput] = useState('');
  const [scanning, setScanning] = useState(false);
  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const [scanResult, setScanResult] = useState<ScanResponse | null>(null);
  const [findingsResult, setFindingsResult] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<ScanHistoryEntry[]>([]);

  // Load stored scan history on mount.
  useEffect(() => {
    setHistory(getScanHistory());
  }, []);

  const handleStartScan = async (pathOverride?: string) => {
    setScanning(true);
    setScanResult(null);
    setError(null);
    setCurrentStepIndex(0);

    const rawTarget = pathOverride !== undefined ? pathOverride : repositoryPath;
    const target = rawTarget.trim();
    // Repo target: a URL is cloned server-side; anything else is a local path
    // (dev only); blank scans the seeded demo repo. Image target: an image
    // reference is pulled + flattened, then run through the same scanners.
    const isUrl = /^https?:\/\//i.test(target);
    const isImage = targetType === 'image';

    // Animate pipeline steps for smooth demo presentation
    const interval = setInterval(() => {
      setCurrentStepIndex((prev) => (prev < PIPELINE_STEPS.length - 1 ? prev + 1 : prev));
    }, 400);

    try {
      const tlsTargets = parseTlsTargets(tlsTargetsInput);
      const res = await startScan({
        projectId: 'demo',
        mode,
        ...(isImage
          ? target
            ? { imageRef: target }
            : {}
          : target
            ? isUrl
              ? { repositoryUrl: target }
              : { repositoryPath: target }
            : {}),
        ...(tlsTargets.length > 0 ? { tlsTargets } : {}),
      });

      const findings = await fetchFindings({ projectId: 'demo' });

      // Capture the CBOM so the history entry is self-contained (best-effort;
      // a failure here must not fail the scan flow).
      let cbom: unknown | null = null;
      if (res.cbomAvailable) {
        try {
          cbom = await fetchCbom(res.scanId);
        } catch {
          cbom = null;
        }
      }

      clearInterval(interval);
      setCurrentStepIndex(PIPELINE_STEPS.length - 1);
      setScanResult(res);
      setFindingsResult(findings);

      // Snapshot this run into local history (input + result + findings + CBOM).
      const targetKind: ScanHistoryEntry['targetKind'] = isImage
        ? 'image-ref'
        : !target
          ? 'demo-repo'
          : isUrl
            ? 'git-url'
            : 'local-path';
      setHistory(
        addScanToHistory({
          targetType,
          targetInput: target,
          targetKind,
          mode,
          response: res,
          findings,
          cbom,
        }),
      );

      // Auto transition to Page 3 (Findings Dashboard) after brief pause
      setTimeout(() => {
        navigate('/dashboard');
      }, 1000);
    } catch (err) {
      clearInterval(interval);
      setError(err instanceof Error ? err.message : 'Scan failed.');
    } finally {
      setScanning(false);
    }
  };

  useEffect(() => {
    if (repoParam) {
      handleStartScan(repoParam);
    }
  }, [repoParam]);

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-100">Cryptographic Discovery Scanner</h1>
        <p className="mt-1 text-xs text-slate-400">
          Trigger static AST analysis over source code & dependencies to construct a CBOM and assess quantum risk.
        </p>
      </div>

      {/* Target Repository & Config Bar */}
      <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-6 shadow-xl space-y-4">
        {/* Target type selector */}
        <div className="flex items-center gap-1 rounded-lg border border-[#222B35] bg-[#080B0F] p-1 w-fit font-mono text-xs">
          {([
            { id: 'repo', label: 'Repository', icon: 'database' },
            { id: 'image', label: 'Container Image', icon: 'layers' },
          ] as const).map((opt) => {
            const active = targetType === opt.id;
            return (
              <button
                key={opt.id}
                onClick={() => setTargetType(opt.id)}
                disabled={scanning}
                className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 font-semibold transition-all ${
                  active
                    ? 'border border-[#7DB7E8]/40 bg-[#7DB7E8]/20 text-[#7DB7E8]'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Icon name={opt.icon} size={13} />
                <span>{opt.label}</span>
              </button>
            );
          })}
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          {/* Target input */}
          <div className="md:col-span-2">
            <label className="text-xs font-mono font-semibold uppercase text-slate-400 block mb-1.5">
              {targetType === 'image'
                ? 'Container Image (reference)'
                : 'Target Repository (GitHub URL or local path)'}
            </label>
            <div className="relative">
              <Icon
                name={targetType === 'image' ? 'layers' : 'database'}
                size={16}
                className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
              />
              <input
                type="text"
                value={repositoryPath}
                onChange={(e) => setRepositoryPath(e.target.value)}
                disabled={scanning}
                placeholder={
                  targetType === 'image'
                    ? 'python:3.11-slim  (image is pulled, flattened, and scanned)'
                    : 'https://github.com/owner/repo  (or leave blank for the demo repo)'
                }
                className="w-full rounded-lg border border-[#222B35] bg-[#080B0F] py-2.5 pl-9 pr-3 font-mono text-xs text-slate-200 placeholder:text-slate-600 focus:border-[#7DB7E8] focus:outline-none"
              />
            </div>
            <span className="text-[11px] text-slate-500 mt-1 block">
              {targetType === 'image'
                ? 'Provide an image reference (requires a container CLI on the server). Its layers are flattened and run through the same scanners as a repository.'
                : 'Paste a public GitHub / GitLab / Bitbucket URL, or leave blank to scan the seeded demo repository.'}
            </span>
          </div>

          {/* Mode Selector */}
          <div>
            <label className="text-xs font-mono font-semibold uppercase text-slate-400 block mb-1.5">
              Execution Mode
            </label>
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value as 'live' | 'cached')}
              disabled={scanning}
              className="w-full rounded-lg border border-[#222B35] bg-[#080B0F] py-2.5 px-3 font-mono text-xs text-slate-200 focus:border-[#7DB7E8] focus:outline-none"
            >
              <option value="live">Live Pipeline (Synchronous)</option>
              <option value="cached">Cached Fallback Result</option>
            </select>
          </div>
        </div>

        {/* Live TLS endpoints — optional, bundled into the same scan so
            certificate findings flow through the same classifier + risk
            engine + recommender as source findings. Empty = repo-only. */}
        <div className="rounded-lg border border-[#222B35] bg-[#080B0F]/60 p-4">
          <label
            htmlFor="scan-tls-targets"
            className="flex items-center justify-between gap-2 text-xs font-mono font-semibold uppercase text-slate-400"
          >
            <span className="flex items-center gap-1.5">
              <Icon name="lock" size={13} className="text-[#7DB7E8]" />
              Live TLS endpoints (optional)
            </span>
            {(() => {
              const parsed = parseTlsTargets(tlsTargetsInput);
              return parsed.length > 0 ? (
                <span
                  className="rounded border border-[#7DB7E8]/40 bg-[#7DB7E8]/10 px-2 py-0.5 font-mono text-[10px] text-[#7DB7E8]"
                  data-testid="tls-target-count"
                >
                  {parsed.length} target{parsed.length === 1 ? '' : 's'}
                </span>
              ) : null;
            })()}
          </label>
          <textarea
            id="scan-tls-targets"
            value={tlsTargetsInput}
            onChange={(e) => setTlsTargetsInput(e.target.value)}
            disabled={scanning}
            rows={2}
            placeholder="github.com, cloudflare.com:443, api.example.com"
            className="mt-2 w-full resize-y rounded-lg border border-[#222B35] bg-[#080B0F] p-2.5 font-mono text-xs text-slate-200 placeholder:text-slate-600 focus:border-[#7DB7E8] focus:outline-none"
          />
          <p className="mt-1.5 text-[11px] text-slate-500">
            Comma or newline separated. Each endpoint's certificate flows
            through the same risk pipeline as source findings — a real
            ECDSA cert is treated identically to ECDSA in code. Backend
            refuses private / loopback addresses (SSRF guard).
          </p>
        </div>

        {/* Start Scan Button */}
        <div className="flex justify-end pt-2 border-t border-[#222B35]">
          <button
            onClick={() => handleStartScan()}
            disabled={scanning}
            className="flex items-center gap-2 rounded-lg border border-[#7DB7E8]/40 bg-[#7DB7E8] px-6 py-2.5 text-xs font-bold text-[#080B0F] shadow-[0_0_20px_rgba(125,183,232,0.2)] transition-all hover:bg-[#9BC7EA] disabled:opacity-50"
          >
            <Icon name={scanning ? 'refresh' : 'play'} size={15} className={scanning ? 'animate-spin' : ''} />
            <span>{scanning ? 'Running Pipeline...' : 'Start Discovery Scan'}</span>
          </button>
        </div>
      </div>

      {/* Error banner */}
      {error ? (
        <div className="rounded-xl border border-red-500/40 bg-red-500/10 p-5">
          <div className="flex items-center gap-2">
            <Icon name="alert-triangle" size={18} className="text-red-400" />
            <h3 className="text-sm font-bold text-red-400">Scan Failed</h3>
          </div>
          <p className="mt-1 text-xs text-slate-300">{error}</p>
        </div>
      ) : null}

      {/* Progress Pipeline Indicator */}
      {scanning ? (
        <div className="rounded-xl border border-[#7DB7E8]/30 bg-[#11171E] p-6 shadow-xl space-y-4 animate-fade-in">
          <div className="flex items-center justify-between">
            <span className="font-mono text-xs font-bold text-[#7DB7E8] uppercase tracking-wider">
              Executing Scan Pipeline Stage {currentStepIndex + 1} / {PIPELINE_STEPS.length}
            </span>
            <span className="font-mono text-xs text-slate-400">
              {Math.round(((currentStepIndex + 1) / PIPELINE_STEPS.length) * 100)}% Complete
            </span>
          </div>

          {/* Progress Bar */}
          <div className="h-2 w-full rounded-full bg-[#080B0F] overflow-hidden border border-[#222B35]">
            <div
              className="h-full bg-gradient-to-r from-[#5F9FD4] to-[#7DB7E8] transition-all duration-300"
              style={{ width: `${((currentStepIndex + 1) / PIPELINE_STEPS.length) * 100}%` }}
            />
          </div>

          {/* Steps List */}
          <div className="grid gap-2 pt-2">
            {PIPELINE_STEPS.map((step, idx) => {
              const isDone = idx < currentStepIndex;
              const isCurrent = idx === currentStepIndex;
              return (
                <div
                  key={idx}
                  className={`flex items-center gap-3 rounded-lg p-2.5 text-xs font-mono transition-colors ${
                    isCurrent
                      ? 'border border-[#7DB7E8]/40 bg-[#7DB7E8]/10 text-[#7DB7E8]'
                      : isDone
                      ? 'text-slate-400'
                      : 'text-slate-600'
                  }`}
                >
                  <Icon
                    name={isDone ? 'check-circle' : isCurrent ? 'refresh' : ('circle' as any)}
                    size={16}
                    className={isCurrent ? 'animate-spin text-[#7DB7E8]' : isDone ? 'text-emerald-400' : ''}
                  />
                  <span>{step.label}</span>
                </div>
              );
            })}
          </div>
        </div>
      ) : null}

      {/* Completed Scan Results Banner & Findings */}
      {scanResult ? (
        <div className="space-y-6 animate-fade-in">
          {/* Status Summary Banner */}
          <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-6 shadow-xl flex flex-wrap items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <Icon name="check-circle" size={20} className="text-emerald-400" />
                <h3 className="text-base font-bold text-slate-100">Scan Execution Completed</h3>
              </div>
              <p className="mt-1 text-xs text-slate-300">
                {scanResult.message || `Discovered ${scanResult.findingCount} cryptographic artefacts.`}
              </p>
            </div>

            <div className="flex items-center gap-3 font-mono text-xs">
              <span className="rounded border border-slate-700 bg-slate-800 px-3 py-1.5 text-slate-300">
                Mode: {scanResult.mode}
              </span>
              {scanResult.durationSeconds != null ? (
                <span className="rounded border border-slate-700 bg-slate-800 px-3 py-1.5 text-slate-300">
                  Duration: {scanResult.durationSeconds.toFixed(1)}s
                </span>
              ) : null}
              <button
                onClick={() => navigate('/cbom')}
                className="rounded border border-[#7DB7E8]/40 bg-[#7DB7E8]/10 px-3 py-1.5 text-[#7DB7E8] hover:bg-[#7DB7E8]/20"
              >
                Inspect CBOM →
              </button>
            </div>
          </div>

          {/* Real results from the pipeline */}
          <FindingTable findings={findingsResult} />
        </div>
      ) : null}

      {/* Recent scans — collapsible history of past runs */}
      <ScanHistory entries={history} onChange={setHistory} />
    </div>
  );
};
