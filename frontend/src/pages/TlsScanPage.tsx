import React, { useState } from 'react';

import { Icon } from '@/components/Icon';
import { RecommendationCard } from '@/components/RecommendationCard';
import { RiskBadge } from '@/components/RiskBadge';
import { ApiError, scanTls } from '@/services/api';
import { DEMO_TLS_RESULT } from '@/services/mockData';
import type { TlsScanResult } from '@/types';

type LoadState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'loaded'; result: TlsScanResult; sample: boolean }
  | { kind: 'error'; message: string };

export const TlsScanPage: React.FC = () => {
  const [host, setHost] = useState('');
  const [port, setPort] = useState(443);
  const [state, setState] = useState<LoadState>({ kind: 'idle' });

  const runScan = async () => {
    const target = host.trim();
    if (!target) return;
    setState({ kind: 'loading' });
    try {
      const result = await scanTls(target, port);
      setState({ kind: 'loaded', result, sample: false });
    } catch (err) {
      setState({
        kind: 'error',
        message: err instanceof ApiError ? err.message : 'TLS scan failed.',
      });
    }
  };

  const loadSample = () => {
    setState({ kind: 'loaded', result: DEMO_TLS_RESULT, sample: true });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-100">TLS &amp; Certificate Scan</h1>
        <p className="mt-1 max-w-3xl text-xs text-slate-400">
          Probe a live endpoint's certificate and negotiated protocol. The certificate's key
          algorithm runs through the same quantum-risk analysis as code findings — an RSA or ECDSA
          certificate is Shor-breakable exactly like the algorithm found in source.
        </p>
      </div>

      {/* Input row */}
      <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-6 shadow-xl">
        <div className="grid gap-4 md:grid-cols-4">
          <div className="md:col-span-2">
            <label className="mb-1.5 block font-mono text-xs font-semibold uppercase text-slate-400">
              Hostname
            </label>
            <div className="relative">
              <Icon name="lock" size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                value={host}
                onChange={(e) => setHost(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && runScan()}
                disabled={state.kind === 'loading'}
                placeholder="example.com"
                className="w-full rounded-lg border border-[#222B35] bg-[#080B0F] py-2.5 pl-9 pr-3 font-mono text-xs text-slate-200 placeholder:text-slate-600 focus:border-[#7DB7E8] focus:outline-none"
              />
            </div>
            <span className="mt-1 block text-[11px] text-slate-500">
              Public hostname only. Internal / private addresses are refused.
            </span>
          </div>

          <div>
            <label className="mb-1.5 block font-mono text-xs font-semibold uppercase text-slate-400">
              Port
            </label>
            <input
              type="number"
              value={port}
              onChange={(e) => setPort(Number(e.target.value) || 443)}
              disabled={state.kind === 'loading'}
              className="w-full rounded-lg border border-[#222B35] bg-[#080B0F] py-2.5 px-3 font-mono text-xs text-slate-200 focus:border-[#7DB7E8] focus:outline-none"
            />
          </div>

          <div className="flex items-end gap-2">
            <button
              onClick={runScan}
              disabled={state.kind === 'loading' || !host.trim()}
              className="flex flex-1 items-center justify-center gap-2 rounded-lg border border-[#7DB7E8]/40 bg-[#7DB7E8] px-4 py-2.5 text-xs font-bold text-[#080B0F] transition-all hover:bg-[#9BC7EA] disabled:opacity-50"
            >
              <Icon name={state.kind === 'loading' ? 'refresh' : 'play'} size={14} className={state.kind === 'loading' ? 'animate-spin' : ''} />
              <span>{state.kind === 'loading' ? 'Probing...' : 'Scan TLS'}</span>
            </button>
          </div>
        </div>

        <div className="mt-3 border-t border-[#222B35] pt-3">
          <button
            onClick={loadSample}
            className="font-mono text-[11px] text-slate-400 hover:text-[#7DB7E8]"
          >
            Load sample result (offline demo) →
          </button>
        </div>
      </div>

      {state.kind === 'loading' ? (
        <div className="flex h-40 flex-col items-center justify-center gap-3">
          <Icon name="refresh" size={26} className="animate-spin text-[#7DB7E8]" />
          <span className="font-mono text-xs text-slate-400">Completing TLS handshake…</span>
        </div>
      ) : null}

      {state.kind === 'error' ? (
        <div className="rounded-xl border border-red-500/40 bg-red-500/10 p-6">
          <div className="flex items-center gap-2">
            <Icon name="alert-triangle" size={18} className="text-red-400" />
            <h3 className="text-sm font-bold text-red-400">TLS scan failed</h3>
          </div>
          <p className="mt-1 text-xs text-slate-300">{state.message}</p>
          <button
            onClick={loadSample}
            className="mt-3 rounded-lg border border-[#222B35] bg-[#11171E] px-3 py-1.5 font-mono text-[11px] text-slate-300 hover:text-white"
          >
            Show sample result instead
          </button>
        </div>
      ) : null}

      {state.kind === 'loaded' ? (
        <div className="space-y-5">
          {state.sample ? (
            <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-2.5 text-xs text-amber-300">
              <Icon name="alert-triangle" size={13} className="mr-1.5 inline" />
              Sample result — not a live scan. Shown for offline demonstration.
            </div>
          ) : null}

          {/* Handshake + certificate */}
          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-5">
              <h3 className="mb-3 font-mono text-[11px] font-semibold uppercase tracking-wider text-slate-300">
                Negotiated handshake
              </h3>
              <dl className="space-y-2 text-sm">
                <Row label="Endpoint" value={`${state.result.host}:${state.result.port}`} mono />
                <Row
                  label="Protocol"
                  value={state.result.protocol}
                  badge={state.result.protocolSecure ? 'secure' : 'weak'}
                />
                <Row label="Cipher" value={state.result.cipherSuite ?? '—'} mono />
                {state.result.cipherBits != null ? (
                  <Row label="Cipher bits" value={String(state.result.cipherBits)} mono />
                ) : null}
              </dl>
            </div>

            <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-5">
              <h3 className="mb-3 font-mono text-[11px] font-semibold uppercase tracking-wider text-slate-300">
                Certificate
              </h3>
              <dl className="space-y-2 text-sm">
                <Row label="Subject" value={state.result.certificate.subject} mono />
                <Row label="Issuer" value={state.result.certificate.issuer} mono />
                <Row
                  label="Key"
                  value={`${state.result.certificate.keyType}${
                    state.result.certificate.keyBits ? ` ${state.result.certificate.keyBits}-bit` : ''
                  }${state.result.certificate.curve ? ` (${state.result.certificate.curve})` : ''}`}
                  mono
                />
                <Row label="Signature" value={state.result.certificate.signatureAlgorithm} mono />
                <Row
                  label="Expires"
                  value={new Date(state.result.certificate.notAfter).toLocaleDateString()}
                  badge={state.result.certificate.expired ? 'weak' : undefined}
                />
              </dl>
            </div>
          </div>

          {/* Weakness notes */}
          {state.result.notes.length > 0 ? (
            <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4">
              <h3 className="mb-2 flex items-center gap-2 text-sm font-bold text-amber-400">
                <Icon name="alert-triangle" size={15} /> Present-day weaknesses
              </h3>
              <ul className="space-y-1 text-xs text-slate-300">
                {state.result.notes.map((note, idx) => (
                  <li key={idx}>• {note}</li>
                ))}
              </ul>
            </div>
          ) : null}

          {/* Quantum risk + recommendation for the certificate key */}
          {state.result.findings.map((finding) => (
            <div key={finding.id} className="space-y-3">
              <div className="flex flex-wrap items-center gap-3 rounded-xl border border-[#222B35] bg-[#0C1117] p-4">
                <span className="font-mono text-sm font-bold text-slate-100">
                  {finding.displayName}
                </span>
                <RiskBadge tier={finding.riskTier} size="sm" />
                {finding.isQuantumSensitive ? (
                  <span className="rounded border border-[#7DB7E8]/30 bg-[#7DB7E8]/10 px-2 py-0.5 font-mono text-[10px] text-[#7DB7E8]">
                    Quantum-vulnerable
                  </span>
                ) : null}
                <span className="ml-auto font-mono text-[11px] text-slate-500">
                  observed live over TLS
                </span>
              </div>
              <RecommendationCard recommendation={finding.recommendation} />
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
};

const Row: React.FC<{
  label: string;
  value: string;
  mono?: boolean;
  badge?: 'secure' | 'weak';
}> = ({ label, value, mono, badge }) => (
  <div className="flex items-start justify-between gap-3">
    <dt className="text-[11px] uppercase tracking-wider text-slate-500">{label}</dt>
    <dd className={`text-right text-slate-200 ${mono ? 'font-mono text-xs' : 'text-sm'}`}>
      {value}
      {badge === 'secure' ? (
        <span className="ml-2 rounded bg-emerald-500/20 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-400">
          secure
        </span>
      ) : null}
      {badge === 'weak' ? (
        <span className="ml-2 rounded bg-red-500/20 px-1.5 py-0.5 text-[10px] font-semibold text-red-400">
          weak
        </span>
      ) : null}
    </dd>
  </div>
);
