import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';

import { CodeEvidence } from '@/components/CodeEvidence';
import { Icon } from '@/components/Icon';
import { MoscaCard } from '@/components/MoscaCard';
import { RecommendationCard } from '@/components/RecommendationCard';
import { RiskBadge } from '@/components/RiskBadge';
import { fetchFinding } from '@/services/api';
import { DEMO_PLANTED_FINDINGS } from '@/services/mockData';
import type { Finding } from '@/types';

type ActiveTab = 'overview' | 'evidence' | 'risk' | 'recommendation';

export default function FindingDetail() {
  const { findingId } = useParams<{ findingId: string }>();
  const navigate = useNavigate();
  const [finding, setFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<ActiveTab>('overview');

  useEffect(() => {
    if (!findingId) return;

    fetchFinding(findingId)
      .then((data) => setFinding(data))
      .catch((_err) => {
        const found = DEMO_PLANTED_FINDINGS.find((item) => item.id === findingId);
        setFinding(found || DEMO_PLANTED_FINDINGS[0]);
      })
      .finally(() => setLoading(false));
  }, [findingId]);

  if (loading) {
    return (
      <div className="flex h-96 items-center justify-center space-y-3">
        <Icon name="refresh" size={28} className="animate-spin text-[#7DB7E8]" />
        <span className="font-mono text-xs text-slate-400">Loading finding analysis…</span>
      </div>
    );
  }

  if (!finding) {
    return (
      <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-8 text-center text-slate-400 space-y-4">
        <Icon name="alert-triangle" size={32} className="mx-auto text-amber-400" />
        <p className="text-base font-semibold">Finding not found.</p>
        <button
          onClick={() => navigate('/findings')}
          className="rounded-lg border border-[#7DB7E8]/40 bg-[#7DB7E8]/10 px-4 py-2 text-xs font-semibold text-[#7DB7E8]"
        >
          Return to Findings
        </button>
      </div>
    );
  }

  const {
    algorithm,
    displayName,
    filePath,
    lineNumber,
    artefactType,
    parameter,
    parameterStatus,
    library,
    evidence,
    classification,
    mosca,
    riskTier,
    recommendation,
    currentRisk,
    quantumRisk,
  } = finding;

  return (
    <div className="space-y-6">
      {/* Top Navigation Back Action */}
      <button
        onClick={() => navigate('/findings')}
        className="inline-flex items-center gap-2 font-mono text-xs text-slate-400 transition-colors hover:text-[#7DB7E8]"
      >
        <Icon name="arrow-right" size={14} className="rotate-180" />
        <span>Back to Findings</span>
      </button>

      {/* Main Finding Title Banner */}
      <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-6 shadow-xl space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-4 border-b border-[#222B35] pb-4">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="font-mono text-2xl font-extrabold text-slate-100">{algorithm}</h1>
              <RiskBadge tier={riskTier} size="lg" />
              {parameterStatus === 'unresolved' ? (
                <span className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 font-mono text-xs font-semibold text-amber-400">
                  Unresolved Parameter
                </span>
              ) : null}
            </div>
            <p className="mt-1 text-xs text-slate-400">{displayName}</p>
          </div>

          <div className="flex items-center gap-2 font-mono text-xs text-slate-400">
            <Icon name="file-code" size={16} className="text-[#7DB7E8]" />
            <span className="text-slate-200">{filePath}</span>
            {lineNumber ? <span className="text-slate-400">:L{lineNumber}</span> : null}
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex flex-wrap gap-2 border-b border-[#222B35] pb-2 font-mono text-xs">
          <button
            onClick={() => setActiveTab('overview')}
            className={`flex items-center gap-2 rounded-lg px-4 py-2 transition-colors ${
              activeTab === 'overview'
                ? 'border border-[#7DB7E8]/40 bg-[#7DB7E8]/10 text-[#7DB7E8] font-bold'
                : 'text-slate-400 hover:bg-[#151C24] hover:text-white'
            }`}
          >
            <Icon name="activity" size={15} />
            <span>Overview</span>
          </button>

          <button
            onClick={() => setActiveTab('evidence')}
            className={`flex items-center gap-2 rounded-lg px-4 py-2 transition-colors ${
              activeTab === 'evidence'
                ? 'border border-[#7DB7E8]/40 bg-[#7DB7E8]/10 text-[#7DB7E8] font-bold'
                : 'text-slate-400 hover:bg-[#151C24] hover:text-white'
            }`}
          >
            <Icon name="file-code" size={15} />
            <span>AST Evidence</span>
          </button>

          <button
            onClick={() => setActiveTab('risk')}
            className={`flex items-center gap-2 rounded-lg px-4 py-2 transition-colors ${
              activeTab === 'risk'
                ? 'border border-[#7DB7E8]/40 bg-[#7DB7E8]/10 text-[#7DB7E8] font-bold'
                : 'text-slate-400 hover:bg-[#151C24] hover:text-white'
            }`}
          >
            <Icon name="clock" size={15} />
            <span>Mosca Risk Analysis</span>
          </button>

          <button
            onClick={() => setActiveTab('recommendation')}
            className={`flex items-center gap-2 rounded-lg px-4 py-2 transition-colors ${
              activeTab === 'recommendation'
                ? 'border border-[#7DB7E8]/40 bg-[#7DB7E8]/10 text-[#7DB7E8] font-bold'
                : 'text-slate-400 hover:bg-[#151C24] hover:text-white'
            }`}
          >
            <Icon name="cpu" size={15} />
            <span>PQC Recommendation</span>
          </button>
        </div>
      </div>

      {/* TAB CONTENT: Overview */}
      {activeTab === 'overview' ? (
        <div className="space-y-6">
          <div className="grid gap-6 md:grid-cols-2">
            {/* Asset Classification Card */}
            <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-6 shadow-xl space-y-4">
              <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-slate-300 border-b border-[#222B35] pb-3">
                Classification & Parameters
              </h3>

              <div className="space-y-3 font-mono text-xs">
                <div className="flex justify-between border-b border-[#222B35]/60 pb-2">
                  <span className="text-slate-400">Algorithm Variant</span>
                  <span className="font-bold text-slate-100">{algorithm}</span>
                </div>
                <div className="flex justify-between border-b border-[#222B35]/60 pb-2">
                  <span className="text-slate-400">Resolved Parameter</span>
                  <span className="font-bold text-slate-100">{parameter || 'unknown'}</span>
                </div>
                <div className="flex justify-between border-b border-[#222B35]/60 pb-2">
                  <span className="text-slate-400">Artefact Type</span>
                  <span className="capitalize text-[#7DB7E8] font-bold">{artefactType}</span>
                </div>
                <div className="flex justify-between border-b border-[#222B35]/60 pb-2">
                  <span className="text-slate-400">Library / Import</span>
                  <span className="text-slate-200">{library || 'Standard Cryptography'}</span>
                </div>
                <div className="flex justify-between border-b border-[#222B35]/60 pb-2">
                  <span className="text-slate-400">Data Secrecy Lifetime (X)</span>
                  <span className="font-bold text-slate-100">{classification?.dataLifetimeYears || 15} years</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Business Criticality</span>
                  <span className="capitalize font-bold text-amber-400">{classification?.criticality || 'high'}</span>
                </div>
              </div>
            </div>

            {/* Quantum Exposure Assessment */}
            <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-6 shadow-xl space-y-4">
              <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-slate-300 border-b border-[#222B35] pb-3">
                Threat & Vulnerability Summary
              </h3>

              <div className="space-y-3 text-xs">
                <div className="rounded border border-[#222B35] bg-[#0C1117] p-3">
                  <span className="text-[11px] font-mono text-slate-400 block">Quantum Threat Model</span>
                  <p className="mt-1 font-semibold text-slate-200">{quantumRisk?.reason || 'Vulnerable to Shor\'s period finding'}</p>
                </div>

                <div className="rounded border border-[#222B35] bg-[#0C1117] p-3">
                  <span className="text-[11px] font-mono text-slate-400 block">Present Classical Risk</span>
                  <p className="mt-1 font-semibold text-slate-200">{currentRisk?.reason || 'Compliant with current classical NIST guidelines'}</p>
                </div>
              </div>
            </div>
          </div>

          <MoscaCard mosca={mosca} />
          <RecommendationCard recommendation={recommendation} />
        </div>
      ) : null}

      {/* TAB CONTENT: AST Evidence */}
      {activeTab === 'evidence' ? (
        <div className="space-y-6">
          <CodeEvidence evidence={evidence} />
        </div>
      ) : null}

      {/* TAB CONTENT: Mosca Risk Analysis */}
      {activeTab === 'risk' ? (
        <div className="space-y-6">
          <MoscaCard mosca={mosca} />
        </div>
      ) : null}

      {/* TAB CONTENT: PQC Recommendation */}
      {activeTab === 'recommendation' ? (
        <div className="space-y-6">
          <RecommendationCard recommendation={recommendation} />
        </div>
      ) : null}
    </div>
  );
}
