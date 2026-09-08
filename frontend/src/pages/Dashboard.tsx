import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';

import { FindingTable } from '@/components/FindingTable';
import { Icon } from '@/components/Icon';
import { RiskBadge } from '@/components/RiskBadge';
import { fetchFindings, fetchHealth, startScan } from '@/services/api';
import { DEMO_HEALTH_RESPONSE, DEMO_PLANTED_FINDINGS } from '@/services/mockData';
import type { Finding, HealthResponse } from '@/types';

type LoadState =
  | { kind: 'loading' }
  | { kind: 'loaded'; health: HealthResponse; findings: Finding[] }
  | { kind: 'error'; message: string };

const SUBSYSTEM_LABELS: Record<string, string> = {
  firebase: 'Firebase (Auth, Firestore, Storage)',
  semgrep: 'Semgrep AST Scanner',
  demoRepository: 'Seeded Demo Repository',
  fallbackCache: 'Cached Fallback Scan',
};

const RISK_COLORS: Record<string, string> = {
  Overdue: '#EF4444',
  Transitional: '#F59E0B',
  'Low Risk': '#22C55E',
  'Weak Now': '#F43F5E',
};

export default function Dashboard() {
  const navigate = useNavigate();
  const [load, setLoad] = useState<LoadState>({ kind: 'loading' });
  const [scanning, setScanning] = useState(false);

  useEffect(() => {
    let cancelled = false;

    fetchHealth()
      .then(async (health) => {
        let findings: Finding[] = [];
        try {
          findings = await fetchFindings({ projectId: 'demo' });
        } catch {
          findings = DEMO_PLANTED_FINDINGS;
        }
        return { health, findings };
      })
      .catch(() => {
        return { health: DEMO_HEALTH_RESPONSE, findings: DEMO_PLANTED_FINDINGS };
      })
      .then(({ health, findings }) => {
        if (!cancelled) {
          setLoad({
            kind: 'loaded',
            health: health || DEMO_HEALTH_RESPONSE,
            findings: findings && findings.length > 0 ? findings : DEMO_PLANTED_FINDINGS,
          });
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const handleRunScan = async () => {
    setScanning(true);
    try {
      await startScan({ projectId: 'demo' });
      const updatedFindings = await fetchFindings({ projectId: 'demo' });
      const updatedHealth = await fetchHealth();
      setLoad({ kind: 'loaded', health: updatedHealth, findings: updatedFindings });
    } catch (err) {
      console.error('Scan failed:', err);
    } finally {
      setScanning(false);
    }
  };

  if (load.kind === 'loading') {
    return (
      <div className="flex h-96 flex-col items-center justify-center space-y-4">
        <Icon name="refresh" size={32} className="animate-spin text-[#7DB7E8]" />
        <p className="text-sm font-mono text-slate-400">Loading Cryptographic Posture…</p>
      </div>
    );
  }

  if (load.kind === 'error') {
    return (
      <div className="rounded-xl border border-red-500/40 bg-red-500/10 p-6 text-slate-100">
        <div className="flex items-center gap-3">
          <Icon name="alert-triangle" size={24} className="text-red-400" />
          <h2 className="text-lg font-semibold">Backend Unreachable</h2>
        </div>
        <p className="mt-2 text-sm text-slate-300">{load.message}</p>
        <p className="mt-4 font-mono text-xs text-slate-400">
          Run: <code className="text-[#7DB7E8]">uvicorn app.main:app --reload --port 8000</code> in <code className="text-slate-300">backend/</code>
        </p>
      </div>
    );
  }

  const { findings, health } = load;

  // Calculate posture metrics
  const totalFindings = findings.length;
  const overdueCount = findings.filter((f) => f.riskTier === 'overdue').length;
  const transitionalCount = findings.filter((f) => f.riskTier === 'transitional').length;
  const lowRiskCount = findings.filter((f) => f.riskTier === 'low-risk').length;
  const weakNowCount = findings.filter((f) => f.isCurrentlyWeak).length;

  const pieData = [
    { name: 'Overdue', value: overdueCount },
    { name: 'Transitional', value: transitionalCount },
    { name: 'Low Risk', value: lowRiskCount },
  ].filter((d) => d.value > 0);

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">Cryptographic Posture</h1>
          <p className="mt-1 text-xs text-slate-400">
            Real-time cryptographic inventory, quantum risk assessment, and migration status.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleRunScan}
            disabled={scanning}
            className="flex items-center gap-2 rounded-lg border border-[#7DB7E8]/40 bg-[#7DB7E8] px-4 py-2 text-xs font-semibold text-[#080B0F] shadow-[0_0_15px_rgba(125,183,232,0.2)] transition-all hover:bg-[#9BC7EA]"
          >
            <Icon name="refresh" size={14} className={scanning ? 'animate-spin' : ''} />
            <span>{scanning ? 'Scanning Target...' : 'Run Live Scan'}</span>
          </button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid gap-4 grid-cols-2 lg:grid-cols-5">
        <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-4 shadow-lg">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold">Total Assets</span>
            <Icon name="database" size={16} className="text-[#7DB7E8]" />
          </div>
          <p className="mt-2 font-mono text-2xl font-bold text-slate-100">{totalFindings}</p>
          <span className="text-[11px] text-slate-500 block mt-1">Discovered primitives</span>
        </div>

        <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-4 shadow-lg">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold">Findings</span>
            <Icon name="search" size={16} className="text-[#7DB7E8]" />
          </div>
          <p className="mt-2 font-mono text-2xl font-bold text-[#7DB7E8]">{totalFindings}</p>
          <span className="text-[11px] text-slate-500 block mt-1">
            {weakNowCount > 0 ? `${weakNowCount} weak classical` : 'Evidence recorded'}
          </span>
        </div>

        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 shadow-lg">
          <div className="flex items-center justify-between text-red-400">
            <span className="text-xs font-semibold">Overdue</span>
            <Icon name="alert-triangle" size={16} />
          </div>
          <p className="mt-2 font-mono text-2xl font-bold text-red-400">{overdueCount}</p>
          <span className="text-[11px] text-red-400/80 block mt-1">Urgent PQC migration</span>
        </div>

        <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 shadow-lg">
          <div className="flex items-center justify-between text-amber-400">
            <span className="text-xs font-semibold">Transitional</span>
            <Icon name="clock" size={16} />
          </div>
          <p className="mt-2 font-mono text-2xl font-bold text-amber-400">{transitionalCount}</p>
          <span className="text-[11px] text-amber-400/80 block mt-1">Hybrid transition</span>
        </div>

        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-4 shadow-lg">
          <div className="flex items-center justify-between text-emerald-400">
            <span className="text-xs font-semibold">Low Risk</span>
            <Icon name="check-circle" size={16} />
          </div>
          <p className="mt-2 font-mono text-2xl font-bold text-emerald-400">{lowRiskCount}</p>
          <span className="text-[11px] text-emerald-400/80 block mt-1">Defer & monitor</span>
        </div>
      </div>

      {/* Visual Analytics Row */}
      <div className="grid gap-6 md:grid-cols-3">
        {/* Risk Distribution Chart */}
        <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-6 shadow-xl">
          <div className="flex items-center justify-between border-b border-[#222B35] pb-3">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
              Risk Distribution
            </h3>
            <span className="text-[11px] text-slate-500">Mosca Framework</span>
          </div>

          <div className="h-48 mt-4">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={45}
                  outerRadius={70}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={RISK_COLORS[entry.name] || '#94A3B8'} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#080B0F', borderColor: '#222B35', borderRadius: '8px' }}
                  itemStyle={{ color: '#F1F5F9', fontSize: '12px', fontFamily: 'monospace' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* Legend */}
          <div className="flex justify-center gap-4 text-xs font-mono">
            <div className="flex items-center gap-1.5 text-red-400">
              <span className="h-2.5 w-2.5 rounded-full bg-red-500" />
              <span>Overdue ({overdueCount})</span>
            </div>
            <div className="flex items-center gap-1.5 text-amber-400">
              <span className="h-2.5 w-2.5 rounded-full bg-amber-500" />
              <span>Transitional ({transitionalCount})</span>
            </div>
            <div className="flex items-center gap-1.5 text-emerald-400">
              <span className="h-2.5 w-2.5 rounded-full bg-emerald-500" />
              <span>Low Risk ({lowRiskCount})</span>
            </div>
          </div>
        </div>

        {/* Algorithm & Artefact Breakdown */}
        <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-6 shadow-xl md:col-span-2">
          <div className="flex items-center justify-between border-b border-[#222B35] pb-3">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
              Discovered Cryptographic Primitives
            </h3>
            <span className="text-[11px] font-mono text-[#7DB7E8]">Seeded Demo Target</span>
          </div>

          <div className="mt-4 space-y-3">
            {findings.map((f) => (
              <div
                key={f.id}
                onClick={() => navigate(`/findings/${f.id}`)}
                className="flex items-center justify-between rounded-lg border border-[#222B35] bg-[#0C1117] p-3 transition-all hover:border-[#7DB7E8]/50 cursor-pointer"
              >
                <div className="flex items-center gap-3">
                  <div className="flex h-8 w-8 items-center justify-center rounded bg-[#151C24] font-mono font-bold text-xs text-[#7DB7E8]">
                    {f.primitive.slice(0, 3).toUpperCase()}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-semibold text-xs text-slate-100">{f.algorithm}</span>
                      <span className="text-slate-500 text-xs">• {f.filePath}:{f.lineNumber}</span>
                    </div>
                    <p className="text-[11px] text-slate-400">{f.displayName}</p>
                  </div>
                </div>

                <div className="flex items-center gap-4">
                  <span className="font-mono text-xs text-[#7DB7E8]">{f.recommendation?.algorithm}</span>
                  <RiskBadge tier={f.riskTier} size="sm" />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Main Recent Findings Grid */}
      <section aria-labelledby="recent-findings">
        <div className="flex items-center justify-between mb-4">
          <h2 id="recent-findings" className="text-lg font-bold text-slate-100">
            Cryptographic Inventory & Findings
          </h2>
          <button
            onClick={() => navigate('/findings')}
            className="text-xs font-mono font-semibold text-[#7DB7E8] hover:underline"
          >
            View All Findings →
          </button>
        </div>

        <FindingTable findings={findings} />
      </section>

      {/* Subsystem Health Monitor */}
      <section className="rounded-xl border border-[#222B35] bg-[#0C1117] p-6">
        <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 mb-4">
          Pipeline Readiness & Subsystem Readiness
        </h2>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {Object.entries(health.subsystems).map(([name, status]) => (
            <div key={name} className="rounded-lg border border-[#222B35] bg-[#11171E] p-3.5">
              <div className="flex items-center gap-2">
                <span className={`h-2 w-2 rounded-full ${status.available ? 'bg-emerald-500' : 'bg-amber-500'}`} />
                <span className="font-medium text-xs text-slate-200">{SUBSYSTEM_LABELS[name] || name}</span>
              </div>
              <p className="mt-1 text-[11px] text-slate-400 pl-4">{status.reason || 'Subsystem ready'}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
