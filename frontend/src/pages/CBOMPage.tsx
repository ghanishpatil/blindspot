import React, { useEffect, useState } from 'react';

import { CBOMPreview } from '@/components/CBOMPreview';
import { CBOMVisualizer } from '@/components/CBOMVisualizer';
import { Icon } from '@/components/Icon';
import { fetchCbom } from '@/services/api';

type CbomView = 'visualizer' | 'json';

export const CBOMPage: React.FC = () => {
  const [cbomData, setCbomData] = useState<unknown | null>(null);
  const [loading, setLoading] = useState(true);
  const [view, setView] = useState<CbomView>('visualizer');

  useEffect(() => {
    fetchCbom()
      .then((data) => setCbomData(data))
      .catch((err) => console.error('Failed to load CBOM:', err))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">
            Cryptographic Bill of Materials (CBOM)
          </h1>
          <p className="mt-1 text-xs text-slate-400">
            Standardized CycloneDX v1.6 inventory specification of all cryptographic primitives,
            parameters, and evidence.
          </p>
        </div>

        {/* Visualizer / JSON segmented control */}
        <div
          role="tablist"
          aria-label="CBOM view"
          className="flex items-center gap-1 rounded-lg border border-[#222B35] bg-[#0C1117] p-1"
        >
          <ViewTab
            active={view === 'visualizer'}
            onClick={() => setView('visualizer')}
            icon="barchart"
            label="Visualizer"
          />
          <ViewTab
            active={view === 'json'}
            onClick={() => setView('json')}
            icon="file-json"
            label="JSON"
          />
        </div>
      </div>

      {loading ? (
        <div className="flex h-64 items-center justify-center gap-2">
          <Icon name="refresh" size={24} className="animate-spin text-[#7DB7E8]" />
          <span className="text-xs font-mono text-slate-400">
            Loading CycloneDX CBOM specification...
          </span>
        </div>
      ) : view === 'visualizer' ? (
        <CBOMVisualizer cbomData={cbomData} />
      ) : (
        <CBOMPreview cbomData={cbomData} scanId="demo-repo" />
      )}
    </div>
  );
};

interface ViewTabProps {
  active: boolean;
  onClick: () => void;
  icon: 'barchart' | 'file-json';
  label: string;
}

const ViewTab: React.FC<ViewTabProps> = ({ active, onClick, icon, label }) => (
  <button
    role="tab"
    aria-selected={active}
    onClick={onClick}
    className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
      active
        ? 'bg-[#7DB7E8]/15 text-[#7DB7E8]'
        : 'text-slate-400 hover:bg-[#151C24] hover:text-slate-200'
    }`}
  >
    <Icon name={icon} size={14} />
    <span>{label}</span>
  </button>
);
