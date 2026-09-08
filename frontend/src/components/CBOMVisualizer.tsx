import React, { useEffect, useMemo, useState } from 'react';
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';

import { Icon } from '@/components/Icon';
import {
  type CryptoAsset,
  assetName,
  assetType,
  countAssetTypes,
  countNames,
  countOccurrences,
  firstOccurrence,
  getDetectionsFromCbom,
  occurrenceFileName,
  occurrenceLine,
  occurrenceLocation,
  primitive,
  resolvePath,
} from '@/services/cbomModel';
import { displayTerm, getTermDescription } from '@/services/cryptoTerms';

interface CBOMVisualizerProps {
  cbomData?: unknown;
  className?: string;
}

/**
 * Categorical palette for the distribution charts.
 *
 * Deliberately blue / indigo / violet / cyan only — red, amber, and green are
 * reserved app-wide for risk tiers, so they never appear here decoratively.
 */
const PALETTE = [
  '#7DB7E8',
  '#A78BFA',
  '#60A5FA',
  '#818CF8',
  '#38BDF8',
  '#C084FC',
  '#93C5FD',
  '#F0ABFC',
  '#0EA5E9',
  '#6366F1',
  '#4F46E5',
  '#22D3EE',
];

/** Ordered specification rows, matching cbomkit's CryptoAssetDetails. */
const SPEC_PROPERTIES: { name: string; path: string }[] = [
  { name: 'Asset Type', path: 'cryptoProperties.assetType' },
  { name: 'Primitive', path: 'cryptoProperties.algorithmProperties.primitive' },
  { name: 'Primitive', path: 'cryptoProperties.primitive' },
  { name: 'Variant', path: 'cryptoProperties.algorithmProperties.variant' },
  {
    name: 'Parameter Set Identifier',
    path: 'cryptoProperties.algorithmProperties.parameterSetIdentifier',
  },
  { name: 'Curve', path: 'cryptoProperties.algorithmProperties.curve' },
  {
    name: 'Execution Environment',
    path: 'cryptoProperties.algorithmProperties.executionEnvironment',
  },
  {
    name: 'Implementation Platform',
    path: 'cryptoProperties.algorithmProperties.implementationPlatform',
  },
  {
    name: 'Certification Level',
    path: 'cryptoProperties.algorithmProperties.certificationLevel',
  },
  { name: 'Mode', path: 'cryptoProperties.algorithmProperties.mode' },
  { name: 'Padding', path: 'cryptoProperties.algorithmProperties.padding' },
  { name: 'Crypto Functions', path: 'cryptoProperties.algorithmProperties.cryptoFunctions' },
  {
    name: 'Classical Security Level',
    path: 'cryptoProperties.algorithmProperties.classicalSecurityLevel',
  },
  {
    name: 'NIST Quantum Security Level',
    path: 'cryptoProperties.algorithmProperties.nistQuantumSecurityLevel',
  },
  { name: 'Subject Name', path: 'cryptoProperties.certificateProperties.subjectName' },
  { name: 'Issuer Name', path: 'cryptoProperties.certificateProperties.issuerName' },
  { name: 'Not Valid Before', path: 'cryptoProperties.certificateProperties.notValidBefore' },
  { name: 'Not Valid After', path: 'cryptoProperties.certificateProperties.notValidAfter' },
  { name: 'Certificate Format', path: 'cryptoProperties.certificateProperties.certificateFormat' },
  { name: 'Type', path: 'cryptoProperties.relatedCryptoMaterialProperties.type' },
  { name: 'State', path: 'cryptoProperties.relatedCryptoMaterialProperties.state' },
  { name: 'Size', path: 'cryptoProperties.relatedCryptoMaterialProperties.size' },
  { name: 'Format', path: 'cryptoProperties.relatedCryptoMaterialProperties.format' },
  { name: 'Protocol Type', path: 'cryptoProperties.protocolProperties.type' },
  { name: 'Version', path: 'cryptoProperties.protocolProperties.version' },
  { name: 'OID', path: 'cryptoProperties.oid' },
  { name: 'BOM Reference', path: 'bom-ref' },
];

type SortKey = 'name' | 'type' | 'primitive' | 'location';
type SortDir = 'asc' | 'desc';

export const CBOMVisualizer: React.FC<CBOMVisualizerProps> = ({ cbomData, className = '' }) => {
  const [selected, setSelected] = useState<CryptoAsset | null>(null);
  const [sortKey, setSortKey] = useState<SortKey>('name');
  const [sortDir, setSortDir] = useState<SortDir>('asc');

  const detections = useMemo(() => getDetectionsFromCbom(cbomData), [cbomData]);

  const assetTypeDist = useMemo(
    () => countAssetTypes(detections, (key) => displayTerm(key)),
    [detections],
  );
  const primitiveDist = useMemo(
    () => countOccurrences(detections, 'primitive', (key) => displayTerm(key)),
    [detections],
  );
  const functionDist = useMemo(
    () => countOccurrences(detections, 'cryptoFunctions', (key) => displayTerm(key)),
    [detections],
  );
  const nameDist = useMemo(() => countNames(detections), [detections]);

  const sorted = useMemo(() => {
    const copy = [...detections];
    copy.sort((a, b) => {
      const va = sortValue(a, sortKey);
      const vb = sortValue(b, sortKey);
      const cmp = va.localeCompare(vb, undefined, { numeric: true });
      return sortDir === 'asc' ? cmp : -cmp;
    });
    return copy;
  }, [detections, sortKey, sortDir]);

  const meta = readMeta(cbomData);

  if (!cbomData) {
    return (
      <div
        className={`rounded-xl border border-[#222B35] bg-[#11171E] p-10 text-center ${className}`}
      >
        <Icon name="layers" size={28} className="mx-auto text-slate-600" />
        <p className="mt-3 text-sm text-slate-400">
          No CBOM available yet. Run a scan to generate the CycloneDX Cryptographic Bill of
          Materials.
        </p>
      </div>
    );
  }

  const onSort = (key: SortKey) => {
    if (key === sortKey) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir('asc');
    }
  };

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Meta strip */}
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 rounded-xl border border-[#222B35] bg-[#0C1117] px-4 py-3 text-xs">
        <MetaItem label="Format" value={`${meta.bomFormat || 'CycloneDX'} ${meta.specVersion || ''}`.trim()} />
        <MetaItem label="Crypto Assets" value={String(detections.length)} />
        <MetaItem label="Distinct Algorithms" value={String(nameDist.distinct)} />
        <MetaItem label="Distinct Primitives" value={String(primitiveDist.distinct)} />
        {meta.serialNumber ? (
          <div className="ml-auto truncate font-mono text-[10px] text-slate-500" title={meta.serialNumber}>
            {meta.serialNumber}
          </div>
        ) : null}
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <DonutChart
          title="Cryptographic Assets"
          data={assetTypeDist.entries}
          centerNumber={detections.length}
          centerLabel="Assets"
        />
        <DonutChart
          title="Cryptographic Primitives"
          data={primitiveDist.entries}
          centerNumber={primitiveDist.distinct}
          centerLabel="Primitives"
        />
        <DonutChart
          title="Cryptographic Functions"
          data={functionDist.entries}
          centerNumber={functionDist.distinct}
          centerLabel="Functions"
        />
      </div>

      {/* Detections table */}
      <div className="overflow-hidden rounded-xl border border-[#222B35] bg-[#11171E]">
        <div className="flex items-center justify-between border-b border-[#222B35] bg-[#0C1117] px-4 py-3">
          <div className="flex items-center gap-2">
            <Icon name="layers" size={16} className="text-[#7DB7E8]" />
            <h3 className="text-sm font-semibold text-slate-200">List of all assets</h3>
            <span className="rounded bg-[#7DB7E8]/10 px-2 py-0.5 text-[10px] font-medium text-[#7DB7E8]">
              {detections.length}
            </span>
          </div>
        </div>

        {detections.length === 0 ? (
          <div className="p-8 text-center text-sm text-slate-500">
            No cryptographic assets present in this CBOM.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-[#222B35] text-[11px] uppercase tracking-wider text-slate-500">
                  <SortableHeader label="Cryptographic asset" active={sortKey === 'name'} dir={sortDir} onClick={() => onSort('name')} />
                  <SortableHeader label="Type" active={sortKey === 'type'} dir={sortDir} onClick={() => onSort('type')} />
                  <SortableHeader label="Primitive" active={sortKey === 'primitive'} dir={sortDir} onClick={() => onSort('primitive')} />
                  <SortableHeader label="Location" active={sortKey === 'location'} dir={sortDir} onClick={() => onSort('location')} />
                  <th className="px-4 py-2.5 text-right font-medium">Details</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((asset, index) => {
                  const occ = firstOccurrence(asset);
                  const fileName = occurrenceFileName(occ);
                  const line = occurrenceLine(occ);
                  const type = assetType(asset);
                  const prim = primitive(asset);
                  return (
                    <tr
                      key={`${assetName(asset)}-${index}`}
                      className="border-b border-[#181F27] transition-colors hover:bg-[#151C24]"
                    >
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <Icon name="key" size={13} className="shrink-0 text-slate-500" />
                          <span className="font-semibold text-slate-100">
                            {assetName(asset).toUpperCase() || 'UNNAMED'}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-slate-300">
                        {type ? displayTerm(type) : <em className="text-slate-600">Unspecified</em>}
                      </td>
                      <td className="px-4 py-3 text-slate-300">
                        {prim ? displayTerm(prim) : <em className="text-slate-600">Unspecified</em>}
                      </td>
                      <td className="px-4 py-3">
                        {fileName ? (
                          <span className="font-mono text-[#7DB7E8]">
                            {fileName}
                            {line != null ? `:${line}` : ''}
                          </span>
                        ) : (
                          <em className="text-slate-600">No code location found</em>
                        )}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={() => setSelected(asset)}
                          aria-label={`See details for ${assetName(asset)}`}
                          className="rounded border border-[#222B35] bg-[#151C24] p-1.5 text-slate-400 transition-colors hover:border-[#7DB7E8]/50 hover:text-[#7DB7E8]"
                        >
                          <Icon name="eye" size={14} />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selected ? <AssetDetailModal asset={selected} onClose={() => setSelected(null)} /> : null}
    </div>
  );
};

// ── Sub-components ────────────────────────────────────────────────────────

const MetaItem: React.FC<{ label: string; value: string }> = ({ label, value }) => (
  <div className="flex items-baseline gap-1.5">
    <span className="text-[10px] uppercase tracking-wider text-slate-500">{label}</span>
    <span className="font-semibold text-slate-200">{value}</span>
  </div>
);

interface DonutChartProps {
  title: string;
  data: { key: string; label: string; value: number }[];
  centerNumber: number;
  centerLabel: string;
}

const DonutChart: React.FC<DonutChartProps> = ({ title, data, centerNumber, centerLabel }) => {
  return (
    <div className="rounded-xl border border-[#222B35] bg-[#11171E] p-4">
      <h4 className="mb-2 text-center text-xs font-semibold uppercase tracking-wider text-slate-400">
        {title}
      </h4>

      {data.length === 0 ? (
        <div className="flex h-[180px] items-center justify-center text-xs text-slate-600">
          No data
        </div>
      ) : (
        <>
          <div className="relative" style={{ height: 180 }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data}
                  dataKey="value"
                  nameKey="label"
                  cx="50%"
                  cy="50%"
                  innerRadius={52}
                  outerRadius={78}
                  paddingAngle={data.length > 1 ? 2 : 0}
                  stroke="none"
                  isAnimationActive={false}
                >
                  {data.map((entry, i) => (
                    <Cell key={entry.key} fill={PALETTE[i % PALETTE.length]} />
                  ))}
                </Pie>
                <Tooltip content={<ChartTooltip />} />
              </PieChart>
            </ResponsiveContainer>
            <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-2xl font-bold text-slate-100">{centerNumber}</span>
              <span className="text-[10px] uppercase tracking-wider text-slate-500">
                {centerLabel}
              </span>
            </div>
          </div>

          <ul className="mt-3 max-h-28 space-y-1 overflow-y-auto pr-1">
            {data.map((entry, i) => (
              <li key={entry.key} className="flex items-center justify-between gap-2 text-[11px]">
                <span className="flex min-w-0 items-center gap-2">
                  <span
                    className="h-2.5 w-2.5 shrink-0 rounded-sm"
                    style={{ background: PALETTE[i % PALETTE.length] }}
                  />
                  <span className="truncate text-slate-300" title={entry.label}>
                    {entry.label}
                  </span>
                </span>
                <span className="tabular-nums text-slate-500">{entry.value}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
};

interface ChartTooltipProps {
  active?: boolean;
  payload?: { name?: string; value?: number }[];
}

const ChartTooltip: React.FC<ChartTooltipProps> = ({ active, payload }) => {
  if (!active || !payload || payload.length === 0) {
    return null;
  }
  const entry = payload[0];
  const value = entry.value ?? 0;
  return (
    <div className="rounded border border-[#222B35] bg-[#0C1117] px-2.5 py-1.5 text-xs shadow-xl">
      <div className="font-medium text-slate-200">{entry.name}</div>
      <div className="text-slate-400">
        {value} detection{value === 1 ? '' : 's'}
      </div>
    </div>
  );
};

interface SortableHeaderProps {
  label: string;
  active: boolean;
  dir: SortDir;
  onClick: () => void;
}

const SortableHeader: React.FC<SortableHeaderProps> = ({ label, active, dir, onClick }) => (
  <th className="px-4 py-2.5 font-medium">
    <button
      onClick={onClick}
      className={`flex items-center gap-1 transition-colors hover:text-slate-300 ${
        active ? 'text-[#7DB7E8]' : ''
      }`}
    >
      <span>{label}</span>
      {active ? (
        <span className="text-[9px]">{dir === 'asc' ? '▲' : '▼'}</span>
      ) : null}
    </button>
  </th>
);

interface AssetDetailModalProps {
  asset: CryptoAsset;
  onClose: () => void;
}

const AssetDetailModal: React.FC<AssetDetailModalProps> = ({ asset, onClose }) => {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const occ = firstOccurrence(asset);
  const location = occurrenceLocation(occ);
  const line = occurrenceLine(occ);
  const snippet = occ && typeof occ.additionalContext === 'string' ? occ.additionalContext : null;
  const symbol = occ && typeof occ.symbol === 'string' ? occ.symbol : null;
  const type = assetType(asset);

  // De-duplicate specification rows (variant/primitive fallbacks may overlap).
  const specRows: { name: string; values: string[] }[] = [];
  const seenNames = new Set<string>();
  for (const property of SPEC_PROPERTIES) {
    const resolved = resolvePath(asset, property.path);
    if (!resolved || resolved.length === 0) {
      continue;
    }
    if (seenNames.has(property.name)) {
      continue;
    }
    seenNames.add(property.name);
    specRows.push({
      name: property.name,
      values: resolved.map((v) => displayTerm(v)),
    });
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
      role="dialog"
      aria-modal="true"
      aria-label="Cryptographic asset details"
      onClick={onClose}
    >
      <div
        className="max-h-[85vh] w-full max-w-2xl overflow-hidden rounded-xl border border-[#222B35] bg-[#11171E] shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between border-b border-[#222B35] bg-[#0C1117] px-5 py-4">
          <div>
            <div className="text-[10px] uppercase tracking-wider text-slate-500">
              {type ? displayTerm(type) : 'Cryptographic Asset'}
            </div>
            <h3 className="mt-0.5 text-lg font-bold text-slate-100">
              {assetName(asset).toUpperCase() || 'UNNAMED ASSET'}
            </h3>
          </div>
          <button
            onClick={onClose}
            aria-label="Close details"
            className="rounded p-1 text-slate-400 transition-colors hover:bg-[#151C24] hover:text-white"
          >
            <Icon name="close" size={18} />
          </button>
        </div>

        <div className="max-h-[calc(85vh-70px)] overflow-y-auto px-5 py-4">
          {/* Code location */}
          <section className="mb-5">
            <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
              Code
            </h4>
            {location ? (
              <div className="rounded-lg border border-[#222B35] bg-[#080B0F] p-3">
                <div className="font-mono text-xs text-[#7DB7E8]">
                  {location}
                  {line != null ? `:${line}` : ''}
                </div>
                {snippet ? (
                  <pre className="mt-2 overflow-x-auto whitespace-pre-wrap font-mono text-[11px] text-slate-300">
                    {snippet}
                  </pre>
                ) : null}
                {!snippet && symbol ? (
                  <div className="mt-2 font-mono text-[11px] text-slate-400">
                    Rule / symbol: <span className="text-slate-300">{symbol}</span>
                  </div>
                ) : null}
              </div>
            ) : (
              <div className="rounded-lg border border-[#222B35] bg-[#080B0F] p-3 text-xs text-slate-500">
                No code location has been specified in the CBOM for this cryptographic asset.
              </div>
            )}
          </section>

          {/* Specification */}
          <section>
            <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
              Specification
            </h4>
            <div className="overflow-hidden rounded-lg border border-[#222B35]">
              <table className="w-full text-left text-xs">
                <tbody>
                  {specRows.map((row, i) => (
                    <tr
                      key={`${row.name}-${i}`}
                      className="border-b border-[#181F27] last:border-b-0"
                    >
                      <td className="w-2/5 bg-[#0C1117] px-3 py-2 align-top font-medium text-slate-400">
                        {row.name}
                      </td>
                      <td className="px-3 py-2 text-slate-200">
                        {row.values.map((value, vi) => {
                          const description = getTermDescription(rawFor(asset, row, vi));
                          return (
                            <div key={vi} className="py-0.5" title={description ?? undefined}>
                              {value}
                            </div>
                          );
                        })}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
};

// ── Helpers ───────────────────────────────────────────────────────────────

function sortValue(asset: CryptoAsset, key: SortKey): string {
  switch (key) {
    case 'name':
      return assetName(asset).toLowerCase();
    case 'type':
      return displayTerm(assetType(asset)).toLowerCase();
    case 'primitive':
      return displayTerm(primitive(asset)).toLowerCase();
    case 'location': {
      const occ = firstOccurrence(asset);
      return occurrenceFileName(occ).toLowerCase();
    }
    default:
      return '';
  }
}

function rawFor(
  asset: CryptoAsset,
  row: { name: string; values: string[] },
  index: number,
): unknown {
  const property = SPEC_PROPERTIES.find((p) => p.name === row.name);
  if (!property) {
    return undefined;
  }
  const resolved = resolvePath(asset, property.path);
  return resolved ? resolved[index] : undefined;
}

interface CbomMeta {
  bomFormat?: string;
  specVersion?: string;
  serialNumber?: string;
}

function readMeta(cbom: unknown): CbomMeta {
  if (typeof cbom !== 'object' || cbom === null) {
    return {};
  }
  const record = cbom as Record<string, unknown>;
  return {
    bomFormat: typeof record.bomFormat === 'string' ? record.bomFormat : undefined,
    specVersion: typeof record.specVersion === 'string' ? record.specVersion : undefined,
    serialNumber: typeof record.serialNumber === 'string' ? record.serialNumber : undefined,
  };
}
