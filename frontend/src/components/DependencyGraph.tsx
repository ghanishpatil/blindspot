import { useEffect, useMemo, useState } from 'react';

import { Icon } from '@/components/Icon';
import {
  getGraph,
  type GraphNode,
  type GraphResponse,
} from '@/services/graphApi';
import { listScans } from '@/services/scansApi';

interface DependencyGraphProps {
  projectId?: string;
}

type State =
  | { kind: 'loading' }
  | { kind: 'empty' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; graph: GraphResponse };

/**
 * Bipartite blast-radius graph.
 *
 * File nodes ring around the outside, algorithm nodes sit in an inner
 * ring, and one straight edge per finding connects them. Nodes are
 * coloured by their worst tier (overdue = red, transitional = amber,
 * low-risk = green). Clicking a node filters the details panel to
 * its associated findings.
 *
 * SVG-only, no graph library, no physics engine. The radial layout
 * is deterministic (angles derived from sort order), which means the
 * same scan always renders the same picture -- important for demos.
 */
export function DependencyGraph({ projectId }: DependencyGraphProps) {
  const [state, setState] = useState<State>({ kind: 'loading' });
  const [selectedId, setSelectedId] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    setState({ kind: 'loading' });

    (async () => {
      try {
        const list = await listScans({ projectId, signal: controller.signal });
        if (controller.signal.aborted) return;
        const latest = list.scans[0]?.scanId;
        if (!latest) {
          setState({ kind: 'empty' });
          return;
        }
        const graph = await getGraph(latest, controller.signal);
        if (controller.signal.aborted) return;
        setState({ kind: 'ready', graph });
        setSelectedId(null);
      } catch (err: unknown) {
        if (controller.signal.aborted) return;
        setState({
          kind: 'error',
          message: err instanceof Error ? err.message : 'Failed to load graph.',
        });
      }
    })();

    return () => controller.abort();
  }, [projectId]);

  return (
    <section className="surface-panel p-6" data-testid="dependency-graph-panel">
      <header className="mb-4">
        <div className="eyebrow">Blast-radius graph</div>
        <h2 className="mt-1 text-lg font-semibold text-[color:var(--color-ink)]">
          Which files touch which algorithms
        </h2>
        <p className="mt-1 max-w-2xl text-[11px] text-[color:var(--color-ink-muted)]">
          Outer ring: source files. Inner ring: cryptographic algorithms.
          One line per finding. Colour = worst tier at that node. Click
          any node to filter the details panel below.
        </p>
      </header>

      {state.kind === 'loading' ? (
        <p className="flex items-center gap-2 py-4 text-[11px] text-[color:var(--color-ink-muted)]">
          <Icon name="refresh" size={14} className="animate-spin" />
          Loading graph…
        </p>
      ) : null}

      {state.kind === 'empty' ? (
        <div
          className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-[color:var(--color-border-subtle)] py-8 text-center text-[11px] text-[color:var(--color-ink-muted)]"
          data-testid="dependency-graph-empty"
        >
          <Icon name="cpu" size={18} className="text-slate-500" />
          <p>Run a scan to see the blast-radius graph.</p>
        </div>
      ) : null}

      {state.kind === 'error' ? (
        <p className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-[11px] text-red-300">
          {state.message}
        </p>
      ) : null}

      {state.kind === 'ready' ? (
        <GraphView
          graph={state.graph}
          selectedId={selectedId}
          onSelect={setSelectedId}
        />
      ) : null}
    </section>
  );
}

// ---------------------------------------------------------------------------
// SVG renderer
// ---------------------------------------------------------------------------
//
// Layout: two concentric rings.
//
//   * Outer ring  -> file nodes; radius scales with `blastRadius`.
//   * Inner ring  -> algorithm nodes; radius scales with `findingCount`.
//   * Edges       -> one straight line per finding; opacity dims when the
//                    user has selected a node and this edge is off-focus.
//
// Everything is deterministic (polar coordinates from sort index) so the
// same scan always produces the exact same picture -- reproducible demos.
// Animations are pure CSS keyframes injected into the SVG's <defs>; no
// JS animation loop, no library dependency, replays automatically when
// React re-mounts after a fresh scan.

const VIEWBOX = 760;
const CENTER = VIEWBOX / 2;
const OUTER_RADIUS = 305;
const INNER_RADIUS = 140;
const FILE_LABEL_OFFSET = 20;

const GraphView: React.FC<{
  graph: GraphResponse;
  selectedId: string | null;
  onSelect: (id: string | null) => void;
}> = ({ graph, selectedId, onSelect }) => {
  const files = useMemo(
    () => graph.nodes.filter((n) => n.kind === 'file'),
    [graph],
  );
  const algorithms = useMemo(
    () => graph.nodes.filter((n) => n.kind === 'algorithm'),
    [graph],
  );

  // Compute polar coordinates. Angles are evenly spread; nodes are
  // ordered by their sorted position in the response, so the layout
  // is deterministic across renders.
  const filePositions = useMemo(
    () => _radialPositions(files, OUTER_RADIUS),
    [files],
  );
  const algorithmPositions = useMemo(
    () => _radialPositions(algorithms, INNER_RADIUS),
    [algorithms],
  );

  const positionById = useMemo(() => {
    const map = new Map<string, { x: number; y: number }>();
    for (const [n, p] of filePositions) map.set(n.id, p);
    for (const [n, p] of algorithmPositions) map.set(n.id, p);
    return map;
  }, [filePositions, algorithmPositions]);

  const connectedIds = useMemo(() => {
    if (!selectedId) return null;
    const ids = new Set<string>([selectedId]);
    for (const e of graph.edges) {
      if (e.source === selectedId) ids.add(e.target);
      if (e.target === selectedId) ids.add(e.source);
    }
    return ids;
  }, [selectedId, graph.edges]);

  const selectedNode = selectedId
    ? graph.nodes.find((n) => n.id === selectedId) ?? null
    : null;
  const selectedFindings = useMemo(() => {
    if (!selectedId) return [];
    return graph.edges.filter(
      (e) => e.source === selectedId || e.target === selectedId,
    );
  }, [selectedId, graph.edges]);

  // Track hover independently so the user gets tooltip + preview
  // highlighting without commiting to a selection.
  const [hoverId, setHoverId] = useState<string | null>(null);
  const focusId = hoverId ?? selectedId;
  const focusNode = focusId
    ? graph.nodes.find((n) => n.id === focusId) ?? null
    : null;

  // ── Precompute per-node visual attributes -------------------------------
  const orderedNodes: Array<{
    node: GraphNode;
    pos: { x: number; y: number };
    r: number;
    stagger: number;
  }> = useMemo(() => {
    const rows: Array<{
      node: GraphNode;
      pos: { x: number; y: number };
      r: number;
      stagger: number;
    }> = [];
    // Files render first so algorithms overlay them at overlap points.
    let idx = 0;
    for (const [node, pos] of filePositions) {
      rows.push({ node, pos, r: _fileRadius(node), stagger: idx++ });
    }
    for (const [node, pos] of algorithmPositions) {
      rows.push({ node, pos, r: _algorithmRadius(node), stagger: idx++ });
    }
    return rows;
  }, [filePositions, algorithmPositions]);

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
      <div className="rounded-md border border-[color:var(--color-border-subtle)] bg-[color:var(--color-canvas-deep)] p-2">
        <svg
          viewBox={`0 0 ${VIEWBOX} ${VIEWBOX}`}
          role="img"
          aria-label="Blast-radius graph"
          className="w-full h-auto"
          data-testid="dependency-graph-svg"
          onClick={(e) => {
            // Background clicks clear selection.
            if ((e.target as SVGElement).tagName === 'svg') onSelect(null);
          }}
        >
          <defs>
            {/* Soft glow used to spotlight the selected node. */}
            <filter id="graph-glow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="4" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
            {/* Radial background so the inner ring glows subtly. */}
            <radialGradient id="graph-bg" cx="50%" cy="50%" r="55%">
              <stop offset="0%" stopColor="#111827" stopOpacity="0.9" />
              <stop offset="100%" stopColor="#0b0f19" stopOpacity="1" />
            </radialGradient>
            <style>{`
              @keyframes graph-node-in {
                0%   { opacity: 0; transform: scale(0.2); }
                60%  { opacity: 1; transform: scale(1.08); }
                100% { opacity: 1; transform: scale(1); }
              }
              @keyframes graph-edge-in {
                from { stroke-dashoffset: var(--edge-len, 600); opacity: 0.05; }
                to   { stroke-dashoffset: 0; opacity: var(--edge-alpha, 0.5); }
              }
              @keyframes graph-ring-in {
                from { opacity: 0; stroke-dashoffset: 1800; }
                to   { opacity: 0.5; stroke-dashoffset: 0; }
              }
              @keyframes graph-pulse {
                0%, 100% { r: var(--r-base, 16); }
                50%      { r: var(--r-pulse, 20); }
              }
              .graph-node-inner {
                transform-box: fill-box;
                transform-origin: center center;
                animation: graph-node-in 520ms cubic-bezier(0.2, 0.9, 0.3, 1.2) both;
                animation-delay: calc(var(--stagger, 0) * 25ms);
                transition: transform 180ms ease-out;
              }
              .graph-node:hover .graph-node-inner {
                transform: scale(1.18);
              }
              .graph-node.is-selected .graph-node-inner {
                transform: scale(1.15);
              }
              .graph-node.is-selected .graph-node-halo {
                animation: graph-pulse 1.6s ease-in-out infinite;
              }
              .graph-edge {
                stroke-dasharray: var(--edge-len, 600);
                stroke-dashoffset: var(--edge-len, 600);
                animation: graph-edge-in 900ms ease-out both;
                animation-delay: 320ms;
                transition:
                  opacity 200ms ease-out,
                  stroke-width 200ms ease-out;
              }
              .graph-ring {
                stroke-dasharray: 1800;
                animation: graph-ring-in 900ms ease-out both;
              }
            `}</style>
          </defs>

          {/* Subtle background + concentric guides so the two rings read as
              rings, not as a scattered dot cloud. */}
          <circle cx={CENTER} cy={CENTER} r={VIEWBOX / 2 - 4} fill="url(#graph-bg)" />
          <circle
            className="graph-ring"
            cx={CENTER}
            cy={CENTER}
            r={OUTER_RADIUS}
            fill="none"
            stroke="rgba(148, 163, 184, 0.18)"
            strokeWidth={1}
            strokeDasharray="4 6"
          />
          <circle
            className="graph-ring"
            cx={CENTER}
            cy={CENTER}
            r={INNER_RADIUS}
            fill="none"
            stroke="rgba(148, 163, 184, 0.24)"
            strokeWidth={1}
            strokeDasharray="4 6"
            style={{ animationDelay: '160ms' } as React.CSSProperties}
          />

          {/* Center hub: at-a-glance shape of the graph. */}
          <g pointerEvents="none">
            <text
              x={CENTER}
              y={CENTER - 6}
              textAnchor="middle"
              fontSize={11}
              fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
              fill="rgba(226, 232, 240, 0.5)"
              letterSpacing="2"
            >
              BLAST RADIUS
            </text>
            <text
              x={CENTER}
              y={CENTER + 12}
              textAnchor="middle"
              fontSize={13}
              fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
              fontWeight={600}
              fill="rgba(226, 232, 240, 0.85)"
            >
              {graph.counts.files} files → {graph.counts.algorithms} algorithms
            </text>
          </g>

          {/* Edges under nodes so nodes overlay them cleanly. */}
          <g data-testid="dependency-graph-edges">
            {graph.edges.map((e, idx) => {
              const src = positionById.get(e.source);
              const dst = positionById.get(e.target);
              if (!src || !dst) return null;
              const active =
                !connectedIds ||
                connectedIds.has(e.source) ||
                connectedIds.has(e.target);
              const focused =
                focusId &&
                (e.source === focusId || e.target === focusId);
              const alpha = focused ? 0.85 : active ? 0.4 : 0.06;
              const width = focused ? 2 : active ? 1.2 : 0.8;
              // Length used for the draw-in animation via CSS var.
              const dx = dst.x - src.x;
              const dy = dst.y - src.y;
              const length = Math.hypot(dx, dy);
              return (
                <line
                  key={`${e.source}-${e.target}-${idx}`}
                  className="graph-edge"
                  x1={CENTER + src.x}
                  y1={CENTER + src.y}
                  x2={CENTER + dst.x}
                  y2={CENTER + dst.y}
                  stroke={_tierColor(e.tier)}
                  strokeWidth={width}
                  strokeLinecap="round"
                  style={
                    {
                      '--edge-len': length,
                      '--edge-alpha': alpha,
                      opacity: alpha,
                    } as React.CSSProperties
                  }
                />
              );
            })}
          </g>

          <g data-testid="dependency-graph-nodes">
            {orderedNodes.map(({ node, pos, r, stagger }) => {
              const isSelected = selectedId === node.id;
              const isHovered = hoverId === node.id;
              const isDim = connectedIds && !connectedIds.has(node.id);
              const color = _tierColor(node.tier);
              const cx = CENTER + pos.x;
              const cy = CENTER + pos.y;

              return (
                <g
                  key={node.id}
                  className={`graph-node ${isSelected ? 'is-selected' : ''}`}
                  transform={`translate(${cx}, ${cy})`}
                  style={{
                    cursor: 'pointer',
                    opacity: isDim && !isHovered ? 0.35 : 1,
                    transition: 'opacity 200ms ease-out',
                  }}
                  onClick={() => onSelect(isSelected ? null : node.id)}
                  onMouseEnter={() => setHoverId(node.id)}
                  onMouseLeave={() =>
                    setHoverId((prev) => (prev === node.id ? null : prev))
                  }
                  data-testid={`graph-node-${node.kind}`}
                >
                  {/* Halo: soft outer ring that pulses when selected. */}
                  <circle
                    className="graph-node-halo"
                    r={r + 6}
                    fill={color}
                    fillOpacity={isSelected ? 0.25 : isHovered ? 0.18 : 0}
                    style={
                      {
                        '--r-base': r + 6,
                        '--r-pulse': r + 12,
                        transition: 'fill-opacity 220ms ease-out',
                      } as React.CSSProperties
                    }
                  />
                  {/* Inner group carries the entrance animation so it
                      scales in-place around the node's own center. */}
                  <g
                    className="graph-node-inner"
                    style={{ ['--stagger' as string]: stagger }}
                  >
                    <circle
                      r={r}
                      fill={color}
                      fillOpacity={0.92}
                      stroke={isSelected ? '#f8fafc' : color}
                      strokeWidth={isSelected ? 2.5 : 1.5}
                      filter={isSelected ? 'url(#graph-glow)' : undefined}
                    />
                    {node.kind === 'algorithm' ? (
                      <text
                        textAnchor="middle"
                        dy="0.35em"
                        fontSize={r >= 20 ? 10 : 9}
                        fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
                        fill="#0b0b12"
                        fontWeight={700}
                        pointerEvents="none"
                      >
                        {_algorithmDisplayLabel(node.label, r)}
                      </text>
                    ) : null}
                  </g>
                  {/* File labels sit *outside* the outer ring, angled so
                      they lean away from the center like clock hands.
                      Kept short: basename only, ellipsised if needed. */}
                  {node.kind === 'file' ? (
                    <FileLabel
                      angleRadians={Math.atan2(pos.y, pos.x)}
                      radius={r}
                      label={_fileBasename(node.label)}
                      accent={color}
                      active={Boolean(isHovered || isSelected || (focusId && connectedIds?.has(node.id)))}
                    />
                  ) : null}
                </g>
              );
            })}
          </g>

          {/* Legend + hover tooltip live in-SVG so they scale with the panel. */}
          <Legend />
          {focusNode ? (
            <HoverTooltip
              node={focusNode}
              pos={positionById.get(focusNode.id) ?? { x: 0, y: 0 }}
            />
          ) : null}
        </svg>
      </div>

      <DetailsPanel
        graph={graph}
        selectedNode={selectedNode}
        selectedFindings={selectedFindings}
      />
    </div>
  );
};

// ---------------------------------------------------------------------------
// Sub-parts: file label, legend, tooltip
// ---------------------------------------------------------------------------

/** File name outside the outer ring, oriented tangentially so it reads
 *  clockwise when the ring is walked. */
const FileLabel: React.FC<{
  angleRadians: number;
  radius: number;
  label: string;
  accent: string;
  active: boolean;
}> = ({ angleRadians, radius, label, accent, active }) => {
  const deg = (angleRadians * 180) / Math.PI;
  // Keep labels upright on the left half of the ring so they don't
  // read upside-down.
  const flip = deg > 90 || deg < -90;
  const rotate = flip ? deg + 180 : deg;
  const dxOut = radius + FILE_LABEL_OFFSET;
  return (
    <g
      transform={`rotate(${rotate}) translate(${flip ? -dxOut : dxOut}, 0)`}
      pointerEvents="none"
    >
      <text
        textAnchor={flip ? 'end' : 'start'}
        dy="0.35em"
        fontSize={9.5}
        fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
        fill={active ? accent : 'rgba(226, 232, 240, 0.65)'}
        style={{ transition: 'fill 200ms ease-out' }}
      >
        {label}
      </text>
    </g>
  );
};

const Legend: React.FC = () => {
  const items: Array<{ tier: string; label: string }> = [
    { tier: 'overdue', label: 'Overdue' },
    { tier: 'transitional', label: 'Transitional' },
    { tier: 'low-risk', label: 'Low-risk' },
    { tier: 'unknown', label: 'Unknown' },
  ];
  return (
    <g
      transform={`translate(${VIEWBOX - 168}, ${VIEWBOX - 96})`}
      pointerEvents="none"
    >
      <rect
        width={158}
        height={82}
        rx={8}
        fill="rgba(15, 23, 42, 0.75)"
        stroke="rgba(148, 163, 184, 0.25)"
      />
      <text
        x={10}
        y={16}
        fontSize={9}
        letterSpacing="1.5"
        fill="rgba(226, 232, 240, 0.55)"
        fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
      >
        RISK TIER
      </text>
      {items.map((it, i) => (
        <g key={it.tier} transform={`translate(10, ${32 + i * 12})`}>
          <circle cx={4} cy={0} r={4} fill={_tierColor(it.tier)} />
          <text
            x={14}
            y={3}
            fontSize={9.5}
            fill="rgba(226, 232, 240, 0.85)"
            fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
          >
            {it.label}
          </text>
        </g>
      ))}
    </g>
  );
};

const HoverTooltip: React.FC<{
  node: GraphNode;
  pos: { x: number; y: number };
}> = ({ node, pos }) => {
  const isRight = pos.x < 0;
  const anchorX = CENTER + pos.x + (isRight ? 22 : -22);
  const anchorY = CENTER + pos.y;
  const width = 210;
  const height = 58;
  const boxX = isRight ? anchorX : anchorX - width;
  const boxY = Math.max(6, Math.min(VIEWBOX - height - 6, anchorY - height / 2));
  const label =
    node.kind === 'file' ? _fileBasename(node.label) : node.label;
  return (
    <g pointerEvents="none" style={{ transition: 'transform 120ms ease-out' }}>
      <rect
        x={boxX}
        y={boxY}
        width={width}
        height={height}
        rx={8}
        fill="rgba(15, 23, 42, 0.92)"
        stroke={_tierColor(node.tier)}
        strokeOpacity={0.55}
      />
      <text
        x={boxX + 12}
        y={boxY + 20}
        fontSize={10}
        fill="rgba(226, 232, 240, 0.6)"
        fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
      >
        {node.kind === 'file' ? 'FILE' : 'ALGORITHM'} · tier {node.tier ?? 'n/a'}
      </text>
      <text
        x={boxX + 12}
        y={boxY + 36}
        fontSize={12}
        fontWeight={600}
        fill="#f8fafc"
        fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
      >
        {_ellipsise(label, 26)}
      </text>
      <text
        x={boxX + 12}
        y={boxY + 50}
        fontSize={10}
        fill="rgba(226, 232, 240, 0.75)"
        fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
      >
        {node.findingCount} finding{node.findingCount === 1 ? '' : 's'}
        {node.kind === 'file'
          ? ` · blast radius ${node.blastRadius}`
          : ''}
      </text>
    </g>
  );
};

// ---------------------------------------------------------------------------
// Details panel + helpers (unchanged behavioural contract).
// ---------------------------------------------------------------------------

const DetailsPanel: React.FC<{
  graph: GraphResponse;
  selectedNode: GraphNode | null;
  selectedFindings: GraphResponse['edges'];
}> = ({ graph, selectedNode, selectedFindings }) => {
  if (!selectedNode) {
    return (
      <div
        className="rounded-md border border-[color:var(--color-border-subtle)] bg-[color:var(--color-canvas-deep)] p-4 text-[11px] text-[color:var(--color-ink-muted)]"
        data-testid="dependency-graph-details-empty"
      >
        <p>
          Click a node to inspect it. Outer nodes are source files (
          {graph.counts.files}); inner nodes are algorithms (
          {graph.counts.algorithms}). Total {graph.counts.edges} findings.
        </p>
        <ul className="mt-3 space-y-1">
          {Object.entries(graph.counts.filesByTier).map(([tier, n]) => (
            <li key={tier} className="flex items-center gap-2">
              <span
                className="inline-block h-2 w-4 rounded"
                style={{ background: _tierColor(tier) }}
              />
              <span>
                {n} file{n === 1 ? '' : 's'} tier={tier}
              </span>
            </li>
          ))}
        </ul>
      </div>
    );
  }

  return (
    <div
      className="rounded-md border border-[color:var(--color-border-subtle)] bg-[color:var(--color-canvas-deep)] p-4 text-[11px]"
      data-testid="dependency-graph-details"
    >
      <div className="mb-2 flex items-center justify-between">
        <span className="eyebrow-muted">
          Selected {selectedNode.kind}
        </span>
        <span
          className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-widest"
          style={{
            background: `${_tierColor(selectedNode.tier)}22`,
            color: _tierColor(selectedNode.tier),
          }}
        >
          {selectedNode.tier ?? 'n/a'}
        </span>
      </div>
      <h3 className="font-mono text-sm text-[color:var(--color-ink)]">
        {selectedNode.label}
      </h3>
      <dl className="mt-3 grid grid-cols-2 gap-y-1 text-[11px]">
        <dt className="text-[color:var(--color-ink-muted)]">Findings</dt>
        <dd className="font-mono text-[color:var(--color-ink)]">
          {selectedNode.findingCount}
        </dd>
        {selectedNode.kind === 'file' ? (
          <>
            <dt className="text-[color:var(--color-ink-muted)]">Blast radius</dt>
            <dd
              className="font-mono text-[color:var(--color-ink)]"
              data-testid="dependency-graph-blast-radius"
            >
              {selectedNode.blastRadius} algorithm
              {selectedNode.blastRadius === 1 ? '' : 's'}
            </dd>
          </>
        ) : null}
      </dl>
      {selectedFindings.length > 0 ? (
        <div className="mt-4">
          <div className="mb-2 text-[10px] uppercase tracking-widest text-[color:var(--color-ink-muted)]">
            Related findings
          </div>
          <ul
            className="max-h-[220px] space-y-1 overflow-auto"
            data-testid="dependency-graph-related"
          >
            {selectedFindings.map((e, idx) => (
              <li
                key={`${e.source}-${e.target}-${idx}`}
                className="rounded-md border border-[color:var(--color-border-subtle)] bg-[color:var(--color-canvas)] px-2 py-1 font-mono text-[10px]"
              >
                {e.findingId ?? '(unbound)'} · tier={e.tier ?? 'n/a'}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Layout + colouring helpers
// ---------------------------------------------------------------------------

function _radialPositions(
  nodes: GraphNode[],
  radius: number,
): Array<[GraphNode, { x: number; y: number }]> {
  const n = nodes.length;
  if (n === 0) return [];
  const step = (Math.PI * 2) / n;
  return nodes.map((node, i) => {
    // Rotate so the first slot sits at the top (12 o'clock) rather than 3 o'clock.
    const angle = -Math.PI / 2 + i * step;
    return [
      node,
      { x: Math.cos(angle) * radius, y: Math.sin(angle) * radius },
    ] as [GraphNode, { x: number; y: number }];
  });
}

function _tierColor(tier: string | null): string {
  switch (tier) {
    case 'overdue':
      return '#EF4444';
    case 'transitional':
      return '#F59E0B';
    case 'low-risk':
      return '#10B981';
    default:
      return '#94A3B8';
  }
}

/** File-node radius: 5 (minimum, low blast radius) → 20 (very
 *  impactful file). Sub-linear so a single dominant file doesn't
 *  visually eclipse the entire layout. */
function _fileRadius(node: GraphNode): number {
  const b = Math.max(0, node.blastRadius);
  const scaled = 5 + Math.sqrt(b) * 4;
  return Math.min(20, Math.max(5, scaled));
}

/** Algorithm-node radius: bigger baseline than file nodes because the
 *  label lives inside them. Scales with total findings using the same
 *  sub-linear curve. */
function _algorithmRadius(node: GraphNode): number {
  const c = Math.max(0, node.findingCount);
  const scaled = 14 + Math.sqrt(c) * 3;
  return Math.min(28, Math.max(14, scaled));
}

/** Basename of a file path, forward- or back-slash agnostic. Used for
 *  outer-ring labels; the details panel still shows the full path. */
function _fileBasename(path: string): string {
  const s = path.replace(/\\/g, '/');
  const idx = s.lastIndexOf('/');
  const base = idx === -1 ? s : s.slice(idx + 1);
  return _ellipsise(base, 22);
}

/** Fit an algorithm label into a circle: bigger circles get more room.
 *  Deterministic (no measuring). */
function _algorithmDisplayLabel(label: string, radius: number): string {
  const budget = Math.max(4, Math.floor(radius * 0.9));
  return _ellipsise(label, budget);
}

function _ellipsise(text: string, budget: number): string {
  if (text.length <= budget) return text;
  if (budget <= 1) return text.slice(0, budget);
  return text.slice(0, budget - 1) + '…';
}
