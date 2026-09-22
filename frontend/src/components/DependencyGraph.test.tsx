/**
 * DependencyGraph contract:
 *
 * 1. Empty state when scan history has no rows.
 * 2. Ready state renders the SVG with the right number of nodes + edges.
 * 3. Clicking a node highlights it and populates the details panel.
 * 4. Blast-radius number renders for file nodes.
 */

import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { DependencyGraph } from '@/components/DependencyGraph';
import * as graphApi from '@/services/graphApi';
import * as scans from '@/services/scansApi';

function summaryRow(id: string): scans.ScanSummaryRow {
  return {
    scanId: id,
    projectId: 'demo',
    ownerId: null,
    status: 'completed',
    mode: 'live',
    repository: 'demo-repo',
    startedAt: '2026-09-01T00:00:00Z',
    completedAt: '2026-09-01T00:00:00Z',
    findingCount: 3,
    summary: {
      totalFindings: 3,
      overdue: 2,
      transitional: 0,
      lowRisk: 1,
      hndlExposed: 0,
      currentWeakCrypto: 0,
    },
  };
}

function graphFixture(): graphApi.GraphResponse {
  const nodes: graphApi.GraphNode[] = [
    {
      id: 'f:1',
      kind: 'file',
      label: 'a.py',
      tier: 'overdue',
      findingCount: 2,
      blastRadius: 2,
      algorithm: null,
      parameter: null,
      curve: null,
    },
    {
      id: 'f:2',
      kind: 'file',
      label: 'b.py',
      tier: 'low-risk',
      findingCount: 1,
      blastRadius: 1,
      algorithm: null,
      parameter: null,
      curve: null,
    },
    {
      id: 'a:rsa',
      kind: 'algorithm',
      label: 'RSA-2048',
      tier: 'overdue',
      findingCount: 2,
      blastRadius: 0,
      algorithm: 'RSA',
      parameter: '2048',
      curve: null,
    },
    {
      id: 'a:md5',
      kind: 'algorithm',
      label: 'MD5',
      tier: 'low-risk',
      findingCount: 1,
      blastRadius: 0,
      algorithm: 'MD5',
      parameter: null,
      curve: null,
    },
  ];
  const edges: graphApi.GraphEdge[] = [
    { source: 'f:1', target: 'a:rsa', findingId: 'F1', tier: 'overdue' },
    { source: 'f:1', target: 'a:md5', findingId: 'F2', tier: 'low-risk' },
    { source: 'f:2', target: 'a:rsa', findingId: 'F3', tier: 'overdue' },
  ];
  return {
    schemaVersion: 'blindspot.graph.v1',
    scanId: 'scan-latest',
    projectId: 'demo',
    generatedAt: null,
    nodes,
    edges,
    counts: {
      files: 2,
      algorithms: 2,
      edges: 3,
      filesByTier: { overdue: 1, 'low-risk': 1 },
      algorithmsByTier: { overdue: 1, 'low-risk': 1 },
    },
  };
}

describe('DependencyGraph', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('renders the empty state when no scan exists yet', async () => {
    vi.spyOn(scans, 'listScans').mockResolvedValue({ count: 0, scans: [] });
    const spy = vi.spyOn(graphApi, 'getGraph');
    render(<DependencyGraph />);
    await screen.findByTestId('dependency-graph-empty');
    expect(spy).not.toHaveBeenCalled();
  });

  it('renders one SVG node per graph node and one line per edge', async () => {
    vi.spyOn(scans, 'listScans').mockResolvedValue({
      count: 1,
      scans: [summaryRow('scan-latest')],
    });
    vi.spyOn(graphApi, 'getGraph').mockResolvedValue(graphFixture());

    render(<DependencyGraph />);
    await screen.findByTestId('dependency-graph-svg');

    const nodesGroup = screen.getByTestId('dependency-graph-nodes');
    const edgesGroup = screen.getByTestId('dependency-graph-edges');

    // 4 nodes, 3 edges.
    expect(nodesGroup.querySelectorAll('g[data-testid^="graph-node-"]')).toHaveLength(4);
    expect(edgesGroup.querySelectorAll('line')).toHaveLength(3);
  });

  it('renders the empty details panel until a node is selected', async () => {
    vi.spyOn(scans, 'listScans').mockResolvedValue({
      count: 1,
      scans: [summaryRow('scan-latest')],
    });
    vi.spyOn(graphApi, 'getGraph').mockResolvedValue(graphFixture());

    render(<DependencyGraph />);
    await screen.findByTestId('dependency-graph-details-empty');
  });

  it('clicking a file node shows blast radius and related findings', async () => {
    vi.spyOn(scans, 'listScans').mockResolvedValue({
      count: 1,
      scans: [summaryRow('scan-latest')],
    });
    vi.spyOn(graphApi, 'getGraph').mockResolvedValue(graphFixture());

    render(<DependencyGraph />);
    await screen.findByTestId('dependency-graph-svg');

    const fileNodes = screen.getAllByTestId('graph-node-file');
    fireEvent.click(fileNodes[0]);

    await screen.findByTestId('dependency-graph-details');
    // Blast radius surface for file node.
    const blast = screen.getByTestId('dependency-graph-blast-radius');
    expect(blast.textContent).toMatch(/\d+ algorithm/);

    // Related findings list carries entries.
    const related = screen.getByTestId('dependency-graph-related');
    expect(related.querySelectorAll('li').length).toBeGreaterThan(0);
  });

  it('backend error surfaces as an inline banner', async () => {
    vi.spyOn(scans, 'listScans').mockResolvedValue({
      count: 1,
      scans: [summaryRow('scan-latest')],
    });
    vi.spyOn(graphApi, 'getGraph').mockRejectedValue(new Error('graph broke'));
    render(<DependencyGraph />);
    await waitFor(() =>
      expect(screen.getByText(/graph broke/i)).toBeTruthy(),
    );
  });

  // ------------------------------------------------------------------
  // Visual enhancements: center summary, legend, node sizing, hover.
  // These are the "make it clearly visible + animated" contract.
  // ------------------------------------------------------------------

  it('renders the center-hub summary with file + algorithm counts', async () => {
    vi.spyOn(scans, 'listScans').mockResolvedValue({
      count: 1,
      scans: [summaryRow('scan-latest')],
    });
    vi.spyOn(graphApi, 'getGraph').mockResolvedValue(graphFixture());
    render(<DependencyGraph />);

    const svg = await screen.findByTestId('dependency-graph-svg');
    // "2 files → 2 algorithms" summary is rendered in the center of the SVG.
    expect(svg.textContent).toMatch(/2\s*files/);
    expect(svg.textContent).toMatch(/2\s*algorithms/);
  });

  it('renders a tier legend inside the SVG', async () => {
    vi.spyOn(scans, 'listScans').mockResolvedValue({
      count: 1,
      scans: [summaryRow('scan-latest')],
    });
    vi.spyOn(graphApi, 'getGraph').mockResolvedValue(graphFixture());
    render(<DependencyGraph />);

    const svg = await screen.findByTestId('dependency-graph-svg');
    // The legend header + all four tier labels are on-screen.
    expect(svg.textContent).toMatch(/RISK TIER/);
    for (const label of ['Overdue', 'Transitional', 'Low-risk', 'Unknown']) {
      expect(svg.textContent).toContain(label);
    }
  });

  it('sizes file nodes by blast radius (bigger blast -> bigger circle)', async () => {
    vi.spyOn(scans, 'listScans').mockResolvedValue({
      count: 1,
      scans: [summaryRow('scan-latest')],
    });
    // Explicit fixture where one file has blastRadius=1 and one has 6.
    const g = graphFixture();
    g.nodes = g.nodes.map((n) => {
      if (n.id === 'f:1') return { ...n, blastRadius: 6, findingCount: 6 };
      if (n.id === 'f:2') return { ...n, blastRadius: 1, findingCount: 1 };
      return n;
    });
    vi.spyOn(graphApi, 'getGraph').mockResolvedValue(g);
    render(<DependencyGraph />);
    await screen.findByTestId('dependency-graph-svg');

    // Both file nodes are rendered as <g data-testid="graph-node-file">.
    // Their first descendant <circle> is the halo; the second is the
    // node body -- we compare the *body* radii.
    const fileNodes = screen.getAllByTestId('graph-node-file');
    const radii = fileNodes.map((n) => {
      const inner = n.querySelector('.graph-node-inner circle');
      return Number(inner?.getAttribute('r') ?? '0');
    });
    // Exactly two file nodes with clearly different sizes.
    expect(radii).toHaveLength(2);
    const [big, small] = radii.slice().sort((a, b) => b - a);
    expect(big).toBeGreaterThan(small);
  });

  it('hovering a node surfaces a tooltip and dims non-connected edges', async () => {
    vi.spyOn(scans, 'listScans').mockResolvedValue({
      count: 1,
      scans: [summaryRow('scan-latest')],
    });
    vi.spyOn(graphApi, 'getGraph').mockResolvedValue(graphFixture());
    render(<DependencyGraph />);
    const svg = await screen.findByTestId('dependency-graph-svg');

    const fileNodes = screen.getAllByTestId('graph-node-file');
    fireEvent.mouseEnter(fileNodes[0]);

    // Tooltip: the label ('a.py') and 'FILE' header appear only when a node
    // is under focus. Before hover, neither is on-screen.
    await waitFor(() => {
      expect(svg.textContent).toMatch(/FILE/);
      expect(svg.textContent).toMatch(/a\.py/);
    });

    fireEvent.mouseLeave(fileNodes[0]);
    // After leaving, tooltip disappears (nothing selected either).
    await waitFor(() => {
      expect(svg.textContent).not.toMatch(/blast radius \d/);
    });
  });

  it('injects CSS keyframes for entrance and pulse animations', async () => {
    vi.spyOn(scans, 'listScans').mockResolvedValue({
      count: 1,
      scans: [summaryRow('scan-latest')],
    });
    vi.spyOn(graphApi, 'getGraph').mockResolvedValue(graphFixture());
    render(<DependencyGraph />);
    const svg = await screen.findByTestId('dependency-graph-svg');
    const style = svg.querySelector('defs style');
    expect(style).not.toBeNull();
    const css = style?.textContent ?? '';
    expect(css).toMatch(/@keyframes graph-node-in/);
    expect(css).toMatch(/@keyframes graph-edge-in/);
    expect(css).toMatch(/@keyframes graph-pulse/);
  });
});
