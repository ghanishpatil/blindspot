/**
 * graphApi contract: URL encoding, unwrap, error path.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { getGraph, type GraphResponse } from '@/services/graphApi';

function mockFetchOnce(body: unknown, ok = true, status = 200): void {
  const fetchMock = vi.fn().mockResolvedValue({
    ok,
    status,
    text: async () => JSON.stringify(body),
  });
  vi.stubGlobal('fetch', fetchMock);
}

const G: GraphResponse = {
  schemaVersion: 'blindspot.graph.v1',
  scanId: 'scan-1',
  projectId: 'demo',
  generatedAt: null,
  nodes: [],
  edges: [],
  counts: { files: 0, algorithms: 0, edges: 0, filesByTier: {}, algorithmsByTier: {} },
};

describe('getGraph', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('hits /api/graph/{id} with URL encoding', async () => {
    mockFetchOnce(G);
    await getGraph('weird/id');
    const url = String(
      (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0],
    );
    expect(url).toContain('/api/graph/weird%2Fid');
  });

  it('unwraps the graph', async () => {
    mockFetchOnce(G);
    const g = await getGraph('scan-1');
    expect(g.schemaVersion).toBe('blindspot.graph.v1');
  });

  it('surfaces backend errors', async () => {
    mockFetchOnce({ detail: 'not found' }, false, 404);
    await expect(getGraph('missing')).rejects.toThrow(/not found/i);
  });
});
