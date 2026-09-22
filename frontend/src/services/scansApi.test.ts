/**
 * scansApi contract: URLs, wire shapes, and error propagation.
 *
 * We stub global.fetch so the test does not depend on the backend.
 * Every test asserts the URL, the query params, and the returned shape.
 */

import { beforeEach, describe, expect, it, vi, afterEach } from 'vitest';

import { listScans, getScan, getScanTrend } from '@/services/scansApi';

function mockFetchOnce(body: unknown, init: Partial<Response> = {}): void {
  const fetchMock = vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    text: async () => JSON.stringify(body),
    ...init,
  });
  vi.stubGlobal('fetch', fetchMock);
}

function mockFetchError(status: number, detail = 'nope'): void {
  const fetchMock = vi.fn().mockResolvedValue({
    ok: false,
    status,
    text: async () => JSON.stringify({ detail }),
  });
  vi.stubGlobal('fetch', fetchMock);
}

describe('scansApi', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('listScans hits /api/scans and parses the row list', async () => {
    mockFetchOnce({
      count: 1,
      scans: [
        {
          scanId: 'scan-1',
          projectId: 'demo',
          ownerId: null,
          status: 'completed',
          mode: 'live',
          repository: 'demo-repo',
          startedAt: '2026-09-07T10:00:00+00:00',
          completedAt: '2026-09-07T10:05:00+00:00',
          findingCount: 12,
          summary: {
            totalFindings: 12,
            overdue: 3,
            transitional: 2,
            lowRisk: 7,
            hndlExposed: 1,
            currentWeakCrypto: 0,
          },
        },
      ],
    });

    const result = await listScans();
    expect(result.count).toBe(1);
    expect(result.scans[0].scanId).toBe('scan-1');
    expect(result.scans[0].summary.overdue).toBe(3);
    expect((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0]).toContain(
      '/api/scans',
    );
  });

  it('listScans forwards project_id as a query parameter', async () => {
    mockFetchOnce({ count: 0, scans: [] });
    await listScans({ projectId: 'alpha' });
    const url = String((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0]);
    expect(url).toContain('project_id=alpha');
  });

  it('getScan hits /api/scans/{id} and encodes the id', async () => {
    mockFetchOnce({
      scan: { id: 'weird/id' },
      findings: [],
      cbom: '{"specVersion":"1.6"}',
    });
    await getScan('weird/id');
    const url = String((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0]);
    expect(url).toContain('/api/scans/weird%2Fid');
  });

  it('getScanTrend hits /api/scans/trend with project_id and returns points', async () => {
    mockFetchOnce({
      projectId: 'demo',
      count: 2,
      points: [
        {
          scanId: 's1',
          startedAt: '2026-09-01T00:00:00+00:00',
          totalFindings: 10,
          overdue: 3,
          transitional: 2,
          lowRisk: 5,
          hndlExposed: 1,
          currentWeakCrypto: 0,
        },
        {
          scanId: 's2',
          startedAt: '2026-09-05T00:00:00+00:00',
          totalFindings: 8,
          overdue: 1,
          transitional: 2,
          lowRisk: 5,
          hndlExposed: 0,
          currentWeakCrypto: 0,
        },
      ],
    });

    const result = await getScanTrend('demo');
    expect(result.count).toBe(2);
    expect(result.points.map((p) => p.overdue)).toEqual([3, 1]);
    const url = String((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0]);
    expect(url).toContain('/api/scans/trend?project_id=demo');
  });

  it('surfaces the backend detail on a 5xx', async () => {
    mockFetchError(500, 'artifacts dir missing');
    await expect(listScans()).rejects.toThrow(/artifacts dir missing/i);
  });

  it('surfaces a 404 as an error for getScan (unknown id)', async () => {
    mockFetchError(404, 'not found');
    await expect(getScan('missing')).rejects.toThrow(/not found/i);
  });
});
