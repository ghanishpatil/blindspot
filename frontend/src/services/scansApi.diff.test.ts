/**
 * getScanDiff contract: URL, params, response shape, error paths.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { getScanDiff, type ScanDiffResponse } from '@/services/scansApi';

function mockFetchOnce(body: unknown, ok = true, status = 200): void {
  const fetchMock = vi.fn().mockResolvedValue({
    ok,
    status,
    text: async () => JSON.stringify(body),
  });
  vi.stubGlobal('fetch', fetchMock);
}

const OK_BODY: ScanDiffResponse = {
  base: {
    scanId: 'scan-old',
    projectId: 'demo',
    startedAt: '2026-09-01T00:00:00Z',
    completedAt: '2026-09-01T00:00:00Z',
    findingCount: 1,
    summary: { overdue: 1 },
  },
  head: {
    scanId: 'scan-new',
    projectId: 'demo',
    startedAt: '2026-09-02T00:00:00Z',
    completedAt: '2026-09-02T00:00:00Z',
    findingCount: 0,
    summary: { overdue: 0 },
  },
  summaryDelta: { overdue: -1 },
  added: [],
  removed: [],
  changed: [
    {
      id: 'CRYPTO-RSA-0',
      algorithm: 'RSA',
      displayName: 'RSA-2048',
      parameter: '2048',
      curve: null,
      filePath: 'src/demo.py',
      lineNumber: 10,
      riskTier: 'low-risk',
      isHndlExposed: false,
      isCurrentlyWeak: false,
      detectionMethod: 'semgrep_api_pattern',
      previousTier: 'overdue',
      currentTier: 'low-risk',
      previousLineNumber: 10,
    },
  ],
  unchangedCount: 0,
  addedCount: 0,
  removedCount: 0,
  changedCount: 1,
};

describe('getScanDiff', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('hits /api/scans/diff with base + head query params', async () => {
    mockFetchOnce(OK_BODY);
    await getScanDiff('scan-old', 'scan-new');
    const url = String(
      (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0],
    );
    expect(url).toContain('/api/scans/diff');
    expect(url).toContain('base=scan-old');
    expect(url).toContain('head=scan-new');
  });

  it('returns the parsed diff shape end-to-end', async () => {
    mockFetchOnce(OK_BODY);
    const result = await getScanDiff('scan-old', 'scan-new');
    expect(result.changedCount).toBe(1);
    expect(result.summaryDelta.overdue).toBe(-1);
    expect(result.changed[0].previousTier).toBe('overdue');
    expect(result.changed[0].currentTier).toBe('low-risk');
  });

  it('URL-encodes ids with slashes so /scans/{scan_id} does not collide', async () => {
    mockFetchOnce(OK_BODY);
    await getScanDiff('weird/base', 'plain-head');
    const url = String(
      (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0],
    );
    // URLSearchParams encodes '/' as '%2F'.
    expect(url).toContain('base=weird%2Fbase');
  });

  it('surfaces backend 4xx detail as an Error', async () => {
    mockFetchOnce({ detail: 'Base and head scan ids must be different.' }, false, 400);
    await expect(getScanDiff('same', 'same')).rejects.toThrow(
      /must be different/i,
    );
  });

  it('surfaces backend 404 as an Error', async () => {
    mockFetchOnce({ detail: "No scan with id 'missing'." }, false, 404);
    await expect(getScanDiff('missing', 'existing')).rejects.toThrow(
      /missing/i,
    );
  });
});
