/**
 * benchmarkApi contract: verbs, URLs, response unwrap, 404 handling.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  getLatestBenchmark,
  runBenchmark,
  type BenchmarkReport,
} from '@/services/benchmarkApi';

function mockFetchOnce(body: unknown, ok = true, status = 200): void {
  const fetchMock = vi.fn().mockResolvedValue({
    ok,
    status,
    text: async () => JSON.stringify(body),
  });
  vi.stubGlobal('fetch', fetchMock);
}

const REPORT: BenchmarkReport = {
  schemaVersion: 'blindspot.benchmark.report.v1',
  datasetName: 'blindspot-builtin',
  datasetDescription: 'test',
  generatedAt: '2026-09-07T00:00:00+00:00',
  pipelineVersion: '0.1.0',
  elapsedSeconds: 0.5,
  totalCases: 2,
  totalExpected: 1,
  totalReported: 1,
  overall: {
    tp: 1, fp: 0, fn: 0, tn: 1,
    precision: 1.0, recall: 1.0, f1: 1.0, accuracy: 1.0,
  },
  categories: {
    'weak-crypto/rsa': {
      tp: 1, fp: 0, fn: 0, tn: 0,
      precision: 1.0, recall: 1.0, f1: 1.0, accuracy: 1.0,
      cases: 1,
    },
  },
  cases: [],
};

describe('benchmarkApi', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('runBenchmark POSTs to /api/benchmark/run', async () => {
    mockFetchOnce(REPORT);
    const report = await runBenchmark();
    const [url, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(String(url)).toContain('/api/benchmark/run');
    expect(init?.method).toBe('POST');
    expect(report.overall.f1).toBe(1.0);
  });

  it('getLatestBenchmark GETs /api/benchmark/latest and unwraps', async () => {
    mockFetchOnce(REPORT);
    const report = await getLatestBenchmark();
    const [url, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(String(url)).toContain('/api/benchmark/latest');
    expect(init?.method).toBe('GET');
    expect(report?.datasetName).toBe('blindspot-builtin');
  });

  it('getLatestBenchmark returns null on a 404 (no run cached yet)', async () => {
    mockFetchOnce({ detail: 'No benchmark run has completed yet.' }, false, 404);
    const report = await getLatestBenchmark();
    expect(report).toBeNull();
  });

  it('getLatestBenchmark rethrows non-404 errors', async () => {
    mockFetchOnce({ detail: 'boom' }, false, 500);
    await expect(getLatestBenchmark()).rejects.toThrow(/boom/i);
  });

  it('runBenchmark surfaces backend error detail as an Error', async () => {
    mockFetchOnce({ detail: 'semgrep exploded' }, false, 500);
    await expect(runBenchmark()).rejects.toThrow(/semgrep exploded/i);
  });
});
