/**
 * agilityApi contract: URL encoding, unwrap, error path.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  getAgilityScore,
  type AgilityScoreResponse,
} from '@/services/agilityApi';

function mockFetchOnce(body: unknown, ok = true, status = 200): void {
  const fetchMock = vi.fn().mockResolvedValue({
    ok,
    status,
    text: async () => JSON.stringify(body),
  });
  vi.stubGlobal('fetch', fetchMock);
}

const SCORE: AgilityScoreResponse = {
  schemaVersion: 'blindspot.agility.v1',
  scanId: 'scan-a',
  projectId: 'demo',
  generatedAt: '2026-09-07T00:00:00+00:00',
  score: 88.75,
  grade: 'A',
  breakdown: {
    tierPosture: { earned: 55, max: 60 },
    weaknessImmunity: { earned: 20, max: 25 },
    hndlImmunity: { earned: 13.75, max: 15 },
  },
  inputs: {
    totalFindings: 8,
    overdue: 1,
    transitional: 0,
    lowRisk: 7,
    currentWeakCrypto: 1,
    hndlExposed: 1,
  },
  rationale: ['1 finding tier=overdue …'],
};

describe('getAgilityScore', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('hits /api/agility/{scanId} and URL-encodes the id', async () => {
    mockFetchOnce(SCORE);
    await getAgilityScore('weird/id');
    const url = String(
      (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0],
    );
    expect(url).toContain('/api/agility/weird%2Fid');
  });

  it('unwraps the response body', async () => {
    mockFetchOnce(SCORE);
    const result = await getAgilityScore('scan-a');
    expect(result.grade).toBe('A');
    expect(result.score).toBe(88.75);
    expect(result.breakdown.tierPosture.earned).toBe(55);
    expect(result.inputs.overdue).toBe(1);
  });

  it('surfaces backend 404 detail as an Error', async () => {
    mockFetchOnce({ detail: "No scan with id 'missing'." }, false, 404);
    await expect(getAgilityScore('missing')).rejects.toThrow(/missing/i);
  });
});
