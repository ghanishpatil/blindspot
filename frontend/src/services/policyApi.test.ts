/**
 * policyApi contract: URLs, verbs, request bodies, error paths.
 *
 * The transport module is thin and the backend is the schema
 * authority. These tests only lock down what the transport promises:
 * hit the right endpoint, send the right JSON, unwrap the response,
 * and surface backend `detail` messages as thrown Errors.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  getActivePolicy,
  getDefaultPolicy,
  resetActivePolicy,
  saveActivePolicy,
  simulatePolicy,
  type PolicyEnvelope,
  type PolicySimulationResponse,
} from '@/services/policyApi';

function mockFetchOnce(body: unknown, ok = true, status = 200): void {
  const fetchMock = vi.fn().mockResolvedValue({
    ok,
    status,
    text: async () => JSON.stringify(body),
  });
  vi.stubGlobal('fetch', fetchMock);
}

const ENVELOPE_DEFAULT: PolicyEnvelope = {
  schemaVersion: 'blindspot.policy.v1',
  isDefault: true,
  policy: {
    schemaVersion: 'blindspot.policy.v1',
    name: 'blindspot-default',
    rules: [
      { id: 'no-new-weak-now', on: 'introduced', match: { isCurrentlyWeak: true }, action: 'block' },
    ],
  },
};

const ENVELOPE_CUSTOM: PolicyEnvelope = {
  schemaVersion: 'blindspot.policy.v1',
  isDefault: false,
  policy: {
    schemaVersion: 'blindspot.policy.v1',
    name: 'custom',
    rules: [
      { id: 'r1', on: 'introduced', match: { isQuantumSensitive: true }, action: 'block' },
    ],
  },
};

const SIM_RESULT: PolicySimulationResponse = {
  policyName: 'custom',
  counts: { introduced: 1, resolved: 0, changed: 0, unchanged: 5 },
  violations: [
    { ruleId: 'r1', findingId: 'F-1', reason: 'q', field: 'isQuantumSensitive', value: true, action: 'block' },
  ],
  blockCount: 1,
  warnCount: 0,
  wouldBlock: true,
};

describe('policyApi', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('getActivePolicy hits GET /api/policy', async () => {
    mockFetchOnce(ENVELOPE_DEFAULT);
    const env = await getActivePolicy();
    const call = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(String(call[0])).toContain('/api/policy');
    expect(call[1]?.method ?? 'GET').toBe('GET');
    expect(env.isDefault).toBe(true);
    expect(env.policy.name).toBe('blindspot-default');
  });

  it('getDefaultPolicy hits GET /api/policy/default', async () => {
    mockFetchOnce(ENVELOPE_DEFAULT);
    await getDefaultPolicy();
    const url = String((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0]);
    expect(url).toContain('/api/policy/default');
  });

  it('saveActivePolicy PUTs the JSON body verbatim', async () => {
    mockFetchOnce(ENVELOPE_CUSTOM);
    const env = await saveActivePolicy(ENVELOPE_CUSTOM.policy);
    const [, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(init?.method).toBe('PUT');
    expect(JSON.parse(String(init?.body))).toEqual(ENVELOPE_CUSTOM.policy);
    expect(env.isDefault).toBe(false);
    expect(env.policy.name).toBe('custom');
  });

  it('saveActivePolicy surfaces 400 detail as Error', async () => {
    mockFetchOnce({ detail: "policy.rules[0].action must be one of ..." }, false, 400);
    await expect(saveActivePolicy({ name: 'bad', rules: [] })).rejects.toThrow(
      /action/i,
    );
  });

  it('resetActivePolicy POSTs to /api/policy/reset', async () => {
    mockFetchOnce(ENVELOPE_DEFAULT);
    await resetActivePolicy();
    const [url, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(String(url)).toContain('/api/policy/reset');
    expect(init?.method).toBe('POST');
  });

  it('simulatePolicy sends {base, head} when policy=null', async () => {
    mockFetchOnce(SIM_RESULT);
    await simulatePolicy('scan-a', 'scan-b', null);
    const [, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse(String(init?.body));
    expect(body).toEqual({ base: 'scan-a', head: 'scan-b' });
    expect(init?.method).toBe('POST');
  });

  it('simulatePolicy attaches policy when provided', async () => {
    mockFetchOnce(SIM_RESULT);
    await simulatePolicy('scan-a', 'scan-b', ENVELOPE_CUSTOM.policy);
    const [, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse(String(init?.body));
    expect(body.policy).toEqual(ENVELOPE_CUSTOM.policy);
  });

  it('simulatePolicy returns wouldBlock+counts+violations verbatim', async () => {
    mockFetchOnce(SIM_RESULT);
    const result = await simulatePolicy('scan-a', 'scan-b', null);
    expect(result.wouldBlock).toBe(true);
    expect(result.blockCount).toBe(1);
    expect(result.violations[0].ruleId).toBe('r1');
    expect(result.counts.introduced).toBe(1);
  });
});
