/**
 * cbomInteropApi contract: URL, verb, body shape, error path.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { diffCboms, type CbomInteropDiffResponse } from '@/services/cbomInteropApi';

function mockFetchOnce(body: unknown, ok = true, status = 200): void {
  const fetchMock = vi.fn().mockResolvedValue({
    ok,
    status,
    text: async () => JSON.stringify(body),
  });
  vi.stubGlobal('fetch', fetchMock);
}

const RESULT: CbomInteropDiffResponse = {
  schemaVersion: 'blindspot.cbom.interop.v1',
  base: {
    specVersion: '1.6',
    timestamp: null,
    componentCount: 1,
    cryptoAssetCount: 1,
    tools: ['Blindspot'],
  },
  head: {
    specVersion: '1.6',
    timestamp: null,
    componentCount: 1,
    cryptoAssetCount: 1,
    tools: ['IBM CBOMkit'],
  },
  counts: { added: 0, removed: 0, changed: 1, unchanged: 0 },
  added: [],
  removed: [],
  changed: [
    {
      name: 'RSA-2048',
      base: {
        bomRef: null,
        name: 'RSA-2048',
        primitive: 'pke',
        parameterSetIdentifier: '2048',
        curve: null,
        mode: null,
        tier: null,
      },
      head: {
        bomRef: null,
        name: 'RSA-2048',
        primitive: 'pke',
        parameterSetIdentifier: '3072',
        curve: null,
        mode: null,
        tier: null,
      },
      changes: { parameter_set_identifier: { from: '2048', to: '3072' } },
      changeClasses: ['parameter_changed'],
    },
  ],
};

describe('diffCboms', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('POSTs to /api/cbom/diff with a base+head body', async () => {
    mockFetchOnce(RESULT);
    await diffCboms({ a: 1 }, { b: 2 });
    const [url, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(String(url)).toContain('/api/cbom/diff');
    expect(init?.method).toBe('POST');
    expect(JSON.parse(String(init?.body))).toEqual({
      base: { a: 1 },
      head: { b: 2 },
    });
  });

  it('unwraps the diff result', async () => {
    mockFetchOnce(RESULT);
    const result = await diffCboms({}, {});
    expect(result.counts.changed).toBe(1);
    expect(result.changed[0].changeClasses).toContain('parameter_changed');
  });

  it('surfaces 400 detail as an Error', async () => {
    mockFetchOnce({ detail: '`base` must be a non-empty CycloneDX BOM object.' }, false, 400);
    await expect(diffCboms({}, {})).rejects.toThrow(/non-empty/i);
  });
});
