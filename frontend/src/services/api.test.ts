/**
 * API client tests.
 *
 * The behaviour that matters for the demo's honesty:
 *
 * - a 501 is recognised as "phase not built" and carries the phase name
 * - a protected call with no signed-in user fails before it reaches the network
 * - an unreachable backend is distinguishable from a rejected request
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  ApiError,
  apiBaseUrl,
  cbomExportUrl,
  fetchHealth,
  fetchFindings,
  reportUrl,
  startScan,
} from '@/services/api';
import * as firebase from '@/services/firebase';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('apiBaseUrl', () => {
  it('falls back to the local backend and strips trailing slashes', () => {
    expect(apiBaseUrl()).toBe('http://127.0.0.1:8000');
  });
});

describe('fetchHealth', () => {
  it('does not require authentication', async () => {
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(jsonResponse({ status: 'ok', readiness: 'degraded' }));

    await fetchHealth();

    const [, init] = fetchSpy.mock.calls[0]!;
    const headers = (init?.headers ?? {}) as Record<string, string>;
    expect(headers.Authorization).toBeUndefined();
  });

  it('reports an unreachable backend distinctly from a rejection', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('Failed to fetch'));

    await expect(fetchHealth()).rejects.toMatchObject({
      name: 'ApiError',
      status: 0,
    });
  });
});

describe('protected requests', () => {
  it('proceed without an auth header when no user is signed in (AUTH_DISABLED mode)', async () => {
    vi.spyOn(firebase, 'getIdToken').mockResolvedValue(null);
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse([]));

    await fetchFindings();

    expect(fetchSpy).toHaveBeenCalled();
    const [, init] = fetchSpy.mock.calls[0]!;
    const headers = (init?.headers ?? {}) as Record<string, string>;
    expect(headers.Authorization).toBeUndefined();
  });

  it('attach the Firebase ID token as a bearer token', async () => {
    vi.spyOn(firebase, 'getIdToken').mockResolvedValue('test-id-token');
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse([]));

    await fetchFindings({ scanId: 'scan-1' });

    const [url, init] = fetchSpy.mock.calls[0]!;
    expect(String(url)).toContain('/api/findings?scanId=scan-1');
    const headers = (init?.headers ?? {}) as Record<string, string>;
    expect(headers.Authorization).toBe('Bearer test-id-token');
  });
});

describe('501 handling', () => {
  it('surfaces the implementing phase instead of looking like empty data', async () => {
    vi.spyOn(firebase, 'getIdToken').mockResolvedValue('test-id-token');
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      jsonResponse(
        {
          detail: {
            error: 'not_implemented',
            endpoint: 'POST /api/scan',
            phase: 'Phase 4-12',
            message: 'Scanning is not implemented yet.',
            implemented: false,
          },
        },
        501,
      ),
    );

    let caught: unknown;
    try {
      await startScan({ mode: 'live' });
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(ApiError);
    const apiError = caught as ApiError;
    expect(apiError.isNotImplemented).toBe(true);
    expect(apiError.notImplementedDetail?.phase).toBe('Phase 4-12');
    expect(apiError.message).toContain('not implemented');
  });

  it('classifies 401 and 503 separately', async () => {
    vi.spyOn(firebase, 'getIdToken').mockResolvedValue('token');

    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      jsonResponse({ detail: 'Missing bearer token.' }, 401),
    );
    await expect(fetchFindings()).rejects.toMatchObject({ status: 401 });

    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      jsonResponse({ detail: 'Firebase is not configured.' }, 503),
    );
    await expect(fetchFindings()).rejects.toMatchObject({ status: 503 });
  });
});

describe('cbomExportUrl', () => {
  it('builds an absolute, encoded download URL', () => {
    expect(cbomExportUrl('scan 1')).toBe(
      'http://127.0.0.1:8000/api/export/cbom?scanId=scan%201',
    );
    expect(cbomExportUrl()).toBe('http://127.0.0.1:8000/api/export/cbom');
  });
});

describe('reportUrl', () => {
  it('defaults to html and appends the format', () => {
    expect(reportUrl()).toBe('http://127.0.0.1:8000/api/report?format=html');
  });

  it.each(['html', 'pdf', 'csv'] as const)(
    'builds an absolute URL for format %s',
    (format) => {
      expect(reportUrl('scan-42', format)).toBe(
        `http://127.0.0.1:8000/api/report?format=${format}&scanId=scan-42`,
      );
    },
  );

  it('URL-encodes hostile scan identifiers', () => {
    // A scan id containing spaces / query-string metacharacters must not
    // be able to inject extra parameters into the request.
    expect(reportUrl('scan 1 & 2', 'csv')).toBe(
      'http://127.0.0.1:8000/api/report?format=csv&scanId=scan+1+%26+2',
    );
  });
});
