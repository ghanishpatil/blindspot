/**
 * Client for the benchmark endpoints (`/api/benchmark*`).
 *
 * Backend endpoints (see `backend/app/api/benchmark.py`):
 *
 *   POST /api/benchmark/run     -> BenchmarkReport (runs + caches)
 *   GET  /api/benchmark/latest  -> BenchmarkReport (404 if none)
 *
 * Types mirror the backend :class:`BenchmarkReport` shape.
 */

import { apiBaseUrl } from '@/services/api';
import * as firebase from '@/services/firebase';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface BenchmarkConfusion {
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  precision: number;
  recall: number;
  f1: number;
  accuracy: number;
}

export interface BenchmarkCategory extends BenchmarkConfusion {
  cases: number;
}

export interface BenchmarkCaseRow {
  caseId: string;
  file: string;
  category: string;
  language: string;
  expectedCount: number;
  reportedCount: number;
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  matched: Array<{
    expected: { algorithm: string; parameter: string | null; curve: string | null };
    finding: Record<string, unknown>;
  }>;
  missed: Array<{
    algorithm: string;
    parameter: string | null;
    curve: string | null;
    notes: string | null;
  }>;
  extra: Array<Record<string, unknown>>;
}

export interface BenchmarkReport {
  schemaVersion: string;
  datasetName: string;
  datasetDescription: string;
  generatedAt: string;
  pipelineVersion: string;
  elapsedSeconds: number;
  totalCases: number;
  totalExpected: number;
  totalReported: number;
  overall: BenchmarkConfusion;
  categories: Record<string, BenchmarkCategory>;
  cases: BenchmarkCaseRow[];
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

async function authorisedFetch(
  path: string,
  init?: RequestInit,
): Promise<Response> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  try {
    const token = await firebase.getIdToken();
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
  } catch {
    // AUTH_DISABLED / demo mode -- proceed without a token.
  }
  return fetch(`${apiBaseUrl()}${path}`, { ...init, headers });
}

async function unwrap<T>(response: Response): Promise<T> {
  const text = await response.text();
  const body = text.length > 0 ? JSON.parse(text) : null;
  if (!response.ok) {
    const detail =
      body && typeof body === 'object' && 'detail' in body
        ? String((body as { detail: unknown }).detail)
        : `Request failed with status ${response.status}.`;
    const err = new Error(detail);
    (err as Error & { status: number }).status = response.status;
    throw err;
  }
  return body as T;
}

/** POST /api/benchmark/run -- runs the harness and returns a fresh report. */
export async function runBenchmark(signal?: AbortSignal): Promise<BenchmarkReport> {
  const response = await authorisedFetch('/api/benchmark/run', {
    method: 'POST',
    signal,
  });
  return unwrap<BenchmarkReport>(response);
}

/** GET /api/benchmark/latest -- last cached run, or null on 404. */
export async function getLatestBenchmark(
  signal?: AbortSignal,
): Promise<BenchmarkReport | null> {
  try {
    const response = await authorisedFetch('/api/benchmark/latest', {
      method: 'GET',
      signal,
    });
    return await unwrap<BenchmarkReport>(response);
  } catch (err) {
    if (err instanceof Error && (err as Error & { status?: number }).status === 404) {
      return null;
    }
    throw err;
  }
}
