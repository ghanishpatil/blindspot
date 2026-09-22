/**
 * Client for the cross-scan aggregation endpoints (`/api/scans*`).
 *
 * Backend endpoints (see `backend/app/api/scans.py`):
 *
 *   GET  /api/scans                       -> ScanListResponse
 *   GET  /api/scans/{scanId}              -> ScanRecordResponse
 *   GET  /api/scans/trend?project_id=...  -> ScanTrendResponse
 *
 * These read directly off the on-disk artefact mirror. They work
 * identically in air-gap mode and in Firebase mode -- the mirror is
 * always written, and never dependent on Firebase.
 *
 * All types below mirror the backend response shape verbatim so a change
 * on either side surfaces as a TypeScript error rather than a runtime
 * KeyError.
 */

import type { Finding, ScanStatus, ScanMode } from '@/types';

// ---------------------------------------------------------------------------
// Shapes
// ---------------------------------------------------------------------------

/** One row in the /api/scans listing. Small on purpose so the page
 *  can render a hundred rows without loading every finding. */
export interface ScanSummaryRow {
  scanId: string | null;
  projectId: string | null;
  ownerId: string | null;
  status: ScanStatus | string | null;
  mode: ScanMode | string | null;
  repository: string | null;
  startedAt: string | null;
  completedAt: string | null;
  findingCount: number;
  summary: {
    totalFindings: number;
    overdue: number;
    transitional: number;
    lowRisk: number;
    hndlExposed: number;
    currentWeakCrypto: number;
  };
}

export interface ScanListResponse {
  count: number;
  scans: ScanSummaryRow[];
}

/** Full record for one scan -- returned by /api/scans/{scanId}. */
export interface ScanRecordResponse {
  scan: Record<string, unknown>;
  findings: Finding[];
  cbom: string | null;
}

/** One point on the trend chart. Every scan of the project is one point. */
export interface ScanTrendPoint {
  scanId: string | null;
  startedAt: string | null;
  totalFindings: number;
  overdue: number;
  transitional: number;
  lowRisk: number;
  hndlExposed: number;
  currentWeakCrypto: number;
}

export interface ScanTrendResponse {
  projectId: string;
  count: number;
  points: ScanTrendPoint[];
}

// ---------------------------------------------------------------------------
// Fetchers
// ---------------------------------------------------------------------------
//
// The functions below intentionally do NOT swallow errors. The caller
// decides whether an error means "show a placeholder" or "surface a
// banner" -- this module is the plain transport layer.

import { apiBaseUrl } from '@/services/api';
import * as firebase from '@/services/firebase';

async function authorisedFetch(path: string, signal?: AbortSignal): Promise<Response> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  try {
    const token = await firebase.getIdToken();
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
  } catch {
    // Demo / AUTH_DISABLED mode -- proceed without a token.
  }
  return fetch(`${apiBaseUrl()}${path}`, { headers, signal });
}

async function unwrap<T>(response: Response): Promise<T> {
  const text = await response.text();
  const body = text.length > 0 ? JSON.parse(text) : null;
  if (!response.ok) {
    const detail =
      body && typeof body === 'object' && 'detail' in body
        ? String((body as { detail: unknown }).detail)
        : `Request failed with status ${response.status}.`;
    throw new Error(detail);
  }
  return body as T;
}

/** List every scan the local mirror knows about, newest first. */
export async function listScans(
  options: { projectId?: string; signal?: AbortSignal } = {},
): Promise<ScanListResponse> {
  const params = new URLSearchParams();
  if (options.projectId) {
    params.set('project_id', options.projectId);
  }
  const suffix = params.toString() ? `?${params.toString()}` : '';
  const response = await authorisedFetch(`/api/scans${suffix}`, options.signal);
  return unwrap<ScanListResponse>(response);
}

/** Full record for one scan (scan + findings + cbom text). */
export async function getScan(
  scanId: string,
  signal?: AbortSignal,
): Promise<ScanRecordResponse> {
  const response = await authorisedFetch(
    `/api/scans/${encodeURIComponent(scanId)}`,
    signal,
  );
  return unwrap<ScanRecordResponse>(response);
}

/** Time-ordered per-Risk_Tier snapshot series for one project. */
export async function getScanTrend(
  projectId: string,
  signal?: AbortSignal,
): Promise<ScanTrendResponse> {
  const params = new URLSearchParams({ project_id: projectId });
  const response = await authorisedFetch(
    `/api/scans/trend?${params.toString()}`,
    signal,
  );
  return unwrap<ScanTrendResponse>(response);
}


// ---------------------------------------------------------------------------
// Diff -- compare two scans (S2)
// ---------------------------------------------------------------------------

/** One row in the ``added`` / ``removed`` / ``changed`` list. Mirrors the
 *  compact projection the backend's ``_row`` / ``_changed_row`` build. */
export interface DiffRow {
  id: string | null;
  algorithm: string | null;
  displayName: string | null;
  parameter: string | null;
  curve: string | null;
  filePath: string | null;
  lineNumber: number | null;
  riskTier: string | null;
  isHndlExposed: boolean;
  isCurrentlyWeak: boolean;
  detectionMethod: string | null;
  /** Present only on rows in the ``changed`` list. */
  previousTier?: string | null;
  currentTier?: string | null;
  previousLineNumber?: number | null;
}

/** Compact scan header attached to both sides of the diff. */
export interface DiffScanHeader {
  scanId: string | null;
  projectId: string | null;
  startedAt: string | null;
  completedAt: string | null;
  findingCount: number;
  summary: Record<string, number>;
}

/** Full response for ``GET /api/scans/diff``. */
export interface ScanDiffResponse {
  base: DiffScanHeader;
  head: DiffScanHeader;
  /** Signed ``head - base`` deltas: negative overdue = migration progress. */
  summaryDelta: Record<string, number>;
  added: DiffRow[];
  removed: DiffRow[];
  changed: DiffRow[];
  unchangedCount: number;
  addedCount: number;
  removedCount: number;
  changedCount: number;
}

/** Compare two scans by id. ``base`` is the older / reference scan. */
export async function getScanDiff(
  baseScanId: string,
  headScanId: string,
  signal?: AbortSignal,
): Promise<ScanDiffResponse> {
  const params = new URLSearchParams({ base: baseScanId, head: headScanId });
  const response = await authorisedFetch(
    `/api/scans/diff?${params.toString()}`,
    signal,
  );
  return unwrap<ScanDiffResponse>(response);
}
