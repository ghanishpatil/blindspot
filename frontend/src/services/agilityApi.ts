/**
 * Client for the crypto-agility score endpoint (`GET /api/agility/{scanId}`).
 *
 * Response mirrors :class:`app.agility.score.AgilityScore` -- score is
 * a float in [0, 100], grade is one of A/B/C/D/F, breakdown is the
 * three-band composite that adds up to `score`.
 */

import { apiBaseUrl } from '@/services/api';
import * as firebase from '@/services/firebase';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AgilityGrade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface AgilityBand {
  earned: number;
  max: number;
}

export interface AgilityBreakdown {
  tierPosture: AgilityBand;
  weaknessImmunity: AgilityBand;
  hndlImmunity: AgilityBand;
}

export interface AgilityInputs {
  totalFindings: number;
  overdue: number;
  transitional: number;
  lowRisk: number;
  currentWeakCrypto: number;
  hndlExposed: number;
}

export interface AgilityScoreResponse {
  schemaVersion: string;
  scanId: string;
  projectId: string | null;
  generatedAt: string | null;
  score: number;
  grade: AgilityGrade;
  breakdown: AgilityBreakdown;
  inputs: AgilityInputs;
  rationale: string[];
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

async function authorisedFetch(
  path: string,
  signal?: AbortSignal,
): Promise<Response> {
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
    const err = new Error(detail);
    (err as Error & { status: number }).status = response.status;
    throw err;
  }
  return body as T;
}

// ---------------------------------------------------------------------------
// Fetcher
// ---------------------------------------------------------------------------

/** GET /api/agility/{scanId} -- crypto-agility score for one scan. */
export async function getAgilityScore(
  scanId: string,
  signal?: AbortSignal,
): Promise<AgilityScoreResponse> {
  const response = await authorisedFetch(
    `/api/agility/${encodeURIComponent(scanId)}`,
    signal,
  );
  return unwrap<AgilityScoreResponse>(response);
}
