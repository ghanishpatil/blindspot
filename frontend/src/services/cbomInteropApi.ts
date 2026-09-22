/**
 * Client for the CBOM interop-diff endpoint (`POST /api/cbom/diff`).
 *
 * Accepts two CycloneDX 1.6 CBOM JSON objects, returns their
 * crypto-asset-level diff. Types mirror
 * :class:`app.cbom.interop_diff.InteropDiffResult`.
 */

import { apiBaseUrl } from '@/services/api';
import * as firebase from '@/services/firebase';

export interface CbomAsset {
  bomRef: string | null;
  name: string;
  primitive: string | null;
  parameterSetIdentifier: string | null;
  curve: string | null;
  mode: string | null;
  tier: string | null;
}

export interface CbomChangedAsset {
  name: string;
  base: CbomAsset;
  head: CbomAsset;
  changes: Record<string, { from: unknown; to: unknown }>;
  changeClasses: string[];
}

export interface CbomInteropMeta {
  specVersion: string | null;
  timestamp: string | null;
  componentCount: number;
  cryptoAssetCount: number;
  tools: string[];
}

export interface CbomInteropDiffResponse {
  schemaVersion: string;
  base: CbomInteropMeta;
  head: CbomInteropMeta;
  counts: {
    added: number;
    removed: number;
    changed: number;
    unchanged: number;
  };
  added: CbomAsset[];
  removed: CbomAsset[];
  changed: CbomChangedAsset[];
}

async function authorisedFetch(
  path: string,
  init?: RequestInit,
): Promise<Response> {
  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
  };
  try {
    const token = await firebase.getIdToken();
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
  } catch {
    // AUTH_DISABLED / demo mode.
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
    throw new Error(detail);
  }
  return body as T;
}

/** POST /api/cbom/diff -- pure comparator over two supplied CBOMs. */
export async function diffCboms(
  base: Record<string, unknown>,
  head: Record<string, unknown>,
  signal?: AbortSignal,
): Promise<CbomInteropDiffResponse> {
  const response = await authorisedFetch('/api/cbom/diff', {
    method: 'POST',
    body: JSON.stringify({ base, head }),
    signal,
  });
  return unwrap<CbomInteropDiffResponse>(response);
}
