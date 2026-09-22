/**
 * Client for the blast-radius graph endpoint (`GET /api/graph/{scanId}`).
 *
 * Response mirrors :class:`app.graph.builder.GraphResult`.
 */

import { apiBaseUrl } from '@/services/api';
import * as firebase from '@/services/firebase';

export type GraphNodeKind = 'file' | 'algorithm';

export interface GraphNode {
  id: string;
  kind: GraphNodeKind;
  label: string;
  tier: string | null;
  findingCount: number;
  blastRadius: number;
  algorithm: string | null;
  parameter: string | null;
  curve: string | null;
}

export interface GraphEdge {
  source: string;
  target: string;
  findingId: string | null;
  tier: string | null;
}

export interface GraphResponse {
  schemaVersion: string;
  scanId: string;
  projectId: string | null;
  generatedAt: string | null;
  nodes: GraphNode[];
  edges: GraphEdge[];
  counts: {
    files: number;
    algorithms: number;
    edges: number;
    filesByTier: Record<string, number>;
    algorithmsByTier: Record<string, number>;
  };
}

async function authorisedFetch(
  path: string,
  signal?: AbortSignal,
): Promise<Response> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  try {
    const token = await firebase.getIdToken();
    if (token) headers.Authorization = `Bearer ${token}`;
  } catch {
    // AUTH_DISABLED / demo mode.
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

/** GET /api/graph/{scanId} -- bipartite blast-radius graph. */
export async function getGraph(
  scanId: string,
  signal?: AbortSignal,
): Promise<GraphResponse> {
  const response = await authorisedFetch(
    `/api/graph/${encodeURIComponent(scanId)}`,
    signal,
  );
  return unwrap<GraphResponse>(response);
}
