/**
 * Client for the policy-as-code endpoints (`/api/policy*`).
 *
 * Backend endpoints (see `backend/app/api/policy.py`):
 *
 *   GET  /api/policy            -> PolicyEnvelope (active policy)
 *   GET  /api/policy/default    -> PolicyEnvelope (built-in default)
 *   PUT  /api/policy            -> PolicyEnvelope (validates + persists)
 *   POST /api/policy/reset      -> PolicyEnvelope (revert to default)
 *   POST /api/policy/simulate   -> SimulationResponse (delta + violations)
 *
 * The response shapes below mirror the backend Pydantic models exactly.
 * A drift on either side surfaces as a TypeScript compile error rather
 * than a runtime `undefined`.
 */

import { apiBaseUrl } from '@/services/api';
import * as firebase from '@/services/firebase';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** One rule inside a policy document. All fields required by the
 *  backend validator (`app.cli.policy._parse_policy`). */
export interface PolicyRule {
  id: string;
  /** One of `introduced` | `resolved` | `changed` | `all`. */
  on: string;
  /** Dotted-key equality matcher against a finding / change doc. */
  match: Record<string, unknown>;
  /** `block` (fails CI) or `warn` (informational). */
  action: string;
}

/** Full policy document. Round-trips through PUT /api/policy. */
export interface PolicyDocument {
  schemaVersion?: string;
  name: string;
  rules: PolicyRule[];
}

/** Envelope returned by every read/write policy endpoint. */
export interface PolicyEnvelope {
  schemaVersion: string;
  /** True when the response is the built-in default (no override saved). */
  isDefault: boolean;
  policy: PolicyDocument;
}

/** One violation surfaced by the simulate endpoint. */
export interface PolicyViolation {
  ruleId: string;
  findingId: string | null;
  reason: string;
  field: string | null;
  value: unknown;
  /** `block` contributes to `wouldBlock`; `warn` does not. */
  action: string;
}

/** Response body for POST /api/policy/simulate. */
export interface PolicySimulationResponse {
  policyName: string;
  counts: {
    introduced: number;
    resolved: number;
    changed: number;
    unchanged: number;
  };
  violations: PolicyViolation[];
  blockCount: number;
  warnCount: number;
  /** Convenience: true iff the policy would exit 2 in CI. */
  wouldBlock: boolean;
}

// ---------------------------------------------------------------------------
// Transport (same idiom as scansApi -- reused for consistency, not shared
// to keep this module self-contained)
// ---------------------------------------------------------------------------

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
    throw new Error(detail);
  }
  return body as T;
}

// ---------------------------------------------------------------------------
// Fetchers
// ---------------------------------------------------------------------------

/** Get the currently active policy. Falls back to default when no override. */
export async function getActivePolicy(
  signal?: AbortSignal,
): Promise<PolicyEnvelope> {
  const response = await authorisedFetch('/api/policy', { signal });
  return unwrap<PolicyEnvelope>(response);
}

/** Get the built-in default policy. Read-only, used for restore preview. */
export async function getDefaultPolicy(
  signal?: AbortSignal,
): Promise<PolicyEnvelope> {
  const response = await authorisedFetch('/api/policy/default', { signal });
  return unwrap<PolicyEnvelope>(response);
}

/** Validate and persist a policy document. Throws on schema failure (400). */
export async function saveActivePolicy(
  policy: PolicyDocument,
  signal?: AbortSignal,
): Promise<PolicyEnvelope> {
  const response = await authorisedFetch('/api/policy', {
    method: 'PUT',
    body: JSON.stringify(policy),
    signal,
  });
  return unwrap<PolicyEnvelope>(response);
}

/** Delete the override. Idempotent -- calling on a fresh install is fine. */
export async function resetActivePolicy(
  signal?: AbortSignal,
): Promise<PolicyEnvelope> {
  const response = await authorisedFetch('/api/policy/reset', {
    method: 'POST',
    body: JSON.stringify({}),
    signal,
  });
  return unwrap<PolicyEnvelope>(response);
}

/** Evaluate a policy against a delta between two scans, without persisting.
 *  Omit `policy` to simulate the currently active one. */
export async function simulatePolicy(
  base: string,
  head: string,
  policy: PolicyDocument | null,
  signal?: AbortSignal,
): Promise<PolicySimulationResponse> {
  const body: Record<string, unknown> = { base, head };
  if (policy !== null) {
    body.policy = policy;
  }
  const response = await authorisedFetch('/api/policy/simulate', {
    method: 'POST',
    body: JSON.stringify(body),
    signal,
  });
  return unwrap<PolicySimulationResponse>(response);
}
