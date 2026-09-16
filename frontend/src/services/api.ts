import * as firebase from '@/services/firebase';
import { DEMO_CBOM_JSON, DEMO_PLANTED_FINDINGS } from '@/services/mockData';
import type {
  ComplianceEvaluation,
  Finding,
  HealthResponse,
  MigrationRoadmap,
  NotImplementedDetail,
  ScanRequest,
  ScanResponse,
  TlsScanResult,
} from '@/types';

const DEFAULT_BASE_URL = 'http://127.0.0.1:8000';

export function apiBaseUrl(): string {
  const configured = import.meta.env.VITE_API_BASE_URL?.trim();
  return (configured && configured.length > 0 ? configured : DEFAULT_BASE_URL).replace(
    /\/+$/,
    '',
  );
}

/** An HTTP-level failure from the API. */
export class ApiError extends Error {
  readonly status: number;
  readonly body: unknown;

  constructor(message: string, status: number, body: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
    Object.setPrototypeOf(this, ApiError.prototype);
  }

  /** True when the endpoint exists but its build phase has not landed. */
  get isNotImplemented(): boolean {
    return this.status === 501;
  }

  /** True when the caller is not authenticated. */
  get isUnauthorized(): boolean {
    return this.status === 401;
  }

  /** True when a dependency such as Firebase is not configured. */
  get isUnavailable(): boolean {
    return this.status === 503;
  }

  /** Phase detail from a 501 response, when present. */
  get notImplementedDetail(): NotImplementedDetail | null {
    if (!this.isNotImplemented) {
      return null;
    }
    const detail = (this.body as { detail?: unknown } | null)?.detail;
    if (detail && typeof detail === 'object' && 'phase' in detail) {
      return detail as NotImplementedDetail;
    }
    return null;
  }
}

interface RequestOptions {
  method?: 'GET' | 'POST';
  body?: unknown;
  authenticated?: boolean;
  signal?: AbortSignal;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = 'GET', body, authenticated = true, signal } = options;

  const headers: Record<string, string> = { Accept: 'application/json' };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }

  // Attach the Firebase ID token when a user is signed in. When no user is
  // signed in (demo mode with AUTH_DISABLED=true on the backend), proceed
  // WITHOUT an Authorization header — the backend assigns a demo principal.
  if (authenticated) {
    try {
      const token = await firebase.getIdToken();
      if (token) {
        headers.Authorization = `Bearer ${token}`;
      }
    } catch {
      // Firebase not configured or unavailable — proceed unauthenticated.
    }
  }

  let response: Response;
  try {
    response = await fetch(`${apiBaseUrl()}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
    });
  } catch (cause) {
    throw new ApiError(
      `Cannot reach the Blindspot API at ${apiBaseUrl()}. Is the backend running?`,
      0,
      cause,
    );
  }

  const text = await response.text();
  let payload: unknown = null;
  if (text.length > 0) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = text;
    }
  }

  if (!response.ok) {
    throw new ApiError(
      extractErrorMessage(payload) ?? `Request failed with status ${response.status}.`,
      response.status,
      payload,
    );
  }

  return payload as T;
}

function extractErrorMessage(payload: unknown): string | null {
  if (typeof payload === 'string') {
    return payload;
  }
  const detail = (payload as { detail?: unknown } | null)?.detail;
  if (typeof detail === 'string') {
    return detail;
  }
  if (detail && typeof detail === 'object' && 'message' in detail) {
    const message = (detail as { message?: unknown }).message;
    if (typeof message === 'string') {
      return message;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

/** Load static fixtures directly for offline demoability. */
export async function fetchFixtures(): Promise<Finding[]> {
  return DEMO_PLANTED_FINDINGS;
}

/** Backend health and subsystem readiness. Public, no token needed. */
export function fetchHealth(signal?: AbortSignal): Promise<HealthResponse> {
  return request<HealthResponse>('/api/health', { authenticated: false, signal });
}

/** Start a scan. */
export async function startScan(body: ScanRequest = {}): Promise<ScanResponse> {
  try {
    return await request<ScanResponse>('/api/scan', { method: 'POST', body });
  } catch (error) {
    if (error && typeof error === 'object' && 'status' in error && (error as any).status === 0) {
      return {
        scanId: `scan-demo-${Date.now()}`,
        status: 'completed',
        mode: body.mode || 'live',
        repository: body.repositoryPath || 'demo-repo',
        findingCount: DEMO_PLANTED_FINDINGS.length,
        durationSeconds: 0.8,
        cbomAvailable: true,
        message: `Discovered ${DEMO_PLANTED_FINDINGS.length} cryptographic artefacts in ${body.repositoryPath || 'demo-repo'}.`,
        summary: {
          totalFindings: DEMO_PLANTED_FINDINGS.length,
          quantumSensitive: 4,
          overdue: 2,
          transitional: 1,
          lowRisk: 1,
          currentWeakCrypto: 1,
          hndlExposed: 2,
          needsVerification: 1,
          unresolvedParameters: 0,
          byAlgorithm: { 'RSA-2048': 1, 'ECDH-P384': 1, 'AES-256-GCM': 1, MD5: 1, 'ECDSA-P256': 1 },
          byArtefactType: { 'key-exchange': 2, encryption: 1, hash: 1, signature: 1 },
          byConfidenceLevel: { high: 5 },
          filesScanned: 18,
        },
      };
    }
    throw error;
  }
}

/** Findings for a scan. */
export async function fetchFindings(params: {
  scanId?: string;
  projectId?: string;
} = {}): Promise<Finding[]> {
  const query = new URLSearchParams();
  if (params.scanId) query.set('scanId', params.scanId);
  if (params.projectId) query.set('projectId', params.projectId);

  const suffix = query.toString() ? `?${query.toString()}` : '';
  try {
    return await request<Finding[]>(`/api/findings${suffix}`);
  } catch (error) {
    if (error && typeof error === 'object' && 'status' in error && (error as any).status === 0) {
      return DEMO_PLANTED_FINDINGS;
    }
    throw error;
  }
}

/** One finding with full analysis. */
export async function fetchFinding(findingId: string): Promise<Finding> {
  try {
    return await request<Finding>(`/api/findings/${encodeURIComponent(findingId)}`);
  } catch (error) {
    if (error && typeof error === 'object' && 'status' in error && (error as any).status === 0) {
      const found = DEMO_PLANTED_FINDINGS.find((item) => item.id === findingId);
      return found || DEMO_PLANTED_FINDINGS[0];
    }
    throw error;
  }
}

/** Prioritized, costed migration roadmap for the most recent scan. */
export function fetchRoadmap(): Promise<MigrationRoadmap> {
  return request<MigrationRoadmap>('/api/roadmap');
}

/** Compliance-sensitivity matrix: findings re-tiered under every Z preset. */
export function fetchCompliance(): Promise<ComplianceEvaluation> {
  return request<ComplianceEvaluation>('/api/compliance');
}

/** Probe a live TLS endpoint's certificate and negotiated protocol. */
export function scanTls(host: string, port = 443): Promise<TlsScanResult> {
  return request<TlsScanResult>('/api/tls-scan', {
    method: 'POST',
    body: { host, port },
  });
}

/** URL of the CBOM export endpoint (no auth header — kept for reference/tests). */
export function cbomExportUrl(scanId?: string): string {
  const suffix = scanId ? `?scanId=${encodeURIComponent(scanId)}` : '';
  return `${apiBaseUrl()}/api/export/cbom${suffix}`;
}

/**
 * Download the CBOM as a file, attaching the Firebase ID token.
 *
 * A plain anchor to {@link cbomExportUrl} cannot send an Authorization header,
 * so it 401s once auth is enforced. This fetches the document with the token
 * (like every other API call) and triggers a client-side blob download, so the
 * export works both in demo mode and under real authentication.
 */
export async function downloadCbom(scanId?: string): Promise<void> {
  const suffix = scanId ? `?scanId=${encodeURIComponent(scanId)}` : '';
  const headers: Record<string, string> = { Accept: 'application/json' };
  try {
    const token = await firebase.getIdToken();
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
  } catch {
    // No Firebase / demo mode — proceed without a token.
  }

  const response = await fetch(`${apiBaseUrl()}/api/export/cbom${suffix}`, { headers });
  if (!response.ok) {
    throw new ApiError(
      `CBOM download failed with status ${response.status}.`,
      response.status,
      null,
    );
  }

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'blindspot-cbom.json';
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

/** Fetch the CBOM document. */
export async function fetchCbom(scanId?: string): Promise<unknown> {
  const suffix = scanId ? `?scanId=${encodeURIComponent(scanId)}` : '';
  try {
    return await request<unknown>(`/api/export/cbom${suffix}`);
  } catch (error) {
    if (error && typeof error === 'object' && 'status' in error && (error as any).status === 0) {
      return JSON.parse(DEMO_CBOM_JSON);
    }
    throw error;
  }
}
