/**
 * Client-side scan history.
 *
 * The backend keeps only the single most-recent scan in memory (see
 * `app/api/scan.py` — `_last_scan` globals), so there is no server endpoint for
 * past scans. To let the Scanner page show a list of recent runs, each completed
 * scan is snapshotted into `localStorage` from the browser that ran it.
 *
 * A snapshot captures everything needed to review a run without re-scanning:
 * the exact input (target, type, mode), the scan response (summary, counts,
 * duration), the findings, and the generated CBOM document.
 */

import type { Finding, ScanResponse } from '@/types';

const STORAGE_KEY = 'blindspot.scanHistory.v1';
const MAX_ENTRIES = 15;

export type ScanTargetType = 'repo' | 'image';

export interface ScanHistoryEntry {
  /** Local unique id for the history row (not the backend scanId). */
  localId: string;
  /** ISO timestamp when the scan completed, in this browser. */
  timestamp: string;

  // --- Input given by the user ------------------------------------------
  targetType: ScanTargetType;
  /** Raw target string the user typed (URL, path, image ref, or blank). */
  targetInput: string;
  /** How the target was interpreted when sent to the backend. */
  targetKind: 'git-url' | 'local-path' | 'image-ref' | 'demo-repo';
  mode: 'live' | 'cached';

  // --- Result ------------------------------------------------------------
  response: ScanResponse;
  findings: Finding[];
  /** CBOM document as returned by the API (may be null if fetch failed). */
  cbom: unknown | null;
}

function safeParse(raw: string | null): ScanHistoryEntry[] {
  if (!raw) {
    return [];
  }
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as ScanHistoryEntry[]) : [];
  } catch {
    return [];
  }
}

/** All stored scans, newest first. Safe on SSR / storage-disabled contexts. */
export function getScanHistory(): ScanHistoryEntry[] {
  if (typeof window === 'undefined' || !window.localStorage) {
    return [];
  }
  return safeParse(window.localStorage.getItem(STORAGE_KEY));
}

/**
 * Prepend a scan snapshot to the history, capping the total kept.
 * Returns the updated list so callers can update state without re-reading.
 */
export function addScanToHistory(
  entry: Omit<ScanHistoryEntry, 'localId' | 'timestamp'>,
): ScanHistoryEntry[] {
  if (typeof window === 'undefined' || !window.localStorage) {
    return [];
  }

  const full: ScanHistoryEntry = {
    ...entry,
    localId: `hist-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: new Date().toISOString(),
  };

  const next = [full, ...getScanHistory()].slice(0, MAX_ENTRIES);

  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
  } catch {
    // Storage full (large CBOM/findings). Retry without the CBOM payloads,
    // which are the biggest part, so the run is still listed.
    const trimmed = next.map((e) => ({ ...e, cbom: null }));
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(trimmed));
      return trimmed;
    } catch {
      return getScanHistory();
    }
  }

  return next;
}

/** Remove a single scan from history. Returns the updated list. */
export function removeScanFromHistory(localId: string): ScanHistoryEntry[] {
  if (typeof window === 'undefined' || !window.localStorage) {
    return [];
  }
  const next = getScanHistory().filter((e) => e.localId !== localId);
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
  return next;
}

/** Clear all stored scans. */
export function clearScanHistory(): ScanHistoryEntry[] {
  if (typeof window !== 'undefined' && window.localStorage) {
    window.localStorage.removeItem(STORAGE_KEY);
  }
  return [];
}

/** A short human label for the scanned target. */
export function describeTarget(entry: ScanHistoryEntry): string {
  switch (entry.targetKind) {
    case 'demo-repo':
      return 'Seeded demo repository';
    case 'git-url':
    case 'image-ref':
    case 'local-path':
      return entry.targetInput;
    default:
      return entry.targetInput || 'Unknown target';
  }
}
