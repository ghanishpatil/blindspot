/**
 * CBOM parsing and aggregation model.
 *
 * Replicates the data logic of the IBM / PQCA `cbomkit` viewer
 * (frontend/src/helpers/cbom.js and info.js) so the Blindspot visualizer
 * derives its detections, tables, and charts exactly the way the reference
 * CycloneDX CBOM viewer does:
 *
 *  - `resolvePath`            — nested lookup that always returns an array
 *  - `getDetectionsFromCbom`  — "unwraps" each component's evidence occurrences
 *                               into one detection row per occurrence
 *  - `countOccurrences`       — value distribution for an algorithmProperties field
 *  - `countNames`             — distinct-asset distribution by component name
 *
 * The visualizer reads only the CBOM document — no invented risk/compliance
 * data — so what it shows always matches the exported artefact.
 */

// A crypto asset component or an unwrapped single-occurrence detection.
export type CryptoAsset = Record<string, unknown>;

/**
 * Resolve a dotted path against an object, always returning an array of values
 * (or `undefined` when nothing matches). Arrays encountered along the path are
 * traversed element-by-element and the results flattened, matching cbomkit's
 * `resolvePath`.
 */
export function resolvePath(obj: unknown, path: string): unknown[] | undefined {
  const parts = path.split('.');

  function traverse(current: unknown, remaining: string[]): unknown[] | undefined {
    if (remaining.length === 0) {
      if (current === undefined) {
        return undefined;
      }
      return Array.isArray(current) ? current : [current];
    }

    const [key, ...rest] = remaining;

    if (Array.isArray(current)) {
      return current
        .map((item) => traverse(item, remaining))
        .filter((item): item is unknown[] => item !== undefined)
        .flat();
    }

    if (
      typeof current === 'object' &&
      current !== null &&
      Object.prototype.hasOwnProperty.call(current, key)
    ) {
      return traverse((current as Record<string, unknown>)[key], rest);
    }

    return undefined;
  }

  return traverse(obj, parts);
}

/** First resolved value for a path, or `undefined`. */
export function resolveFirst(obj: unknown, path: string): unknown {
  const values = resolvePath(obj, path);
  if (values && values.length > 0) {
    return values[0];
  }
  return undefined;
}

function isCbom(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/**
 * Extract crypto-asset detections from a CBOM. Each component with N evidence
 * occurrences becomes N detection rows (one occurrence each); a component with
 * no occurrences appears once. Non-crypto components are ignored. Mirrors
 * cbomkit's `getDetectionsFromCbom` + `removeBomRefFromDetectionNames`.
 */
export function getDetectionsFromCbom(cbom: unknown): CryptoAsset[] {
  if (!isCbom(cbom)) {
    return [];
  }
  const components = cbom.components;
  if (!Array.isArray(components)) {
    return [];
  }

  const detections: CryptoAsset[] = [];

  for (const component of components) {
    if (!isCbom(component) || component.type !== 'cryptographic-asset') {
      continue;
    }

    const evidence = component.evidence as Record<string, unknown> | undefined;
    const occurrences = evidence?.occurrences;

    if (Array.isArray(occurrences) && occurrences.length > 0) {
      for (const occurrence of occurrences) {
        const clone = structuredCloneSafe(component) as CryptoAsset;
        (clone.evidence as Record<string, unknown>).occurrences = [occurrence];
        detections.push(clone);
      }
    } else {
      detections.push(structuredCloneSafe(component) as CryptoAsset);
    }
  }

  // Some names carry their bom-ref as "name@ref"; strip it for display.
  for (const detection of detections) {
    if (typeof detection.name === 'string' && detection.name.includes('@')) {
      detection.name = detection.name.split('@')[0];
    }
  }

  return detections;
}

function structuredCloneSafe<T>(value: T): T {
  if (typeof structuredClone === 'function') {
    return structuredClone(value);
  }
  return JSON.parse(JSON.stringify(value)) as T;
}

// ── Field accessors (same paths as cbomkit's DataTable) ──────────────────

/** CycloneDX `cryptoProperties.assetType`, e.g. "algorithm". */
export function assetType(asset: CryptoAsset): string {
  const value = resolveFirst(asset, 'cryptoProperties.assetType');
  return value != null ? String(value) : '';
}

/**
 * Primitive of a crypto asset. The standard location is
 * `cryptoProperties.algorithmProperties.primitive`; we fall back to
 * `cryptoProperties.primitive` to tolerate simplified CBOMs.
 */
export function primitive(asset: CryptoAsset): string {
  const standard = resolveFirst(asset, 'cryptoProperties.algorithmProperties.primitive');
  if (standard != null) {
    return String(standard);
  }
  const fallback = resolveFirst(asset, 'cryptoProperties.primitive');
  return fallback != null ? String(fallback) : '';
}

/** First evidence occurrence `{ location, line, ... }`, or null. */
export function firstOccurrence(asset: CryptoAsset): Record<string, unknown> | null {
  const values = resolvePath(asset, 'evidence.occurrences');
  if (Array.isArray(values) && values.length > 0 && typeof values[0] === 'object') {
    return values[0] as Record<string, unknown>;
  }
  return null;
}

/** File name (basename) of an occurrence's location. */
export function occurrenceFileName(occurrence: Record<string, unknown> | null): string {
  if (!occurrence) {
    return '';
  }
  const location = occurrence.location;
  if (typeof location !== 'string') {
    return '';
  }
  const normalized = location.replace(/\\/g, '/');
  return normalized.substring(normalized.lastIndexOf('/') + 1);
}

/** Full path of an occurrence's location. */
export function occurrenceLocation(occurrence: Record<string, unknown> | null): string {
  if (!occurrence || typeof occurrence.location !== 'string') {
    return '';
  }
  return occurrence.location;
}

/** Line number of an occurrence, or null. */
export function occurrenceLine(occurrence: Record<string, unknown> | null): number | null {
  if (!occurrence) {
    return null;
  }
  const line = occurrence.line;
  return typeof line === 'number' ? line : null;
}

/** Asset display name. */
export function assetName(asset: CryptoAsset): string {
  return typeof asset.name === 'string' ? asset.name : '';
}

// ── Aggregations for the statistics charts ───────────────────────────────

export interface CountEntry {
  /** Raw term value, e.g. "pke". */
  key: string;
  /** Display label resolved via the crypto dictionary. */
  label: string;
  /** Number of detections carrying this value. */
  value: number;
}

/** Result of an aggregation: entries plus the count of distinct values. */
export interface Distribution {
  entries: CountEntry[];
  distinct: number;
}

/**
 * Count occurrences of an `algorithmProperties` field across detections.
 * The field may be a string or an array of strings (e.g. `cryptoFunctions`).
 * Mirrors cbomkit's `countOccurrences`.
 */
export function countOccurrences(
  detections: CryptoAsset[],
  field: string,
  labelFor: (key: string) => string,
): Distribution {
  const counts: Record<string, number> = {};
  let distinct = 0;

  for (const detection of detections) {
    const algorithmProperties = resolveFirst(detection, 'cryptoProperties.algorithmProperties') as
      | Record<string, unknown>
      | undefined;

    // Tolerate the primitive living directly under cryptoProperties too.
    let raw: unknown = algorithmProperties?.[field];
    if (raw == null && field === 'primitive') {
      raw = resolveFirst(detection, 'cryptoProperties.primitive');
    }
    if (raw == null) {
      continue;
    }

    const values = Array.isArray(raw) ? raw : [raw];
    for (const value of values) {
      const key = String(value);
      if (!counts[key]) {
        distinct += 1;
      }
      counts[key] = (counts[key] || 0) + 1;
    }
  }

  return {
    entries: toEntries(counts, labelFor),
    distinct,
  };
}

/** Count detections by asset type (`cryptoProperties.assetType`). */
export function countAssetTypes(
  detections: CryptoAsset[],
  labelFor: (key: string) => string,
): Distribution {
  const counts: Record<string, number> = {};
  let distinct = 0;

  for (const detection of detections) {
    const type = assetType(detection);
    if (!type) {
      continue;
    }
    if (!counts[type]) {
      distinct += 1;
    }
    counts[type] = (counts[type] || 0) + 1;
  }

  return { entries: toEntries(counts, labelFor), distinct };
}

/** Count detections by asset name. Mirrors cbomkit's `countNames`. */
export function countNames(detections: CryptoAsset[]): Distribution {
  const counts: Record<string, number> = {};
  let distinct = 0;

  for (const detection of detections) {
    const name = assetName(detection);
    if (!name) {
      continue;
    }
    if (!counts[name]) {
      distinct += 1;
    }
    counts[name] = (counts[name] || 0) + 1;
  }

  return {
    entries: toEntries(counts, (key) => key),
    distinct,
  };
}

function toEntries(
  counts: Record<string, number>,
  labelFor: (key: string) => string,
): CountEntry[] {
  return Object.entries(counts)
    .map(([key, value]) => ({ key, label: labelFor(key) || key, value }))
    .sort((a, b) => b.value - a.value || a.label.localeCompare(b.label));
}

/** Total number of detections (occurrence-unwrapped). */
export function detectionCount(detections: CryptoAsset[]): number {
  return detections.length;
}
