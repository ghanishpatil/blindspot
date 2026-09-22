import { useEffect, useState } from 'react';

import { Icon } from '@/components/Icon';
import { fetchHealth } from '@/services/api';
import type { StorageStatus } from '@/types';

type State =
  | { kind: 'loading' }
  | { kind: 'known'; storage: StorageStatus }
  | { kind: 'unknown' };

/**
 * Small pill in the AppShell topbar showing the resolved storage backend.
 *
 * Two states judges care about:
 *
 * - **LOCAL · Air-gap** (green) -- the demo is running with zero outbound
 *   Firebase traffic. Every scan is mirrored to `artifactsDir` and the
 *   fallback cache. This is the single-glance proof that the ECDAT
 *   deployment can live on an NCIIPC / air-gapped network.
 * - **FIREBASE** (blue) -- Firestore + Firebase Storage are configured
 *   and being written to. Same code path as the demo build.
 *
 * The chip is intentionally quiet on older backends that do not report
 * `storage` on `/api/health`; it renders "STORAGE ?" in muted styling
 * instead of falsely claiming a mode.
 */
export function StorageBackendChip() {
  const [state, setState] = useState<State>({ kind: 'loading' });

  useEffect(() => {
    const controller = new AbortController();
    fetchHealth(controller.signal)
      .then((health) => {
        if (health.storage) {
          setState({ kind: 'known', storage: health.storage });
        } else {
          setState({ kind: 'unknown' });
        }
      })
      .catch(() => {
        if (!controller.signal.aborted) {
          setState({ kind: 'unknown' });
        }
      });
    return () => controller.abort();
  }, []);

  if (state.kind === 'loading') {
    return (
      <span
        aria-live="polite"
        className="inline-flex items-center gap-1.5 rounded-lg border border-[#222B35] bg-[#11171E] px-2.5 py-1.5 font-mono text-[11px] text-slate-500"
      >
        <span className="h-1.5 w-1.5 rounded-full bg-slate-500" />
        Storage…
      </span>
    );
  }

  if (state.kind === 'unknown') {
    return (
      <span
        title="Backend did not report storage backend state. Upgrade backend to see this."
        className="inline-flex items-center gap-1.5 rounded-lg border border-[#222B35] bg-[#11171E] px-2.5 py-1.5 font-mono text-[11px] text-slate-500"
      >
        <Icon name="database" size={12} />
        Storage ?
      </span>
    );
  }

  const { effective, requested, artifactsDir, fallbackCachePath } = state.storage;
  const isLocal = effective === 'local';

  const label = isLocal ? 'LOCAL · Air-gap' : effective.toUpperCase();
  const classes = isLocal
    ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
    : 'border-[#7DB7E8]/40 bg-[#7DB7E8]/10 text-[#7DB7E8]';

  const title =
    `Storage backend: ${effective}` +
    (requested && requested !== effective ? ` (requested: ${requested})` : '') +
    `\nArtifacts: ${artifactsDir}\nCache: ${fallbackCachePath}`;

  return (
    <span
      role="status"
      aria-label={`Storage backend: ${effective}`}
      title={title}
      className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 font-mono text-[11px] font-semibold tracking-wide ${classes}`}
    >
      <Icon name={isLocal ? 'shield' : 'database'} size={12} />
      {label}
    </span>
  );
}
