import { useEffect, useState } from 'react';

import { fetchHealth } from '@/services/api';
import type { HealthResponse } from '@/types';

type State =
  | { kind: 'loading' }
  | { kind: 'online'; health: HealthResponse }
  | { kind: 'offline'; message: string };

const DOT_CLASS: Record<'loading' | 'ready' | 'degraded' | 'offline', string> = {
  loading: 'bg-ink-faint',
  ready: 'bg-tier-low',
  degraded: 'bg-tier-transitional',
  offline: 'bg-tier-overdue',
};

/**
 * Live backend connectivity indicator.
 *
 * Distinguishes three states that need different responses:
 *
 * - **offline** — the API is unreachable; start the backend
 * - **degraded** — the API is up but part of the pipeline is not ready
 *   (no Firebase, no seeded repo, no semgrep)
 * - **ready** — everything the pipeline needs is present
 *
 * Collapsing "degraded" into "online" would hide exactly the problems that
 * break a demo.
 */
export function BackendStatus() {
  const [state, setState] = useState<State>({ kind: 'loading' });

  useEffect(() => {
    const controller = new AbortController();

    fetchHealth(controller.signal)
      .then((health) => setState({ kind: 'online', health }))
      .catch((error: unknown) => {
        if (controller.signal.aborted) {
          return;
        }
        setState({
          kind: 'offline',
          message: error instanceof Error ? error.message : 'Backend unreachable.',
        });
      });

    return () => controller.abort();
  }, []);

  if (state.kind === 'loading') {
    return (
      <span className="flex items-center gap-2 text-xs text-ink-faint">
        <span className={`h-2 w-2 rounded-full ${DOT_CLASS.loading}`} />
        Checking backend…
      </span>
    );
  }

  if (state.kind === 'offline') {
    return (
      <span
        className="flex items-center gap-2 text-xs text-ink-muted"
        title={state.message}
      >
        <span className={`h-2 w-2 rounded-full ${DOT_CLASS.offline}`} />
        Backend offline
      </span>
    );
  }

  const { health } = state;
  const isReady = health.readiness === 'ready';
  const detail = isReady
    ? `${health.service} v${health.version}`
    : `Not ready: ${health.degradedSubsystems.join(', ')}`;

  return (
    <span className="flex items-center gap-2 text-xs text-ink-muted" title={detail}>
      <span
        className={`h-2 w-2 rounded-full ${isReady ? DOT_CLASS.ready : DOT_CLASS.degraded}`}
      />
      {isReady ? 'Backend ready' : 'Backend degraded'}
    </span>
  );
}
