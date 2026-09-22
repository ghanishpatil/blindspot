/**
 * StorageBackendChip contract:
 *
 * 1. Renders a green "LOCAL · Air-gap" pill when the backend resolves to
 *    the local filesystem. This is the visible proof that a scan does
 *    not talk to Firebase.
 * 2. Renders a blue "FIREBASE" pill when the backend is talking to
 *    Firebase / Firestore.
 * 3. Renders a muted "Storage ?" pill when the backend response omits
 *    the storage block entirely (old backends), never a false claim.
 * 4. Renders a "Storage…" pill while the health call is in flight.
 */

import { render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { StorageBackendChip } from '@/components/StorageBackendChip';
import * as api from '@/services/api';
import type { HealthResponse } from '@/types';

const BASE_HEALTH: Omit<HealthResponse, 'storage'> = {
  status: 'ok',
  service: 'blindspot-ecdat',
  version: '1.0.0',
  environment: 'development',
  phase: '1',
  readiness: 'ready',
  degradedSubsystems: [],
  subsystems: {
    firebase: { available: true, reason: null },
    semgrep: { available: true, reason: null },
    demoRepository: { available: true, reason: null },
    fallbackCache: { available: true, reason: null },
  },
  mosca: {
    activeZ: 10,
    activeZSource: 'test',
    defaultY: 3,
    zPresets: [],
  },
};

describe('StorageBackendChip', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('renders the air-gap label when the backend resolves to local', async () => {
    vi.spyOn(api, 'fetchHealth').mockResolvedValue({
      ...BASE_HEALTH,
      storage: {
        requested: 'auto',
        effective: 'local',
        artifactsDir: '/artifacts',
        fallbackCachePath: '/cache/last.json',
      },
    });

    render(<StorageBackendChip />);
    const chip = await screen.findByRole('status');
    expect(chip).toHaveTextContent(/local/i);
    expect(chip).toHaveTextContent(/air-gap/i);
  });

  it('renders the Firebase label when the backend resolves to firebase', async () => {
    vi.spyOn(api, 'fetchHealth').mockResolvedValue({
      ...BASE_HEALTH,
      storage: {
        requested: 'firebase',
        effective: 'firebase',
        artifactsDir: '/artifacts',
        fallbackCachePath: '/cache/last.json',
      },
    });

    render(<StorageBackendChip />);
    const chip = await screen.findByRole('status');
    expect(chip).toHaveTextContent(/firebase/i);
    expect(chip).not.toHaveTextContent(/air-gap/i);
  });

  it('renders a muted unknown pill when the backend omits the storage block', async () => {
    // Old backend that has not been redeployed yet.
    vi.spyOn(api, 'fetchHealth').mockResolvedValue({ ...BASE_HEALTH });

    render(<StorageBackendChip />);
    // No role="status" for the unknown state -- deliberate, so an
    // accessibility scan does not surface a fake claim.
    await waitFor(() => {
      expect(screen.getByText(/storage \?/i)).toBeInTheDocument();
    });
  });

  it('renders the muted unknown pill when the health call outright fails', async () => {
    vi.spyOn(api, 'fetchHealth').mockRejectedValue(new Error('backend offline'));

    render(<StorageBackendChip />);
    await waitFor(() => {
      expect(screen.getByText(/storage \?/i)).toBeInTheDocument();
    });
  });

  it('shows the loading placeholder before the health call resolves', () => {
    // Never-resolving promise so the component stays in the loading state.
    vi.spyOn(api, 'fetchHealth').mockReturnValue(new Promise(() => {}));

    render(<StorageBackendChip />);
    expect(screen.getByText(/storage…/i)).toBeInTheDocument();
  });
});
