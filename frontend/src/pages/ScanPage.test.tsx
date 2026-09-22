/**
 * ScanPage — the parts we own for the F2 (bundled TLS) shipment.
 *
 * Contract:
 *
 * 1. Typing hosts into the "Live TLS endpoints" textarea updates the
 *    small counter chip in real time, so the user has feedback before
 *    they click "Start Discovery Scan".
 * 2. Pressing "Start Discovery Scan" calls `startScan()` with a parsed
 *    `tlsTargets` array. Empty input means the key is omitted.
 * 3. The parser semantics match `parseTlsTargets`: comma / whitespace /
 *    newline separated, dedup, trim.
 *
 * We stub `startScan` + `fetchFindings` + `fetchCbom` so the test does
 * not depend on the backend running.
 */

import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { ScanPage } from '@/pages/ScanPage';
import * as api from '@/services/api';
import { DEMO_CBOM_JSON, DEMO_PLANTED_FINDINGS } from '@/services/mockData';

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/scan']}>
      <ScanPage />
    </MemoryRouter>,
  );
}

const FAKE_SCAN_RESPONSE = {
  scanId: 'scan-tls-test',
  status: 'completed' as const,
  mode: 'live' as const,
  repository: 'demo-repo',
  findingCount: DEMO_PLANTED_FINDINGS.length,
  durationSeconds: 0.5,
  cbomAvailable: true,
  message: null,
  summary: {
    totalFindings: DEMO_PLANTED_FINDINGS.length,
    quantumSensitive: 3,
    overdue: 2,
    transitional: 1,
    lowRisk: 1,
    currentWeakCrypto: 1,
    hndlExposed: 2,
    needsVerification: 1,
    unresolvedParameters: 0,
    byAlgorithm: {},
    byArtefactType: {},
    byConfidenceLevel: {},
    filesScanned: 10,
  },
};

describe('ScanPage - TLS targets input (F2)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(api, 'fetchFindings').mockResolvedValue(DEMO_PLANTED_FINDINGS);
    vi.spyOn(api, 'fetchCbom').mockResolvedValue(JSON.parse(DEMO_CBOM_JSON));
  });

  it('shows no target-count chip until the user types something valid', () => {
    renderPage();

    expect(screen.queryByTestId('tls-target-count')).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(/live tls endpoints/i), {
      target: { value: '  ' },
    });
    expect(screen.queryByTestId('tls-target-count')).not.toBeInTheDocument();
  });

  it('updates the target-count chip as the user types comma-separated hosts', () => {
    renderPage();

    fireEvent.change(screen.getByLabelText(/live tls endpoints/i), {
      target: { value: 'github.com, cloudflare.com:443' },
    });

    const chip = screen.getByTestId('tls-target-count');
    expect(chip).toHaveTextContent('2 targets');
  });

  it('sends the parsed tls_targets array on scan submit', async () => {
    const startScanSpy = vi
      .spyOn(api, 'startScan')
      .mockResolvedValue(FAKE_SCAN_RESPONSE);

    renderPage();

    fireEvent.change(screen.getByLabelText(/live tls endpoints/i), {
      target: { value: '  github.com , cloudflare.com:443\n api.example.com  ' },
    });

    fireEvent.click(screen.getByRole('button', { name: /start discovery scan/i }));

    await waitFor(() => expect(startScanSpy).toHaveBeenCalledTimes(1));
    const call = startScanSpy.mock.calls[0][0];
    expect(call?.tlsTargets).toEqual([
      'github.com',
      'cloudflare.com:443',
      'api.example.com',
    ]);
  });

  it('omits tls_targets entirely when the user leaves the input empty', async () => {
    const startScanSpy = vi
      .spyOn(api, 'startScan')
      .mockResolvedValue(FAKE_SCAN_RESPONSE);

    renderPage();

    fireEvent.click(screen.getByRole('button', { name: /start discovery scan/i }));

    await waitFor(() => expect(startScanSpy).toHaveBeenCalledTimes(1));
    const call = startScanSpy.mock.calls[0][0];
    expect(call).not.toHaveProperty('tlsTargets');
  });
});
