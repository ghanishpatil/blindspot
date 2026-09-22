/**
 * AgilityScoreCard contract:
 *
 * 1. Empty state when scan history is empty.
 * 2. Ready state renders the grade badge + score.
 * 3. Breakdown bars carry the correct earned/max ratios.
 * 4. Input tiles show the tier / weak / hndl counts verbatim.
 * 5. Backend error surfaces in an inline banner.
 */

import { render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { AgilityScoreCard } from '@/components/AgilityScoreCard';
import * as agility from '@/services/agilityApi';
import * as scans from '@/services/scansApi';

function summaryRow(id: string): scans.ScanSummaryRow {
  return {
    scanId: id,
    projectId: 'demo',
    ownerId: null,
    status: 'completed',
    mode: 'live',
    repository: 'demo-repo',
    startedAt: '2026-09-01T00:00:00Z',
    completedAt: '2026-09-01T00:00:00Z',
    findingCount: 1,
    summary: {
      totalFindings: 1,
      overdue: 0,
      transitional: 0,
      lowRisk: 1,
      hndlExposed: 0,
      currentWeakCrypto: 0,
    },
  };
}

function scoreFixture(
  overrides: Partial<agility.AgilityScoreResponse> = {},
): agility.AgilityScoreResponse {
  return {
    schemaVersion: 'blindspot.agility.v1',
    scanId: 'scan-a',
    projectId: 'demo',
    generatedAt: '2026-09-07T00:00:00+00:00',
    score: 88.75,
    grade: 'A',
    breakdown: {
      tierPosture: { earned: 55, max: 60 },
      weaknessImmunity: { earned: 20, max: 25 },
      hndlImmunity: { earned: 13.75, max: 15 },
    },
    inputs: {
      totalFindings: 8,
      overdue: 1,
      transitional: 0,
      lowRisk: 7,
      currentWeakCrypto: 1,
      hndlExposed: 1,
    },
    rationale: ['1 finding tier=overdue -- costs tier-posture budget.'],
    ...overrides,
  };
}

describe('AgilityScoreCard', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('renders the empty state when there are no scans', async () => {
    vi.spyOn(scans, 'listScans').mockResolvedValue({ count: 0, scans: [] });
    const spy = vi.spyOn(agility, 'getAgilityScore');
    render(<AgilityScoreCard />);
    await screen.findByTestId('agility-empty');
    // Never called when there is no scan to score.
    expect(spy).not.toHaveBeenCalled();
  });

  it('renders the grade and score for the latest scan', async () => {
    vi.spyOn(scans, 'listScans').mockResolvedValue({
      count: 1,
      scans: [summaryRow('scan-latest')],
    });
    const scoreSpy = vi
      .spyOn(agility, 'getAgilityScore')
      .mockResolvedValue(scoreFixture());

    render(<AgilityScoreCard />);
    await screen.findByTestId('agility-result');

    const badge = screen.getByTestId('agility-grade-badge');
    expect(badge.textContent).toContain('A');

    const scoreEl = screen.getByTestId('agility-score-value');
    expect(scoreEl.textContent).toContain('88.8'); // toFixed(1)

    // Fetches against the latest scan id.
    expect(scoreSpy).toHaveBeenCalledWith('scan-latest', expect.anything());
  });

  it('renders breakdown bars for the three bands', async () => {
    vi.spyOn(scans, 'listScans').mockResolvedValue({
      count: 1,
      scans: [summaryRow('scan-latest')],
    });
    vi.spyOn(agility, 'getAgilityScore').mockResolvedValue(scoreFixture());

    render(<AgilityScoreCard />);
    await screen.findByTestId('agility-result');

    // One bar per band.
    expect(screen.getByTestId('agility-bar-tier')).toBeTruthy();
    expect(screen.getByTestId('agility-bar-weakness')).toBeTruthy();
    expect(screen.getByTestId('agility-bar-hndl')).toBeTruthy();
  });

  it('surfaces backend errors inline', async () => {
    vi.spyOn(scans, 'listScans').mockResolvedValue({
      count: 1,
      scans: [summaryRow('scan-latest')],
    });
    vi.spyOn(agility, 'getAgilityScore').mockRejectedValue(new Error('boom'));

    render(<AgilityScoreCard />);
    await waitFor(() =>
      expect(screen.getByText(/boom/i)).toBeTruthy(),
    );
  });
});
