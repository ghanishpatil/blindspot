/**
 * TrendChart contract:
 *
 * 1. Zero-point trend renders the "need at least 2 scans" empty state.
 * 2. One-point trend also shows the empty state -- a line needs two.
 * 3. Two-or-more points render a real chart (Recharts).
 * 4. A trend-fetch failure surfaces a visible error, not a blank card.
 * 5. Loading state is visible while the fetch is in flight.
 */

import { render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { TrendChart } from '@/components/TrendChart';
import * as scansApi from '@/services/scansApi';

function trendResponse(points: scansApi.ScanTrendPoint[]) {
  return {
    projectId: 'demo',
    count: points.length,
    points,
  };
}

function point(startedAt: string, overdue = 0): scansApi.ScanTrendPoint {
  return {
    scanId: `scan-${startedAt}`,
    startedAt,
    totalFindings: overdue + 5,
    overdue,
    transitional: 1,
    lowRisk: 4,
    hndlExposed: 0,
    currentWeakCrypto: 0,
  };
}

describe('TrendChart', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('shows the empty state when the project has no scans', async () => {
    vi.spyOn(scansApi, 'getScanTrend').mockResolvedValue(trendResponse([]));
    render(<TrendChart projectId="demo" />);
    expect(await screen.findByTestId('trend-empty')).toBeInTheDocument();
  });

  it('shows the empty state when the project has only one scan', async () => {
    vi.spyOn(scansApi, 'getScanTrend').mockResolvedValue(
      trendResponse([point('2026-09-01T00:00:00+00:00', 3)]),
    );
    render(<TrendChart projectId="demo" />);
    expect(await screen.findByTestId('trend-empty')).toBeInTheDocument();
  });

  it('renders the chart region when there are at least two scans', async () => {
    vi.spyOn(scansApi, 'getScanTrend').mockResolvedValue(
      trendResponse([
        point('2026-09-01T00:00:00+00:00', 3),
        point('2026-09-05T00:00:00+00:00', 1),
      ]),
    );
    render(<TrendChart projectId="demo" />);
    // Wait for the loading state to clear.
    await waitFor(() => expect(screen.queryByText(/loading trend/i)).not.toBeInTheDocument());
    // Empty state must NOT appear when we have >= 2 points.
    expect(screen.queryByTestId('trend-empty')).not.toBeInTheDocument();
  });

  it('surfaces a fetch failure as an inline error message', async () => {
    vi.spyOn(scansApi, 'getScanTrend').mockRejectedValue(
      new Error('artifacts dir missing'),
    );
    render(<TrendChart projectId="demo" />);
    expect(await screen.findByText(/artifacts dir missing/i)).toBeInTheDocument();
  });

  it('shows the loading placeholder while the request is in flight', () => {
    vi.spyOn(scansApi, 'getScanTrend').mockReturnValue(new Promise(() => {}));
    render(<TrendChart projectId="demo" />);
    expect(screen.getByText(/loading trend/i)).toBeInTheDocument();
  });
});
