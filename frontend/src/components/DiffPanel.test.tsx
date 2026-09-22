/**
 * DiffPanel contract:
 *
 * 1. Empty state when < 2 scans exist on disk (nothing to diff).
 * 2. Two selectors + a Compare button when >= 2 scans; compare disabled
 *    when base == head.
 * 3. Clicking Compare fires getScanDiff with the selected ids.
 * 4. Results block renders exactly one row per added / removed / changed
 *    finding.
 * 5. Signed delta chips: negative overdue delta renders green (good);
 *    positive overdue delta renders red (regression signal).
 * 6. Fetch failure -> visible inline error, no console-only silence.
 */

import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { DiffPanel } from '@/components/DiffPanel';
import * as scansApi from '@/services/scansApi';

function summaryRow(id: string, startedAt: string): scansApi.ScanSummaryRow {
  return {
    scanId: id,
    projectId: 'demo',
    ownerId: null,
    status: 'completed',
    mode: 'live',
    repository: 'demo-repo',
    startedAt,
    completedAt: startedAt,
    findingCount: 1,
    summary: {
      totalFindings: 1,
      overdue: 1,
      transitional: 0,
      lowRisk: 0,
      hndlExposed: 0,
      currentWeakCrypto: 0,
    },
  };
}

function diffResponse(
  changed: number,
  overdueDelta: number,
): scansApi.ScanDiffResponse {
  return {
    base: {
      scanId: 'scan-old',
      projectId: 'demo',
      startedAt: '2026-09-01T00:00:00Z',
      completedAt: '2026-09-01T00:00:00Z',
      findingCount: 1,
      summary: { overdue: 1 },
    },
    head: {
      scanId: 'scan-new',
      projectId: 'demo',
      startedAt: '2026-09-02T00:00:00Z',
      completedAt: '2026-09-02T00:00:00Z',
      findingCount: 1,
      summary: { overdue: 1 + overdueDelta },
    },
    summaryDelta: {
      totalFindings: 0,
      overdue: overdueDelta,
      transitional: 0,
      lowRisk: 0,
      hndlExposed: 0,
      currentWeakCrypto: 0,
    },
    added: [],
    removed: [],
    changed: Array.from({ length: changed }, (_, i) => ({
      id: `F${i}`,
      algorithm: 'RSA',
      displayName: 'RSA-2048',
      parameter: '2048',
      curve: null,
      filePath: `src/a${i}.py`,
      lineNumber: 10,
      riskTier: 'low-risk',
      isHndlExposed: false,
      isCurrentlyWeak: false,
      detectionMethod: 'semgrep_api_pattern',
      previousTier: 'overdue',
      currentTier: 'low-risk',
      previousLineNumber: 10,
    })),
    unchangedCount: 0,
    addedCount: 0,
    removedCount: 0,
    changedCount: changed,
  };
}

function renderPanel() {
  return render(
    <MemoryRouter>
      <DiffPanel projectId="demo" />
    </MemoryRouter>,
  );
}

describe('DiffPanel', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('shows the empty state when fewer than 2 scans exist', async () => {
    vi.spyOn(scansApi, 'listScans').mockResolvedValue({
      count: 1,
      scans: [summaryRow('only', '2026-09-01T00:00:00Z')],
    });
    renderPanel();
    expect(await screen.findByTestId('diff-empty')).toBeInTheDocument();
  });

  it('renders base + head selectors when 2+ scans exist', async () => {
    vi.spyOn(scansApi, 'listScans').mockResolvedValue({
      count: 2,
      scans: [
        summaryRow('scan-new', '2026-09-02T00:00:00Z'),
        summaryRow('scan-old', '2026-09-01T00:00:00Z'),
      ],
    });
    renderPanel();
    expect(await screen.findByTestId('diff-base-select')).toBeInTheDocument();
    expect(screen.getByTestId('diff-head-select')).toBeInTheDocument();
    // Pre-fill: newest -> head, second-newest -> base.
    await waitFor(() => {
      expect((screen.getByTestId('diff-head-select') as HTMLSelectElement).value).toBe(
        'scan-new',
      );
      expect((screen.getByTestId('diff-base-select') as HTMLSelectElement).value).toBe(
        'scan-old',
      );
    });
  });

  it('calls getScanDiff with the selected ids on Compare', async () => {
    vi.spyOn(scansApi, 'listScans').mockResolvedValue({
      count: 2,
      scans: [
        summaryRow('scan-new', '2026-09-02T00:00:00Z'),
        summaryRow('scan-old', '2026-09-01T00:00:00Z'),
      ],
    });
    const diffSpy = vi
      .spyOn(scansApi, 'getScanDiff')
      .mockResolvedValue(diffResponse(1, -1));

    renderPanel();
    const btn = await screen.findByTestId('diff-run-button');
    fireEvent.click(btn);

    await waitFor(() => expect(diffSpy).toHaveBeenCalledTimes(1));
    expect(diffSpy).toHaveBeenCalledWith('scan-old', 'scan-new');
  });

  it('renders the changed rows with a from -> to tier chip pair', async () => {
    vi.spyOn(scansApi, 'listScans').mockResolvedValue({
      count: 2,
      scans: [
        summaryRow('scan-new', '2026-09-02T00:00:00Z'),
        summaryRow('scan-old', '2026-09-01T00:00:00Z'),
      ],
    });
    vi.spyOn(scansApi, 'getScanDiff').mockResolvedValue(diffResponse(1, -1));

    renderPanel();
    fireEvent.click(await screen.findByTestId('diff-run-button'));

    const changedBlock = await screen.findByTestId('diff-changed');
    expect(changedBlock).toHaveTextContent(/rsa-2048/i);
    // Migration progress: overdue delta = -1 -> good, green chip.
    // We assert the numeric value shows the leading minus sign so the
    // delta chip cannot be mistaken for a positive count.
    const result = await screen.findByTestId('diff-result');
    expect(result).toHaveTextContent(/-1/);
  });

  it('surfaces a fetch failure inline instead of swallowing it', async () => {
    vi.spyOn(scansApi, 'listScans').mockResolvedValue({
      count: 2,
      scans: [
        summaryRow('scan-new', '2026-09-02T00:00:00Z'),
        summaryRow('scan-old', '2026-09-01T00:00:00Z'),
      ],
    });
    vi.spyOn(scansApi, 'getScanDiff').mockRejectedValue(
      new Error('base and head must differ'),
    );

    renderPanel();
    fireEvent.click(await screen.findByTestId('diff-run-button'));

    await waitFor(() => {
      expect(screen.getByText(/base and head must differ/i)).toBeInTheDocument();
    });
  });

  // --------------------------------------------------------------------
  // UX contract: bucket tables scroll inside a bounded region and can
  // be collapsed. Prevents a huge diff from blowing out the page.
  // --------------------------------------------------------------------

  it('small buckets stay expanded by default with an internal scroller', async () => {
    vi.spyOn(scansApi, 'listScans').mockResolvedValue({
      count: 2,
      scans: [
        summaryRow('scan-new', '2026-09-02T00:00:00Z'),
        summaryRow('scan-old', '2026-09-01T00:00:00Z'),
      ],
    });
    vi.spyOn(scansApi, 'getScanDiff').mockResolvedValue(diffResponse(1, -1));

    renderPanel();
    fireEvent.click(await screen.findByTestId('diff-run-button'));

    // Bucket auto-expanded (only 1 row); scroller wrapper is present.
    const scroller = await screen.findByTestId('diff-changed-scroller');
    expect(scroller).toBeInTheDocument();
    // The wrapper carries the bounded max-height class so overflow scrolls
    // *inside* the bucket rather than pushing sibling buckets off-screen.
    expect(scroller.className).toMatch(/max-h-\[/);
    expect(scroller.className).toMatch(/overflow-auto/);
  });

  it('huge buckets auto-collapse and toggle open on click', async () => {
    vi.spyOn(scansApi, 'listScans').mockResolvedValue({
      count: 2,
      scans: [
        summaryRow('scan-new', '2026-09-02T00:00:00Z'),
        summaryRow('scan-old', '2026-09-01T00:00:00Z'),
      ],
    });
    // 30 rows > AUTO_COLLAPSE_THRESHOLD (25) -> starts collapsed.
    vi.spyOn(scansApi, 'getScanDiff').mockResolvedValue(diffResponse(30, -30));

    renderPanel();
    fireEvent.click(await screen.findByTestId('diff-run-button'));

    const toggle = await screen.findByTestId('diff-changed-toggle');
    // Auto-collapsed -> scroller does NOT render its table body.
    expect(screen.queryByTestId('diff-changed-scroller')).not.toBeInTheDocument();
    expect(toggle).toHaveAttribute('aria-expanded', 'false');

    // Click to expand.
    fireEvent.click(toggle);
    expect(await screen.findByTestId('diff-changed-scroller')).toBeInTheDocument();
    expect(toggle).toHaveAttribute('aria-expanded', 'true');

    // Click again to collapse.
    fireEvent.click(toggle);
    await waitFor(() =>
      expect(screen.queryByTestId('diff-changed-scroller')).not.toBeInTheDocument(),
    );
  });

  it('empty buckets show the empty label and no toggle affordance', async () => {
    vi.spyOn(scansApi, 'listScans').mockResolvedValue({
      count: 2,
      scans: [
        summaryRow('scan-new', '2026-09-02T00:00:00Z'),
        summaryRow('scan-old', '2026-09-01T00:00:00Z'),
      ],
    });
    // 0 added, 0 removed, 1 changed. The Added / Removed buckets are
    // empty; their toggle button MUST be disabled (aria-expanded absent)
    // so keyboard users don't get tricked into expanding an empty region.
    vi.spyOn(scansApi, 'getScanDiff').mockResolvedValue(diffResponse(1, -1));

    renderPanel();
    fireEvent.click(await screen.findByTestId('diff-run-button'));

    const addedToggle = (await screen.findByTestId('diff-added-toggle')) as HTMLButtonElement;
    expect(addedToggle.disabled).toBe(true);
    expect(addedToggle).not.toHaveAttribute('aria-expanded');
  });
});
