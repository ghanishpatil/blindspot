/**
 * BenchmarkPanel contract:
 *
 * 1. Empty state renders when getLatestBenchmark resolves null (404).
 * 2. Ready state renders the score cards with F1 / precision / recall.
 * 3. Clicking Run calls runBenchmark and swaps the panel into ready state.
 * 4. Per-category rollup renders one row per category with F1 to 3dp.
 * 5. Runtime error from POST /run surfaces in an inline banner.
 */

import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { BenchmarkPanel } from '@/components/BenchmarkPanel';
import * as api from '@/services/benchmarkApi';

function makeReport(overrides: Partial<api.BenchmarkReport> = {}): api.BenchmarkReport {
  return {
    schemaVersion: 'blindspot.benchmark.report.v1',
    datasetName: 'blindspot-builtin',
    datasetDescription: 'test',
    generatedAt: '2026-09-07T00:00:00+00:00',
    pipelineVersion: '0.1.0',
    elapsedSeconds: 0.42,
    totalCases: 2,
    totalExpected: 2,
    totalReported: 1,
    overall: {
      tp: 1, fp: 0, fn: 1, tn: 0,
      precision: 1.0, recall: 0.5, f1: 0.667, accuracy: 0.5,
    },
    categories: {
      'weak-crypto/rsa': {
        tp: 1, fp: 0, fn: 0, tn: 0,
        precision: 1.0, recall: 1.0, f1: 1.0, accuracy: 1.0,
        cases: 1,
      },
      'weak-crypto/hash': {
        tp: 0, fp: 0, fn: 1, tn: 0,
        precision: 0.0, recall: 0.0, f1: 0.0, accuracy: 0.0,
        cases: 1,
      },
    },
    cases: [
      {
        caseId: 'weak-rsa-1024',
        file: 'cases/weak_rsa_1024.py',
        category: 'weak-crypto/rsa',
        language: 'python',
        expectedCount: 1,
        reportedCount: 1,
        tp: 1, fp: 0, fn: 0, tn: 0,
        matched: [], missed: [], extra: [],
      },
    ],
    ...overrides,
  };
}

describe('BenchmarkPanel', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('renders the empty state when no run is cached yet', async () => {
    vi.spyOn(api, 'getLatestBenchmark').mockResolvedValue(null);
    render(<BenchmarkPanel />);
    const empty = await screen.findByTestId('benchmark-empty');
    expect(empty.textContent).toMatch(/no benchmark has run yet/i);
  });

  it('renders the ready state with score cards when a report loads', async () => {
    vi.spyOn(api, 'getLatestBenchmark').mockResolvedValue(makeReport());
    render(<BenchmarkPanel />);
    const f1 = await screen.findByTestId('benchmark-score-f1');
    expect(f1.textContent).toMatch(/0\.667/);
    const precision = screen.getByTestId('benchmark-score-precision');
    expect(precision.textContent).toMatch(/1\.000/);
    const recall = screen.getByTestId('benchmark-score-recall');
    expect(recall.textContent).toMatch(/0\.500/);
  });

  it('per-category rollup renders one row per category', async () => {
    vi.spyOn(api, 'getLatestBenchmark').mockResolvedValue(makeReport());
    render(<BenchmarkPanel />);
    const tbody = await screen.findByTestId('benchmark-categories-tbody');
    // Two categories in the fixture -> two rows.
    expect(tbody.querySelectorAll('tr')).toHaveLength(2);
    expect(tbody.textContent).toMatch(/weak-crypto\/rsa/);
    expect(tbody.textContent).toMatch(/weak-crypto\/hash/);
  });

  it('clicking Run calls runBenchmark and moves into ready state', async () => {
    vi.spyOn(api, 'getLatestBenchmark').mockResolvedValue(null);
    const runMock = vi.spyOn(api, 'runBenchmark').mockResolvedValue(makeReport());

    render(<BenchmarkPanel />);
    const button = await screen.findByTestId('benchmark-run-button');
    fireEvent.click(button);

    await waitFor(() => expect(runMock).toHaveBeenCalledTimes(1));
    // After the run resolves, empty state should disappear and score cards render.
    await screen.findByTestId('benchmark-score-f1');
    expect(screen.queryByTestId('benchmark-empty')).toBeNull();
  });

  it('surfaces a run failure in an inline banner', async () => {
    vi.spyOn(api, 'getLatestBenchmark').mockResolvedValue(null);
    vi.spyOn(api, 'runBenchmark').mockRejectedValue(
      new Error('semgrep exploded'),
    );
    render(<BenchmarkPanel />);
    const button = await screen.findByTestId('benchmark-run-button');
    fireEvent.click(button);

    const err = await screen.findByTestId('benchmark-run-error');
    expect(err.textContent).toMatch(/semgrep exploded/i);
  });
});
