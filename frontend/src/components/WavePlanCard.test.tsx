/**
 * WavePlanCard contract:
 *
 * 1. Empty state when the roadmap comes back with zero waves.
 * 2. Ready state renders one row per wave with strategy tag + item count.
 * 3. Error surfaces inline.
 * 4. Link to /roadmap page always visible so operators can drill down.
 */

import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { WavePlanCard } from '@/components/WavePlanCard';
import * as api from '@/services/api';
import type { MigrationRoadmap } from '@/types';

import type { MigrationStrategy, RoadmapItem } from '@/types';

function makeItem(overrides: Partial<RoadmapItem> = {}): RoadmapItem {
  return {
    findingId: 'f',
    displayName: 'placeholder',
    algorithm: 'RSA',
    filePath: 'src/a.py',
    lineNumber: 1,
    strategy: 'REMEDIATE_NOW' as MigrationStrategy,
    currentAlgorithm: 'RSA',
    targetAlgorithm: 'ML-KEM-768',
    parameterSet: '2048',
    riskTier: 'overdue',
    criticality: 'high',
    priorityScore: 100,
    blastRadius: 1,
    effort: 'low',
    costBand: 'low',
    rationale: '-',
    isCurrentWeakness: false,
    ...overrides,
  };
}

function makeRoadmap(overrides: Partial<MigrationRoadmap> = {}): MigrationRoadmap {
  return {
    scanId: 'scan-1',
    generatedAt: '2026-09-01T00:00:00Z',
    totalItems: 3,
    summary: {},
    waves: [
      {
        key: 'w1',
        order: 1,
        title: 'Remediate weak crypto',
        description: 'MD5 + SHA-1 hashes',
        strategy: 'REMEDIATE_NOW' as MigrationStrategy,
        items: [
          makeItem({ findingId: 'f1', displayName: 'MD5', algorithm: 'MD5' }),
          makeItem({ findingId: 'f2', displayName: 'SHA-1', algorithm: 'SHA-1' }),
        ],
        itemCount: 2,
      },
      {
        key: 'w2',
        order: 2,
        title: 'PQC migration',
        description: 'RSA / ECC to ML-KEM / ML-DSA',
        strategy: 'PQC' as MigrationStrategy,
        items: [
          makeItem({
            findingId: 'f3',
            displayName: 'RSA-2048',
            algorithm: 'RSA',
            effort: 'high',
          }),
        ],
        itemCount: 1,
      },
    ],
    ...overrides,
  };
}

describe('WavePlanCard', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('renders empty state when the roadmap has no waves', async () => {
    vi.spyOn(api, 'fetchRoadmap').mockResolvedValue(
      makeRoadmap({ waves: [], totalItems: 0 }),
    );
    render(
      <MemoryRouter>
        <WavePlanCard />
      </MemoryRouter>,
    );
    await screen.findByTestId('wave-plan-empty');
  });

  it('renders one row per wave with strategy label and item count', async () => {
    vi.spyOn(api, 'fetchRoadmap').mockResolvedValue(makeRoadmap());
    render(
      <MemoryRouter>
        <WavePlanCard />
      </MemoryRouter>,
    );
    const tbody = await screen.findByTestId('wave-plan-tbody');
    expect(tbody.querySelectorAll('tr')).toHaveLength(2);
    expect(screen.getByTestId('wave-row-1').textContent).toMatch(/REMEDIATE_NOW/);
    expect(screen.getByTestId('wave-row-2').textContent).toMatch(/PQC/);
  });

  it('surfaces backend error inline', async () => {
    vi.spyOn(api, 'fetchRoadmap').mockRejectedValue(new Error('nope'));
    render(
      <MemoryRouter>
        <WavePlanCard />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText(/nope/i)).toBeTruthy());
  });

  it('always shows a link to the full roadmap page', () => {
    vi.spyOn(api, 'fetchRoadmap').mockImplementation(() => new Promise(() => {}));
    render(
      <MemoryRouter>
        <WavePlanCard />
      </MemoryRouter>,
    );
    const link = screen.getByTestId('wave-plan-view-full') as HTMLAnchorElement;
    expect(link.getAttribute('href')).toBe('/roadmap');
  });
});
