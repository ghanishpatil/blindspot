/**
 * FindingPresetSensitivity contract:
 *
 * 1. Silent (renders null) when the compliance endpoint fails -- the
 *    surrounding page must remain usable.
 * 2. Silent when this finding is not in the current scan.
 * 3. Ready state renders the preset dropdown + tier chip + Mosca equation.
 * 4. Changing preset re-renders the equation for that preset.
 * 5. Flip indicator appears when the selected preset's tier differs
 *    from the baseline tier.
 */

import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { FindingPresetSensitivity } from '@/components/FindingPresetSensitivity';
import * as api from '@/services/api';
import type { ComplianceEvaluation } from '@/types';

function makeEvaluation(
  overrides: Partial<ComplianceEvaluation> = {},
): ComplianceEvaluation {
  return {
    scanId: 'scan-1',
    generatedAt: '2026-09-01T00:00:00Z',
    baselinePresetName: 'Demo default',
    totalFindings: 1,
    presets: [
      { name: 'Demo default', z: 10, targetYear: 2036, source: 'demo' },
      { name: 'India CII 2027', z: 3, targetYear: 2027, source: 'india' },
      { name: 'CRQC estimate', z: 15, targetYear: 2040, source: 'crqc' },
    ],
    findings: [
      {
        findingId: 'F-1',
        displayName: 'RSA-2048',
        algorithm: 'RSA',
        filePath: 'src/a.py',
        lineNumber: 10,
        criticality: 'high',
        isQuantumVulnerable: true,
        baselineTier: 'low-risk',
        tiersByPreset: {
          'Demo default': {
            tier: 'low-risk',
            applicable: true,
            x: 5,
            y: 3,
            z: 10,
            equation: '5.0 + 3.0 > 10.0 (false)',
            marginYears: -2,
          },
          'India CII 2027': {
            tier: 'overdue',
            applicable: true,
            x: 5,
            y: 3,
            z: 3,
            equation: '5.0 + 3.0 > 3.0 (true)',
            marginYears: 5,
          },
          'CRQC estimate': {
            tier: 'low-risk',
            applicable: true,
            x: 5,
            y: 3,
            z: 15,
            equation: '5.0 + 3.0 > 15.0 (false)',
            marginYears: -7,
          },
        },
      },
    ],
    summaryByPreset: {},
    ...overrides,
  };
}

describe('FindingPresetSensitivity', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('renders null when the compliance endpoint fails', async () => {
    vi.spyOn(api, 'fetchCompliance').mockRejectedValue(new Error('no scan'));
    const { container } = render(<FindingPresetSensitivity findingId="F-1" />);
    await waitFor(() =>
      expect(container.querySelector('[data-testid="finding-preset-sensitivity"]')).toBeNull(),
    );
  });

  it('renders null when the finding is not in the evaluation', async () => {
    vi.spyOn(api, 'fetchCompliance').mockResolvedValue(makeEvaluation());
    const { container } = render(<FindingPresetSensitivity findingId="F-UNKNOWN" />);
    await waitFor(() =>
      expect(container.querySelector('[data-testid="finding-preset-sensitivity"]')).toBeNull(),
    );
  });

  it('renders the preset selector and baseline tier on load', async () => {
    vi.spyOn(api, 'fetchCompliance').mockResolvedValue(makeEvaluation());
    render(<FindingPresetSensitivity findingId="F-1" />);
    const select = (await screen.findByTestId(
      'preset-sensitivity-select',
    )) as HTMLSelectElement;
    // Defaults to the baseline preset.
    expect(select.value).toBe('Demo default');
    // Baseline tier equals selected -> stable indicator, not flipped.
    expect(screen.getByTestId('preset-sensitivity-stable-indicator')).toBeTruthy();
  });

  it('flips the equation and shows the flip indicator when preset changes tier', async () => {
    vi.spyOn(api, 'fetchCompliance').mockResolvedValue(makeEvaluation());
    render(<FindingPresetSensitivity findingId="F-1" />);
    const select = (await screen.findByTestId(
      'preset-sensitivity-select',
    )) as HTMLSelectElement;

    fireEvent.change(select, { target: { value: 'India CII 2027' } });

    // The equation now reflects the India preset's Z=3.
    const equation = await screen.findByTestId('preset-sensitivity-equation');
    expect(equation.textContent).toMatch(/> 3\.0/);

    // Flip indicator appears because the tier moved low-risk -> overdue.
    expect(screen.getByTestId('preset-sensitivity-flip-indicator')).toBeTruthy();
  });

  it('shows stable indicator when the selected preset preserves baseline tier', async () => {
    vi.spyOn(api, 'fetchCompliance').mockResolvedValue(makeEvaluation());
    render(<FindingPresetSensitivity findingId="F-1" />);
    const select = (await screen.findByTestId(
      'preset-sensitivity-select',
    )) as HTMLSelectElement;

    fireEvent.change(select, { target: { value: 'CRQC estimate' } });

    // Both baseline and CRQC keep the finding at low-risk.
    await waitFor(() =>
      expect(screen.getByTestId('preset-sensitivity-stable-indicator')).toBeTruthy(),
    );
    expect(screen.queryByTestId('preset-sensitivity-flip-indicator')).toBeNull();
  });
});
