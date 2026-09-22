/**
 * PolicyEditor contract:
 *
 * 1. Default state chip renders "Built-in default" when isDefault=true.
 * 2. Custom-override chip renders "Custom override" when isDefault=false.
 * 3. Parse-status flips to invalid on non-JSON input and disables Save.
 * 4. Save calls saveActivePolicy with the parsed body; success flash
 *    replaces the state chip.
 * 5. Reset calls resetActivePolicy and reverts the status chip.
 * 6. Simulate needs >= 2 scans; the run button posts base+head+policy
 *    to simulatePolicy and renders the verdict + violations table.
 */

import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { PolicyEditor } from '@/components/PolicyEditor';
import * as policyApi from '@/services/policyApi';
import * as scansApi from '@/services/scansApi';

// ---------------------------------------------------------------------------
// Test data builders -- kept small; the API contract is exercised elsewhere.
// ---------------------------------------------------------------------------

function defaultEnvelope(): policyApi.PolicyEnvelope {
  return {
    schemaVersion: 'blindspot.policy.v1',
    isDefault: true,
    policy: {
      schemaVersion: 'blindspot.policy.v1',
      name: 'blindspot-default',
      rules: [
        {
          id: 'no-new-weak-now',
          on: 'introduced',
          match: { isCurrentlyWeak: true },
          action: 'block',
        },
      ],
    },
  };
}

function customEnvelope(): policyApi.PolicyEnvelope {
  return {
    schemaVersion: 'blindspot.policy.v1',
    isDefault: false,
    policy: {
      schemaVersion: 'blindspot.policy.v1',
      name: 'team-policy',
      rules: [
        {
          id: 'no-new-quantum-sensitive',
          on: 'introduced',
          match: { isQuantumSensitive: true },
          action: 'block',
        },
      ],
    },
  };
}

function summaryRow(id: string): scansApi.ScanSummaryRow {
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
      overdue: 1,
      transitional: 0,
      lowRisk: 0,
      hndlExposed: 0,
      currentWeakCrypto: 0,
    },
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('PolicyEditor', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    // Default scans stub: always resolves; individual tests can override.
    vi.spyOn(scansApi, 'listScans').mockResolvedValue({ count: 0, scans: [] });
  });

  it('renders the built-in default state chip when isDefault is true', async () => {
    vi.spyOn(policyApi, 'getActivePolicy').mockResolvedValue(defaultEnvelope());
    render(<PolicyEditor />);
    const chip = await screen.findByTestId('policy-status-chip');
    expect(chip.textContent).toMatch(/built-in default/i);
  });

  it('renders the custom-override chip when isDefault is false', async () => {
    vi.spyOn(policyApi, 'getActivePolicy').mockResolvedValue(customEnvelope());
    render(<PolicyEditor />);
    const chip = await screen.findByTestId('policy-status-chip');
    expect(chip.textContent).toMatch(/custom override/i);
  });

  it('shows the parsed rule count in the parse-status footer', async () => {
    vi.spyOn(policyApi, 'getActivePolicy').mockResolvedValue(defaultEnvelope());
    render(<PolicyEditor />);
    const status = await screen.findByTestId('policy-parse-status');
    expect(status.textContent).toMatch(/1 rule/);
    expect(status.textContent).toMatch(/blindspot-default/);
  });

  it('flags invalid JSON and disables Save', async () => {
    vi.spyOn(policyApi, 'getActivePolicy').mockResolvedValue(defaultEnvelope());
    render(<PolicyEditor />);
    const textarea = await screen.findByTestId('policy-editor-textarea');
    fireEvent.change(textarea, { target: { value: '{ this is not json' } });

    const status = await screen.findByTestId('policy-parse-status');
    expect(status.textContent).toMatch(/invalid json/i);

    const save = screen.getByTestId('policy-save-button') as HTMLButtonElement;
    expect(save.disabled).toBe(true);
  });

  it('saves the edited policy and shows a success message', async () => {
    vi.spyOn(policyApi, 'getActivePolicy').mockResolvedValue(defaultEnvelope());
    const saveMock = vi
      .spyOn(policyApi, 'saveActivePolicy')
      .mockResolvedValue(customEnvelope());

    render(<PolicyEditor />);
    const textarea = await screen.findByTestId('policy-editor-textarea');
    // Overwrite with a valid custom policy.
    fireEvent.change(textarea, {
      target: { value: JSON.stringify(customEnvelope().policy, null, 2) },
    });

    fireEvent.click(screen.getByTestId('policy-save-button'));
    await waitFor(() => expect(saveMock).toHaveBeenCalledTimes(1));

    const body = saveMock.mock.calls[0][0];
    expect(body.name).toBe('team-policy');

    const ok = await screen.findByTestId('policy-save-ok');
    expect(ok.textContent).toMatch(/policy saved/i);

    // Status chip flips to custom-override after save.
    const chip = await screen.findByTestId('policy-status-chip');
    expect(chip.textContent).toMatch(/custom override/i);
  });

  it('surfaces backend 400 detail from save as an error banner', async () => {
    vi.spyOn(policyApi, 'getActivePolicy').mockResolvedValue(defaultEnvelope());
    vi.spyOn(policyApi, 'saveActivePolicy').mockRejectedValue(
      new Error('policy.rules[0].action must be one of ...'),
    );
    render(<PolicyEditor />);
    await screen.findByTestId('policy-editor-textarea');
    fireEvent.click(screen.getByTestId('policy-save-button'));
    const err = await screen.findByTestId('policy-save-error');
    expect(err.textContent).toMatch(/action/i);
  });

  it('reset() calls resetActivePolicy and reverts the status chip', async () => {
    vi.spyOn(policyApi, 'getActivePolicy').mockResolvedValue(customEnvelope());
    const resetMock = vi
      .spyOn(policyApi, 'resetActivePolicy')
      .mockResolvedValue(defaultEnvelope());

    render(<PolicyEditor />);
    // Wait for the initial custom chip so we can prove the flip.
    await waitFor(() =>
      expect(screen.getByTestId('policy-status-chip').textContent).toMatch(
        /custom override/i,
      ),
    );

    fireEvent.click(screen.getByTestId('policy-reset-button'));
    await waitFor(() => expect(resetMock).toHaveBeenCalledTimes(1));

    const chip = await screen.findByTestId('policy-status-chip');
    expect(chip.textContent).toMatch(/built-in default/i);
  });

  it('simulation section hides the run button until >= 2 scans exist', async () => {
    vi.spyOn(policyApi, 'getActivePolicy').mockResolvedValue(defaultEnvelope());
    vi.spyOn(scansApi, 'listScans').mockResolvedValue({
      count: 1,
      scans: [summaryRow('scan-only-one')],
    });
    render(<PolicyEditor />);
    await screen.findByTestId('policy-editor-textarea');
    // Run button not rendered when there aren't enough scans.
    expect(screen.queryByTestId('policy-sim-run')).toBeNull();
  });

  it('simulate posts base+head+policy and renders the verdict', async () => {
    vi.spyOn(policyApi, 'getActivePolicy').mockResolvedValue(defaultEnvelope());
    vi.spyOn(scansApi, 'listScans').mockResolvedValue({
      count: 2,
      scans: [summaryRow('scan-b'), summaryRow('scan-a')],
    });
    const simMock = vi
      .spyOn(policyApi, 'simulatePolicy')
      .mockResolvedValue({
        policyName: 'blindspot-default',
        counts: { introduced: 1, resolved: 0, changed: 0, unchanged: 4 },
        violations: [
          {
            ruleId: 'no-new-weak-now',
            findingId: 'F-1',
            reason: 'New finding is currently weak.',
            field: 'isCurrentlyWeak',
            value: true,
            action: 'block',
          },
        ],
        blockCount: 1,
        warnCount: 0,
        wouldBlock: true,
      });

    render(<PolicyEditor />);
    // Wait for editor + scan list to load and Simulate button to appear.
    const run = await screen.findByTestId('policy-sim-run');
    fireEvent.click(run);
    await waitFor(() => expect(simMock).toHaveBeenCalledTimes(1));

    // The verdict chip surfaces the wouldBlock=true state.
    const verdict = await screen.findByTestId('policy-sim-verdict');
    expect(verdict.textContent).toMatch(/would block/i);

    // The violation shows up in the table.
    const violationRow = await screen.findByTestId('policy-sim-violations-tbody');
    expect(violationRow.textContent).toMatch(/no-new-weak-now/);
    expect(violationRow.textContent).toMatch(/currently weak/i);

    // The request body carried the edited policy from the textarea.
    const [base, head, policy] = simMock.mock.calls[0];
    expect(base).toBe('scan-a'); // second-newest by seed order
    expect(head).toBe('scan-b'); // newest
    expect(policy).not.toBeNull();
    expect((policy as { name: string }).name).toBe('blindspot-default');
  });
});
