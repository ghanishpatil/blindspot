/**
 * CbomInteropDiff contract:
 *
 * 1. Both slots start empty; Run button is disabled.
 * 2. Uploading valid JSON in both slots enables Run.
 * 3. Clicking Run posts the parsed JSON as {base, head} and renders
 *    the returned diff with counts + changed rows.
 * 4. Invalid JSON in a slot shows an inline error and keeps Run disabled.
 * 5. Backend error surfaces in an inline banner.
 */

import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { CbomInteropDiff } from '@/components/CbomInteropDiff';
import * as api from '@/services/cbomInteropApi';

function makeFile(name: string, contents: string): File {
  return new File([contents], name, { type: 'application/json' });
}

function makeResponse(): api.CbomInteropDiffResponse {
  return {
    schemaVersion: 'blindspot.cbom.interop.v1',
    base: {
      specVersion: '1.6',
      timestamp: null,
      componentCount: 1,
      cryptoAssetCount: 1,
      tools: ['Blindspot'],
    },
    head: {
      specVersion: '1.6',
      timestamp: null,
      componentCount: 1,
      cryptoAssetCount: 1,
      tools: ['IBM CBOMkit'],
    },
    counts: { added: 0, removed: 0, changed: 1, unchanged: 0 },
    added: [],
    removed: [],
    changed: [
      {
        name: 'RSA-2048',
        base: {
          bomRef: null,
          name: 'RSA-2048',
          primitive: 'pke',
          parameterSetIdentifier: '2048',
          curve: null,
          mode: null,
          tier: null,
        },
        head: {
          bomRef: null,
          name: 'RSA-2048',
          primitive: 'pke',
          parameterSetIdentifier: '3072',
          curve: null,
          mode: null,
          tier: null,
        },
        changes: { parameter_set_identifier: { from: '2048', to: '3072' } },
        changeClasses: ['parameter_changed'],
      },
    ],
  };
}

describe('CbomInteropDiff', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('starts with Run disabled until both slots are populated', () => {
    render(<CbomInteropDiff />);
    const run = screen.getByTestId('cbom-diff-run') as HTMLButtonElement;
    expect(run.disabled).toBe(true);
  });

  it('shows an inline slot error when a file is not JSON', async () => {
    render(<CbomInteropDiff />);
    const input = screen.getByTestId('cbom-slot-base-input') as HTMLInputElement;
    const bad = makeFile('bad.json', 'not-json');
    fireEvent.change(input, { target: { files: [bad] } });
    const err = await screen.findByTestId('cbom-slot-base-error');
    expect(err.textContent).toMatch(/parse|json/i);
    const run = screen.getByTestId('cbom-diff-run') as HTMLButtonElement;
    expect(run.disabled).toBe(true);
  });

  it('runs the diff and renders the result table when both slots parse', async () => {
    const diffSpy = vi.spyOn(api, 'diffCboms').mockResolvedValue(makeResponse());
    render(<CbomInteropDiff />);

    const baseInput = screen.getByTestId('cbom-slot-base-input') as HTMLInputElement;
    const headInput = screen.getByTestId('cbom-slot-head-input') as HTMLInputElement;

    fireEvent.change(baseInput, {
      target: {
        files: [makeFile('base.json', JSON.stringify({ specVersion: '1.6' }))],
      },
    });
    fireEvent.change(headInput, {
      target: {
        files: [makeFile('head.json', JSON.stringify({ specVersion: '1.6' }))],
      },
    });

    // Filenames rendered.
    await screen.findByTestId('cbom-slot-base-filename');
    await screen.findByTestId('cbom-slot-head-filename');

    const run = screen.getByTestId('cbom-diff-run') as HTMLButtonElement;
    await waitFor(() => expect(run.disabled).toBe(false));
    fireEvent.click(run);

    await waitFor(() => expect(diffSpy).toHaveBeenCalledTimes(1));
    const [base, head] = diffSpy.mock.calls[0];
    expect(base).toEqual({ specVersion: '1.6' });
    expect(head).toEqual({ specVersion: '1.6' });

    // Changed table renders with one RSA-2048 row.
    const result = await screen.findByTestId('cbom-diff-result');
    expect(result.textContent).toMatch(/RSA-2048/);
    expect(result.textContent).toMatch(/parameter/i);
  });

  it('surfaces backend error as an inline banner', async () => {
    vi.spyOn(api, 'diffCboms').mockRejectedValue(new Error('interop diff failed'));
    render(<CbomInteropDiff />);
    const baseInput = screen.getByTestId('cbom-slot-base-input') as HTMLInputElement;
    const headInput = screen.getByTestId('cbom-slot-head-input') as HTMLInputElement;
    fireEvent.change(baseInput, {
      target: { files: [makeFile('a.json', '{}')] },
    });
    fireEvent.change(headInput, {
      target: { files: [makeFile('b.json', '{}')] },
    });
    const run = await screen.findByTestId('cbom-diff-run');
    await waitFor(() => expect((run as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(run);
    const err = await screen.findByTestId('cbom-diff-error');
    expect(err.textContent).toMatch(/interop diff failed/i);
  });
});
