/**
 * ExportReportButtons component tests.
 *
 * Verifies three properties that make the component honest:
 *
 * 1. All three PS-standardised formats (HTML, PDF, CSV) are rendered as
 *    reachable controls -- the deliverable line calls out multiple formats,
 *    so a UI showing only one would fail the wording.
 * 2. Clicking a format dispatches `downloadReport` with the right args.
 * 3. Backend errors -- most importantly the 503 that means "no headless
 *    browser installed" -- surface verbatim in the UI rather than swallow.
 */

import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { ExportReportButtons } from '@/components/ExportReportButtons';
import * as api from '@/services/api';

describe('ExportReportButtons', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('renders one clickable chip for each standardised format', () => {
    render(<ExportReportButtons />);

    // Each chip is a real button with an accessible label.
    expect(screen.getByRole('button', { name: /html/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /pdf/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /csv/i })).toBeInTheDocument();
  });

  it.each(['html', 'pdf', 'csv'] as const)(
    'dispatches downloadReport with format=%s and the given scan id',
    async (format) => {
      const spy = vi.spyOn(api, 'downloadReport').mockResolvedValue(undefined);
      render(<ExportReportButtons scanId="scan-77" />);

      fireEvent.click(screen.getByRole('button', { name: new RegExp(format, 'i') }));

      await waitFor(() => expect(spy).toHaveBeenCalledTimes(1));
      expect(spy).toHaveBeenCalledWith('scan-77', format);
    },
  );

  it('surfaces backend errors inline rather than swallowing them', async () => {
    vi.spyOn(api, 'downloadReport').mockRejectedValue(
      new api.ApiError(
        'No Chrome, Chromium, or Edge binary was found on PATH.',
        503,
        null,
      ),
    );

    render(<ExportReportButtons />);
    fireEvent.click(screen.getByRole('button', { name: /pdf/i }));

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(/no chrome, chromium, or edge/i);
  });
});
