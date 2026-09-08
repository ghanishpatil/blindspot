import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import App from '@/App';

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('Failed to fetch'));
});

describe('routing', () => {
  it('renders the public landing page with Blindspot branding', () => {
    renderAt('/');

    expect(screen.getAllByText('BLINDSPOT')[0]).toBeInTheDocument();
    expect(
      screen.getAllByText(/you cannot migrate cryptography/i)[0],
    ).toBeInTheDocument();
  });

  it('renders the login screen', () => {
    renderAt('/login');
    expect(screen.getByRole('heading', { name: /BLINDSPOT ECDAT/i })).toBeInTheDocument();
  });

  it('renders the dashboard inside the app shell', async () => {
    renderAt('/dashboard');

    expect(await screen.findByRole('heading', { name: /cryptographic posture/i })).toBeInTheDocument();
  });

  it('renders the findings table route', async () => {
    renderAt('/findings');
    expect(await screen.findByRole('heading', { name: /cryptographic findings/i })).toBeInTheDocument();
  });

  it('renders finding detail with the id from the route', async () => {
    renderAt('/findings/crypto-rsa-2048-001');

    const matches = await screen.findAllByText(/RSA-2048/i);
    expect(matches[0]).toBeInTheDocument();
  });

  it('renders a 404 for unknown routes', () => {
    renderAt('/does-not-exist');
    expect(screen.getByRole('heading', { name: /page not found/i })).toBeInTheDocument();
  });
});

describe('production ECDAT pipeline visualization', () => {
  it('renders planted cryptographic artefacts on the dashboard', async () => {
    renderAt('/dashboard');

    const matches = await screen.findAllByText(/RSA-2048/i);
    expect(matches[0]).toBeInTheDocument();
  });
});
