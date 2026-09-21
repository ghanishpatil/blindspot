import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { RecommendationCard } from '@/components/RecommendationCard';
import type { LatencyProfile, Recommendation } from '@/types';

const _latency: LatencyProfile = {
  target: 'ML-DSA-65',
  keygenCycles: 210_000,
  encapsulateCycles: null,
  decapsulateCycles: null,
  signCycles: 530_000,
  verifyCycles: 179_000,
  classicalSignCycles: 100_000,
  classicalVerifyCycles: 350_000,
  classicalEncapsulateCycles: null,
  classicalDecapsulateCycles: null,
  handshakeExtraBytes: 3_500,
  handshakeExtraBytesSource: 'Cloudflare 2021 - handshake overhead',
  relativeLatency: 'moderate',
  summary: 'ML-DSA-65 sign is ~5x slower than ECDSA P-256 on the reference platform.',
  platformNote: 'Intel Skylake AVX2 - not measured on the scanned system.',
  basis: 'Reference-implementation benchmarks - not runtime latency measured on this system.',
  sources: ['CRYSTALS-Dilithium Round 3 submission'],
};

const _baseRecommendation: Recommendation = {
  strategy: 'PQC',
  algorithm: 'ML-DSA-65',
  parameterSet: 'ML-DSA-65 (NIST FIPS 204, Category 3)',
  rationale: 'ECDSA-256 used for certificate signing is overdue for quantum migration.',
  replaces: 'ECDSA-256',
  priority: 1,
  effort: 'high',
  migrationNotes: ['Verify ML-DSA-65 is supported by your deployment targets.'],
  references: ['NIST FIPS 204'],
  isQuantumRecommendation: true,
  costProfile: null,
  latencyProfile: _latency,
};

describe('RecommendationCard - Reference Latency panel', () => {
  it('renders the reference-latency heading when a latency profile is present', () => {
    render(<RecommendationCard recommendation={_baseRecommendation} />);
    expect(screen.getByText(/reference latency/i)).toBeInTheDocument();
  });

  it('renders every operation the profile carries', () => {
    render(<RecommendationCard recommendation={_baseRecommendation} />);
    // Exact-match on tile headers so the rationale prose (which mentions
    // 'signing') does not accidentally satisfy these assertions.
    expect(screen.getByText(/^Keygen$/)).toBeInTheDocument();
    expect(screen.getByText(/^Sign$/)).toBeInTheDocument();
    expect(screen.getByText(/^Verify$/)).toBeInTheDocument();
  });

  it('formats cycle counts with unit suffixes', () => {
    render(<RecommendationCard recommendation={_baseRecommendation} />);
    // 210_000 -> "210 k cyc", 530_000 -> "530 k cyc"
    expect(screen.getByText(/210 k cyc/)).toBeInTheDocument();
    expect(screen.getByText(/530 k cyc/)).toBeInTheDocument();
  });

  it('shows the classical baseline where the profile provides one', () => {
    render(<RecommendationCard recommendation={_baseRecommendation} />);
    // 100_000 -> "100 k cyc classical"
    expect(screen.getByText(/100 k cyc classical/)).toBeInTheDocument();
  });

  it('renders the platform-note disclaimer verbatim so the numbers cannot be confused with a local measurement', () => {
    render(<RecommendationCard recommendation={_baseRecommendation} />);
    expect(
      screen.getByText(/not measured on the scanned system/i),
    ).toBeInTheDocument();
  });

  it('renders the source citation as a chip', () => {
    render(<RecommendationCard recommendation={_baseRecommendation} />);
    expect(
      screen.getByText(/CRYSTALS-Dilithium Round 3 submission/i),
    ).toBeInTheDocument();
  });

  it('renders the handshake overhead source separately from the cycle-count source', () => {
    render(<RecommendationCard recommendation={_baseRecommendation} />);
    expect(
      screen.getByText(/Cloudflare 2021 - handshake overhead/i),
    ).toBeInTheDocument();
  });

  it('omits the panel entirely when no latency profile is provided', () => {
    render(
      <RecommendationCard
        recommendation={{ ..._baseRecommendation, latencyProfile: null }}
      />,
    );
    expect(screen.queryByText(/reference latency/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/CRYSTALS-Dilithium/i)).not.toBeInTheDocument();
  });
});
