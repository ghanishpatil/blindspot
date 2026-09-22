import { describe, expect, it } from 'vitest';

import { parseTlsTargets } from '@/services/tlsTargets';

describe('parseTlsTargets', () => {
  it('returns an empty array when the input is empty or whitespace', () => {
    expect(parseTlsTargets('')).toEqual([]);
    expect(parseTlsTargets('   ')).toEqual([]);
    expect(parseTlsTargets('\n\t\r')).toEqual([]);
  });

  it('splits comma-separated tokens', () => {
    expect(parseTlsTargets('github.com, cloudflare.com, example.com')).toEqual([
      'github.com',
      'cloudflare.com',
      'example.com',
    ]);
  });

  it('splits newline-separated tokens', () => {
    expect(parseTlsTargets('github.com\ncloudflare.com\napi.example.com')).toEqual([
      'github.com',
      'cloudflare.com',
      'api.example.com',
    ]);
  });

  it('preserves host:port entries', () => {
    expect(parseTlsTargets('github.com:443, api.example.com:8443')).toEqual([
      'github.com:443',
      'api.example.com:8443',
    ]);
  });

  it('deduplicates repeated entries in first-seen order', () => {
    expect(
      parseTlsTargets('github.com, github.com, cloudflare.com, github.com'),
    ).toEqual(['github.com', 'cloudflare.com']);
  });

  it('tolerates a mix of separators and stray whitespace', () => {
    // Copy-paste from a spreadsheet often gives semicolons + trailing
    // whitespace. The parser must be forgiving so the demo does not fail
    // on cosmetics.
    expect(
      parseTlsTargets('  github.com ; cloudflare.com ,\n  api.example.com  '),
    ).toEqual(['github.com', 'cloudflare.com', 'api.example.com']);
  });

  it('does not validate hostnames -- validation is the backend contract', () => {
    // We deliberately do NOT reject 'not-a-host' or 'foo.com:not-a-port'
    // here because the backend `_parse_tls_target` and `validate_tls_target`
    // already do it. Duplicating that logic would drift.
    expect(parseTlsTargets('not-a-host, foo.com:not-a-port')).toEqual([
      'not-a-host',
      'foo.com:not-a-port',
    ]);
  });
});
