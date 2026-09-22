/**
 * Pure parser for the TLS-targets input on the Scan page.
 *
 * The user types a free-form string; we split it on commas, newlines, and
 * whitespace, trim, drop empty tokens, and de-duplicate while preserving
 * first-occurrence order. Nothing here validates hostnames -- the backend
 * `POST /api/scan` boundary and the `_parse_tls_target` helper on the
 * server enforce the SSRF guard and the shape. Client-side validation
 * would only duplicate that logic and drift out of sync.
 *
 * Returned array is always safe to send verbatim as the `tls_targets`
 * field on the scan request. When the input is empty or all-whitespace,
 * an empty array is returned so callers can conditionally omit the key.
 */
export function parseTlsTargets(input: string): string[] {
  if (!input) {
    return [];
  }
  const seen = new Set<string>();
  const out: string[] = [];
  // Split on any run of commas, semicolons, whitespace, or line breaks so
  // the demo copy-paste flow (`github.com, cloudflare.com:443\napi.example.com`)
  // just works.
  for (const raw of input.split(/[,;\s]+/g)) {
    const token = raw.trim();
    if (!token) {
      continue;
    }
    if (seen.has(token)) {
      continue;
    }
    seen.add(token);
    out.push(token);
  }
  return out;
}
