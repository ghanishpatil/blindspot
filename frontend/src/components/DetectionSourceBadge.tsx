import type { DetectionMethod } from '@/types';

/**
 * Compact colour-coded pill labelling *where* a finding came from.
 *
 * Every finding in Blindspot carries a `detection_method` -- the honest
 * label for the discovery source that produced it. The dashboard used to
 * hide this in a tooltip; that let cloud-KMS and live-TLS attestations
 * blend in with plain source-code hits, which erased one of the
 * strongest differentiators.
 *
 * This component renders that label prominently on every row and on the
 * finding detail hero. Colours are deliberately spread across the palette
 * so a user scanning a long list can pattern-match without reading text.
 *
 * The map covers every enum value the backend emits. An unknown value
 * still renders (as `Unknown`) rather than throwing, so a future backend
 * addition never breaks the frontend.
 */

interface DetectionSourceBadgeProps {
  method: DetectionMethod | string | null | undefined;
  /**
   * Compact variant used inside the findings table (tight cells).
   * Otherwise the default (`md`) is used on the detail hero.
   */
  size?: 'sm' | 'md';
  className?: string;
}

interface Descriptor {
  label: string;
  tone: string; // Tailwind class fragment for background + text + border
  title: string;
}

const DESCRIPTORS: Record<string, Descriptor> = {
  // Live cloud KMS attestation -- the differentiator badges.
  aws_kms_attested: {
    label: 'AWS KMS',
    tone: 'border-orange-500/40 bg-orange-500/10 text-orange-300',
    title:
      "Live AWS KMS attestation: algorithm, key size, and rotation configuration read straight from the account via boto3 DescribeKey.",
  },
  azure_kv_attested: {
    label: 'Azure KV',
    tone: 'border-sky-500/40 bg-sky-500/10 text-sky-300',
    title:
      "Live Azure Key Vault attestation: JWK payload read via azure-keyvault-keys. HSM-backed keys additionally tagged as hardware modules.",
  },
  gcp_kms_attested: {
    label: 'GCP KMS',
    tone: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300',
    title:
      "Live GCP Cloud KMS attestation: CryptoKeyVersion algorithm enum + rotation period read via google-cloud-kms.",
  },
  pkcs11_attested: {
    label: 'HSM · PKCS#11',
    tone: 'border-purple-500/40 bg-purple-500/10 text-purple-300',
    title:
      "Live PKCS#11 attestation: CKA_KEY_TYPE, CKA_MODULUS_BITS, and CKA_EC_PARAMS read from a real HSM token.",
  },

  // Live network / disk evidence.
  tls_probe: {
    label: 'Live TLS',
    tone: 'border-cyan-500/40 bg-cyan-500/10 text-cyan-300',
    title:
      "Observed live over the network from a TLS handshake. The negotiated protocol and the presented certificate's public-key algorithm flow through the same risk pipeline as source findings.",
  },
  static_cert_file: {
    label: 'On-disk cert',
    tone: 'border-slate-500/40 bg-slate-500/10 text-slate-300',
    title:
      "Certificate parsed from a PEM/DER file at rest in the repository -- algorithm read straight from the encoded structure with cryptography.x509.",
  },
  static_key_material: {
    label: 'On-disk key',
    tone: 'border-slate-500/40 bg-slate-500/10 text-slate-300',
    title:
      "Private or public key material parsed from a file / inline PEM block. Algorithm read directly from the encoded key.",
  },
  static_keystore: {
    label: 'Keystore',
    tone: 'border-zinc-500/40 bg-zinc-500/10 text-zinc-300',
    title:
      "Password-protected keystore (PKCS#12 / JKS). Existence proves the surface; contents remain unresolved until unlocked.",
  },

  // Static declaration signals.
  infra_declaration: {
    label: 'Declared',
    tone: 'border-teal-500/40 bg-teal-500/10 text-teal-300',
    title:
      "IaC / SDK declaration of an HSM / KMS surface. Proves the surface exists; the exact algorithm still needs attested verification.",
  },
  config_policy_declared: {
    label: 'Config policy',
    tone: 'border-indigo-500/40 bg-indigo-500/10 text-indigo-300',
    title:
      "Cipher / protocol / KEX / MAC policy declared in a config file (nginx, sshd, openssl.cnf, java.security...). What the admin asked for; live probing proves what the server actually negotiates.",
  },

  // Source / dependency / binary.
  semgrep_api_pattern: {
    label: 'Source (AST)',
    tone: 'border-blue-500/40 bg-blue-500/10 text-blue-300',
    title:
      "Direct call to a known cryptographic API, matched by a Semgrep rule against the parsed AST. Highest confidence for source findings.",
  },
  semgrep_ast_confirmed: {
    label: 'Source (AST)',
    tone: 'border-blue-500/40 bg-blue-500/10 text-blue-300',
    title:
      "Pattern confirmed against the syntax tree, not just text.",
  },
  semgrep_string_match: {
    label: 'Source (string)',
    tone: 'border-blue-500/30 bg-blue-500/10 text-blue-200',
    title:
      "Textual match only. Lower confidence -- may be a comment or a variable name; routed for verification.",
  },
  dependency_manifest: {
    label: 'Manifest',
    tone: 'border-fuchsia-500/40 bg-fuchsia-500/10 text-fuchsia-300',
    title:
      "Declared dependency known to provide the primitive. Proves capability, not use.",
  },
  binary_signature: {
    label: 'Binary',
    tone: 'border-rose-500/40 bg-rose-500/10 text-rose-300',
    title:
      "Fingerprint match against a compiled binary (crypto constants / OIDs / library strings). Heuristic -- routed for verification.",
  },
  config_inference: {
    label: 'Config',
    tone: 'border-amber-500/40 bg-amber-500/10 text-amber-300',
    title:
      "Inferred from configuration rather than observed in code.",
  },
  unknown: {
    label: 'Unknown',
    tone: 'border-slate-500/40 bg-slate-500/10 text-slate-400',
    title: 'Detection method not recorded.',
  },
};

export function DetectionSourceBadge({
  method,
  size = 'md',
  className = '',
}: DetectionSourceBadgeProps) {
  const key = (method ?? 'unknown').toString();
  const descriptor = DESCRIPTORS[key] ?? {
    label: prettifyUnknown(key),
    tone: DESCRIPTORS.unknown.tone,
    title: `Detection method: ${key}`,
  };

  const sizing =
    size === 'sm'
      ? 'px-1.5 py-0.5 text-[10px]'
      : 'px-2 py-0.5 text-[11px]';

  return (
    <span
      role="note"
      title={descriptor.title}
      className={`inline-flex items-center gap-1 rounded border font-mono font-semibold uppercase tracking-widest ${descriptor.tone} ${sizing} ${className}`}
      data-detection-method={key}
    >
      {descriptor.label}
    </span>
  );
}

/**
 * Cloud-KMS-only rotation-state chip.
 *
 * Backends encode the rotation state in the evidence snippet as
 * `rotation=enabled | disabled | n/a`. We parse it out and render a
 * dedicated pill only for the three cloud-KMS detection methods -- the
 * only sources that report rotation. Everything else returns null so
 * the row does not gain a meaningless chip.
 */
interface RotationChipProps {
  method: DetectionMethod | string | null | undefined;
  codeSnippet: string | null | undefined;
  size?: 'sm' | 'md';
}

const CLOUD_KMS_METHODS = new Set([
  'aws_kms_attested',
  'azure_kv_attested',
  'gcp_kms_attested',
]);

const ROTATION_RE = /rotation=(enabled|disabled|n\/a)/i;

export function RotationChip({ method, codeSnippet, size = 'md' }: RotationChipProps) {
  const key = (method ?? '').toString();
  if (!CLOUD_KMS_METHODS.has(key)) {
    return null;
  }
  if (!codeSnippet) {
    return null;
  }
  const match = codeSnippet.match(ROTATION_RE);
  if (!match) {
    return null;
  }
  const state = match[1].toLowerCase();

  const tone =
    state === 'enabled'
      ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
      : state === 'disabled'
        ? 'border-red-500/40 bg-red-500/10 text-red-300'
        : 'border-slate-500/40 bg-slate-500/10 text-slate-400';

  const label = state === 'n/a' ? 'rotation n/a' : `rotation ${state}`;

  const sizing =
    size === 'sm'
      ? 'px-1.5 py-0.5 text-[10px]'
      : 'px-2 py-0.5 text-[11px]';

  return (
    <span
      role="note"
      title="AWS KMS / Azure Key Vault / GCP KMS key-rotation configuration, read straight from the vendor's API."
      className={`inline-flex items-center rounded border font-mono font-semibold uppercase tracking-widest ${tone} ${sizing}`}
      data-rotation-state={state}
    >
      {label}
    </span>
  );
}

function prettifyUnknown(key: string): string {
  return key
    .split('_')
    .map((s) => s.charAt(0).toUpperCase() + s.slice(1))
    .join(' ');
}
