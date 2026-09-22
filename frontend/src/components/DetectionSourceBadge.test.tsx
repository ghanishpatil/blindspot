/**
 * Contract of DetectionSourceBadge + RotationChip.
 *
 * 1. Every backend detection_method value renders with a distinct label.
 * 2. Cloud-KMS methods render a rotation chip that parses the state from
 *    the evidence code_snippet -- and only cloud-KMS methods.
 * 3. Unknown methods degrade to a readable label rather than crashing.
 * 4. The rotation chip surfaces the state (enabled / disabled / n/a).
 */

import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import {
  DetectionSourceBadge,
  RotationChip,
} from '@/components/DetectionSourceBadge';
import type { DetectionMethod } from '@/types';

describe('DetectionSourceBadge', () => {
  const cases: [DetectionMethod, RegExp][] = [
    ['aws_kms_attested', /aws kms/i],
    ['azure_kv_attested', /azure kv/i],
    ['gcp_kms_attested', /gcp kms/i],
    ['pkcs11_attested', /hsm/i],
    ['tls_probe', /live tls/i],
    ['static_cert_file', /on-disk cert/i],
    ['static_key_material', /on-disk key/i],
    ['static_keystore', /keystore/i],
    ['infra_declaration', /declared/i],
    ['config_policy_declared', /config policy/i],
    ['semgrep_api_pattern', /source \(ast\)/i],
    ['dependency_manifest', /manifest/i],
    ['binary_signature', /binary/i],
  ];

  it.each(cases)('renders %s as a distinct label', (method, label) => {
    render(<DetectionSourceBadge method={method} />);
    expect(screen.getByRole('note')).toHaveTextContent(label);
  });

  it('sets a data attribute for the raw method (used by CSS / scans)', () => {
    render(<DetectionSourceBadge method="aws_kms_attested" />);
    expect(screen.getByRole('note')).toHaveAttribute(
      'data-detection-method',
      'aws_kms_attested',
    );
  });

  it('does not crash on a null / unknown method', () => {
    render(<DetectionSourceBadge method={null} />);
    // Falls through to the Unknown descriptor.
    expect(screen.getByRole('note')).toHaveTextContent(/unknown/i);
  });

  it('prettifies an unrecognised future backend value', () => {
    render(<DetectionSourceBadge method={'future_thing_attested' as DetectionMethod} />);
    expect(screen.getByRole('note')).toHaveTextContent(/future thing attested/i);
  });
});

describe('RotationChip', () => {
  it('shows rotation enabled for AWS KMS findings with enabled state', () => {
    render(
      <RotationChip
        method="aws_kms_attested"
        codeSnippet="aws-kms key_id=abc rotation=enabled"
      />,
    );
    expect(screen.getByRole('note')).toHaveTextContent(/rotation enabled/i);
    expect(screen.getByRole('note')).toHaveAttribute('data-rotation-state', 'enabled');
  });

  it('shows rotation disabled for Azure KV findings with disabled state', () => {
    render(
      <RotationChip
        method="azure_kv_attested"
        codeSnippet="azure-kv name=x rotation=disabled"
      />,
    );
    expect(screen.getByRole('note')).toHaveTextContent(/rotation disabled/i);
  });

  it('shows rotation n/a for GCP KMS findings whose rotation is not applicable', () => {
    render(
      <RotationChip
        method="gcp_kms_attested"
        codeSnippet="gcp-kms name=x rotation=n/a"
      />,
    );
    expect(screen.getByRole('note')).toHaveTextContent(/rotation n\/a/i);
  });

  it('renders nothing for non-cloud-KMS findings', () => {
    // Even if the snippet contains a rotation phrase, we do not want the
    // chip on source or TLS findings -- the concept does not apply there.
    const { container: c1 } = render(
      <RotationChip
        method="tls_probe"
        codeSnippet="rotation=enabled (shouldn't matter)"
      />,
    );
    expect(c1.querySelector('[data-rotation-state]')).toBeNull();

    const { container: c2 } = render(
      <RotationChip
        method="semgrep_api_pattern"
        codeSnippet="rsa.generate(2048)"
      />,
    );
    expect(c2.querySelector('[data-rotation-state]')).toBeNull();
  });

  it('renders nothing when the cloud-KMS snippet has no rotation phrase', () => {
    // Older backend snippets that predate the F1 rotation-status addition.
    const { container } = render(
      <RotationChip
        method="aws_kms_attested"
        codeSnippet="aws-kms key_id=abc spec=SYMMETRIC_DEFAULT"
      />,
    );
    expect(container.querySelector('[data-rotation-state]')).toBeNull();
  });
});
