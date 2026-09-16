/**
 * RiskChip — a small semantic tier label.
 *
 * Deliberately compact and monospaced. Colour comes from tier semantics only,
 * never from styling whim. Used across findings tables, cards, and headers so
 * a tier reads the same everywhere.
 */
import React from 'react';

import type { RiskTier } from '@/types';

type TierLike = RiskTier | 'weak-now' | 'unknown' | null | undefined;

interface RiskChipProps {
  tier: TierLike;
  /** Show tier as a soft chip; false renders as an inline dot + label. */
  soft?: boolean;
  size?: 'sm' | 'md';
  className?: string;
}

const CONFIG: Record<string, { label: string; text: string; bg: string; dot: string; ring: string }> = {
  overdue: {
    label: 'Overdue',
    text: 'text-[#E85D5D]',
    bg: 'bg-[color:var(--color-overdue-soft)]',
    ring: 'ring-1 ring-inset ring-[#E85D5D]/25',
    dot: 'bg-[#E85D5D]',
  },
  transitional: {
    label: 'Transitional',
    text: 'text-[#E9A73A]',
    bg: 'bg-[color:var(--color-transitional-soft)]',
    ring: 'ring-1 ring-inset ring-[#E9A73A]/25',
    dot: 'bg-[#E9A73A]',
  },
  'low-risk': {
    label: 'Low-risk',
    text: 'text-[#4FB37A]',
    bg: 'bg-[color:var(--color-low-risk-soft)]',
    ring: 'ring-1 ring-inset ring-[#4FB37A]/25',
    dot: 'bg-[#4FB37A]',
  },
  'weak-now': {
    label: 'Weak now',
    text: 'text-[#EB6480]',
    bg: 'bg-[#EB6480]/10',
    ring: 'ring-1 ring-inset ring-[#EB6480]/25',
    dot: 'bg-[#EB6480]',
  },
  unknown: {
    label: 'Unknown',
    text: 'text-[color:var(--color-ink-muted)]',
    bg: 'bg-[color:var(--color-border-subtle)]/40',
    ring: 'ring-1 ring-inset ring-[color:var(--color-border-strong)]/40',
    dot: 'bg-[color:var(--color-ink-muted)]',
  },
};

export const RiskChip: React.FC<RiskChipProps> = ({ tier, soft = true, size = 'sm', className = '' }) => {
  const key = tier ?? 'unknown';
  const cfg = CONFIG[key] ?? CONFIG.unknown;

  if (!soft) {
    return (
      <span className={`inline-flex items-center gap-1.5 font-mono ${size === 'md' ? 'text-xs' : 'text-[11px]'} ${cfg.text} ${className}`}>
        <span className={`h-1.5 w-1.5 rounded-full ${cfg.dot}`} />
        {cfg.label}
      </span>
    );
  }

  const padding = size === 'md' ? 'px-2.5 py-1 text-xs' : 'px-2 py-0.5 text-[11px]';
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md font-mono font-semibold uppercase tracking-wider ${padding} ${cfg.bg} ${cfg.text} ${cfg.ring} ${className}`}
    >
      <span className={`h-1 w-1 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  );
};
