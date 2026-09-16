/**
 * Stat — a labelled numerical statistic.
 *
 * Design choices:
 *   * Uses tabular mono numerals so the digit stack never jitters as values
 *     change (real-time refresh, filter toggles).
 *   * Optional accent bar on the left renders semantic colour when the metric
 *     itself is semantic (overdue count, hndl count, etc.).
 *   * No card-in-a-card: this is a leaf element. The caller decides the
 *     surrounding surface.
 */
import React from 'react';

import { Icon, type IconName } from '@/components/Icon';

type Accent = 'accent' | 'overdue' | 'transitional' | 'low-risk' | 'hndl' | 'muted';

interface StatProps {
  label: string;
  value: number | string;
  hint?: string;
  icon?: IconName;
  accent?: Accent;
  /** Compact variant is used inside strips; the default is used standalone. */
  size?: 'sm' | 'md' | 'lg';
}

const ACCENT: Record<Accent, { bar: string; text: string; ring: string }> = {
  accent: { bar: 'bg-[color:var(--color-accent)]', text: 'text-[color:var(--color-accent)]', ring: 'ring-[color:var(--color-accent)]/15' },
  overdue: { bar: 'bg-[#E85D5D]', text: 'text-[#E85D5D]', ring: 'ring-[#E85D5D]/15' },
  transitional: { bar: 'bg-[#E9A73A]', text: 'text-[#E9A73A]', ring: 'ring-[#E9A73A]/15' },
  'low-risk': { bar: 'bg-[#4FB37A]', text: 'text-[#4FB37A]', ring: 'ring-[#4FB37A]/15' },
  hndl: { bar: 'bg-[#B090F5]', text: 'text-[#B090F5]', ring: 'ring-[#B090F5]/15' },
  muted: { bar: 'bg-[color:var(--color-border-strong)]', text: 'text-[color:var(--color-ink)]', ring: 'ring-[color:var(--color-border-strong)]/40' },
};

const VALUE_SIZE = {
  sm: 'text-xl',
  md: 'text-2xl',
  lg: 'text-3xl',
};

export const Stat: React.FC<StatProps> = ({
  label,
  value,
  hint,
  icon,
  accent = 'muted',
  size = 'md',
}) => {
  const a = ACCENT[accent];
  return (
    <div className="relative flex flex-col gap-1 rounded-lg border border-[color:var(--color-border-subtle)] bg-[color:var(--color-panel)] px-4 py-3.5 overflow-hidden">
      {/* Accent bar — architectural, not decorative. */}
      <span className={`absolute inset-y-0 left-0 w-[3px] ${a.bar}`} aria-hidden="true" />
      <div className="flex items-center justify-between">
        <span className="eyebrow-muted">{label}</span>
        {icon ? <Icon name={icon} size={14} className={a.text} /> : null}
      </div>
      <span key={String(value)} className={`metric-value tick-in ${VALUE_SIZE[size]} ${a.text}`}>
        {value}
      </span>
      {hint ? <span className="text-[11px] text-[color:var(--color-ink-muted)]">{hint}</span> : null}
    </div>
  );
};
