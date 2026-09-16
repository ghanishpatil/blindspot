/**
 * SectionEyebrow — the small kicker above section titles.
 *
 * Two visual jobs: (1) a subtle vertical line accent on the left tying the
 * eyebrow to the rest of the section, (2) monospace + wide tracking so it
 * reads as a section label, not decorative text.
 */
import React from 'react';

interface SectionEyebrowProps {
  children: React.ReactNode;
  align?: 'left' | 'center';
  accent?: 'accent' | 'hndl' | 'overdue' | 'muted';
}

const ACCENT: Record<string, string> = {
  accent: 'text-[color:var(--color-accent)] before:bg-[color:var(--color-accent)]',
  hndl: 'text-[#B090F5] before:bg-[#B090F5]',
  overdue: 'text-[#E85D5D] before:bg-[#E85D5D]',
  muted: 'text-[color:var(--color-ink-muted)] before:bg-[color:var(--color-border-strong)]',
};

export const SectionEyebrow: React.FC<SectionEyebrowProps> = ({ children, align = 'left', accent = 'accent' }) => (
  <span
    className={`
      relative inline-flex items-center pl-3
      font-mono text-[11px] font-semibold uppercase tracking-[0.16em]
      before:absolute before:left-0 before:top-1/2 before:h-[10px] before:w-[2px] before:-translate-y-1/2
      ${ACCENT[accent]}
      ${align === 'center' ? 'mx-auto' : ''}
    `}
  >
    {children}
  </span>
);
