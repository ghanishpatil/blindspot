/**
 * KeyValue — a label/value row for metadata panels.
 *
 * Used in Finding Detail evidence panels, classification blocks, cost profile
 * grids, etc. The label is mono + muted so the value can breathe.
 */
import React from 'react';

interface KeyValueProps {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
  /** Split on a fixed left column instead of the default two-column flow. */
  align?: 'row' | 'stacked';
  className?: string;
}

export const KeyValue: React.FC<KeyValueProps> = ({
  label,
  value,
  mono = false,
  align = 'row',
  className = '',
}) => {
  if (align === 'stacked') {
    return (
      <div className={`flex flex-col gap-1 ${className}`}>
        <span className="eyebrow-muted">{label}</span>
        <span className={`${mono ? 'font-mono text-xs' : 'text-sm'} text-[color:var(--color-ink)]`}>
          {value}
        </span>
      </div>
    );
  }
  return (
    <div className={`flex items-baseline justify-between gap-4 border-b border-[color:var(--color-border-subtle)]/60 py-2 ${className}`}>
      <span className="eyebrow-muted whitespace-nowrap">{label}</span>
      <span className={`text-right ${mono ? 'font-mono text-xs' : 'text-sm'} text-[color:var(--color-ink)]`}>
        {value}
      </span>
    </div>
  );
};
