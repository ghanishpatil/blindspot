import React from 'react';

import type { RiskTier } from '@/types';

interface RiskBadgeProps {
  tier: RiskTier | 'weak-now' | 'unknown' | string | null;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
  className?: string;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({
  tier,
  size = 'md',
  showLabel = true,
  className = '',
}) => {
  const normalizedTier = (tier || 'unknown').toLowerCase();

  let bg = 'bg-slate-800/80 text-slate-300 border-slate-700';
  let dot = 'bg-slate-400';
  let label = 'Unknown Risk';

  if (normalizedTier === 'overdue' || normalizedTier === 'critical') {
    bg = 'bg-red-500/10 text-red-400 border-red-500/30';
    dot = 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]';
    label = 'Overdue';
  } else if (normalizedTier === 'transitional' || normalizedTier === 'warning') {
    bg = 'bg-amber-500/10 text-amber-400 border-amber-500/30';
    dot = 'bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.5)]';
    label = 'Transitional';
  } else if (normalizedTier === 'low-risk' || normalizedTier === 'low_risk' || normalizedTier === 'success') {
    bg = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
    dot = 'bg-emerald-500 shadow-[0_0_8px_rgba(34,197,94,0.5)]';
    label = 'Low Risk';
  } else if (normalizedTier === 'weak-now' || normalizedTier === 'weak_now') {
    bg = 'bg-rose-500/10 text-rose-400 border-rose-500/30';
    dot = 'bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.5)]';
    label = 'Weak Now';
  }

  const sizeClasses =
    size === 'sm'
      ? 'px-2 py-0.5 text-xs font-mono'
      : size === 'lg'
      ? 'px-3.5 py-1.5 text-sm font-semibold tracking-wide'
      : 'px-2.5 py-1 text-xs font-medium';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border ${sizeClasses} ${bg} ${className}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${dot}`} />
      {showLabel ? label : null}
    </span>
  );
};
