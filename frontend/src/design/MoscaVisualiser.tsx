/**
 * MoscaVisualiser — X + Y measured against Z on a shared timeline.
 *
 * Mosca's inequality is the project's conceptual centre. This component turns
 * the abstract equation into a spatial one: three years-long bars on a shared
 * horizontal scale, with the sum (X+Y) rendered as an aggregate against the
 * quantum horizon (Z). When the sum reaches or exceeds Z, the excess is
 * highlighted in tier colour — you can *see* the overdue margin.
 *
 * Real, unadorned math — no fabricated numbers, no decorative flourish. If Z
 * is set to a policy preset, its label is shown above the horizon marker so
 * the assumption is always visible.
 */
import React from 'react';

interface MoscaVisualiserProps {
  x: number;              // years
  y: number;              // years
  z: number;              // years
  zLabel?: string;        // e.g. "Demo default" | "India CII 2027"
  applicable?: boolean;   // false when Mosca does not apply (non-quantum-vulnerable)
  compact?: boolean;
}

function tierColour(margin: number): string {
  if (margin > 0) return '#E85D5D';       // overdue
  if (margin > -3) return '#E9A73A';      // transitional (within 3y of Z)
  return '#4FB37A';                        // low-risk
}

export const MoscaVisualiser: React.FC<MoscaVisualiserProps> = ({
  x,
  y,
  z,
  zLabel,
  applicable = true,
  compact = false,
}) => {
  const sum = x + y;
  const margin = sum - z;
  // Scale so the longer of (X+Y) or Z fills the track; add ~15% headroom to
  // keep the horizon marker visible when the sum is exactly Z.
  const domain = Math.max(sum, z) * 1.15 || 1;
  const pct = (n: number) => Math.max(0, Math.min(100, (n / domain) * 100));

  const overdue = applicable && margin > 0;
  const tint = applicable ? tierColour(margin) : '#8F98A6';

  return (
    <div className={`w-full ${compact ? '' : 'space-y-4'}`}>
      {/* Equation header */}
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <div className="flex items-baseline gap-2 font-mono text-sm text-[color:var(--color-ink)]">
          <span className="rounded bg-[color:var(--color-accent-soft)] px-1.5 py-0.5 text-[color:var(--color-accent)]">X = {x}y</span>
          <span className="text-[color:var(--color-ink-faint)]">+</span>
          <span className="rounded bg-[#B090F5]/15 px-1.5 py-0.5 text-[#B090F5]">Y = {y}y</span>
          <span className="text-[color:var(--color-ink-faint)]">{applicable ? (overdue ? '>' : '≤') : '·'}</span>
          <span className="rounded border border-[color:var(--color-border-strong)] px-1.5 py-0.5 text-[color:var(--color-ink)]">Z = {z}y</span>
        </div>
        {applicable ? (
          <span
            className="font-mono text-[11px] font-semibold uppercase tracking-widest"
            style={{ color: tint }}
          >
            {overdue ? `+${margin.toFixed(1)}y overdue` : `${Math.abs(margin).toFixed(1)}y of margin`}
          </span>
        ) : (
          <span className="font-mono text-[11px] font-semibold uppercase tracking-widest text-[color:var(--color-ink-muted)]">
            Mosca not applicable
          </span>
        )}
      </div>

      {/* Bars — three horizontal tracks against a shared timeline */}
      <div className="relative rounded-lg border border-[color:var(--color-border-subtle)] bg-[color:var(--color-panel)] p-4">
        {/* Timeline ticks */}
        <div className="mb-4 flex justify-between font-mono text-[10px] uppercase tracking-widest text-[color:var(--color-ink-faint)]">
          <span>Year 0</span>
          <span>Year {Math.round(domain)}</span>
        </div>

        <div className="space-y-3">
          {/* Row: X — data secrecy lifetime */}
          <MoscaBar
            label="X"
            sub="Data lifetime"
            widthPct={pct(x)}
            colour="var(--color-accent)"
            value={`${x} yr`}
          />
          {/* Row: Y — migration time */}
          <MoscaBar
            label="Y"
            sub="Migration time"
            widthPct={pct(y)}
            colour="#B090F5"
            value={`${y} yr`}
          />

          {/* Row: X + Y stacked against Z */}
          <div className="relative pt-2">
            <div className="mb-1 flex items-center justify-between font-mono text-[11px]">
              <span className="text-[color:var(--color-ink-muted)]">
                <span className="font-semibold text-[color:var(--color-ink)]">X + Y</span>
                <span className="ml-1 text-[color:var(--color-ink-faint)]">vs. Z</span>
              </span>
              <span className="text-[color:var(--color-ink-faint)]">{sum} yr {applicable ? (overdue ? '>' : '≤') : '·'} {z} yr</span>
            </div>
            <div className="relative h-3 overflow-hidden rounded-sm bg-[color:var(--color-canvas)] ring-1 ring-inset ring-[color:var(--color-border-subtle)]">
              {/* Threshold (Z) marker: a vertical rule cast across the bar. */}
              <div
                className="absolute inset-y-0 z-10 w-px bg-[color:var(--color-ink)] opacity-70"
                style={{ left: `${pct(z)}%` }}
              />
              {/* Filled aggregate — X + Y, coloured by the resulting margin. */}
              <div
                className="absolute inset-y-0 left-0 origin-left rounded-r-sm transition-[width] duration-700 ease-out"
                style={{
                  width: `${pct(sum)}%`,
                  background: `linear-gradient(90deg, ${tint} 0%, ${tint} 70%, ${tint}CC 100%)`,
                }}
              />
              {/* The overdue overflow — the portion of X+Y beyond Z. */}
              {overdue ? (
                <div
                  className="absolute inset-y-0 z-[5]"
                  style={{
                    left: `${pct(z)}%`,
                    width: `${pct(sum - z)}%`,
                    background:
                      'repeating-linear-gradient(-45deg, rgba(0,0,0,0.35), rgba(0,0,0,0.35) 2px, transparent 2px, transparent 6px)',
                  }}
                />
              ) : null}
            </div>
            {/* Z label under the marker */}
            <div className="relative mt-1 h-4">
              <span
                className="absolute -translate-x-1/2 whitespace-nowrap font-mono text-[10px] uppercase tracking-widest text-[color:var(--color-ink-muted)]"
                style={{ left: `${pct(z)}%` }}
              >
                Z = {z}y{zLabel ? ` · ${zLabel}` : ''}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

/** One horizontal bar row in the visualiser. */
const MoscaBar: React.FC<{
  label: string;
  sub: string;
  widthPct: number;
  colour: string;
  value: string;
}> = ({ label, sub, widthPct, colour, value }) => (
  <div>
    <div className="mb-1 flex items-center justify-between font-mono text-[11px]">
      <span>
        <span className="font-semibold text-[color:var(--color-ink)]">{label}</span>
        <span className="ml-1.5 text-[color:var(--color-ink-faint)]">· {sub}</span>
      </span>
      <span className="text-[color:var(--color-ink-muted)]">{value}</span>
    </div>
    <div className="h-2 overflow-hidden rounded-sm bg-[color:var(--color-canvas)] ring-1 ring-inset ring-[color:var(--color-border-subtle)]">
      <div
        className="h-full origin-left rounded-r-sm transition-[width] duration-700 ease-out"
        style={{ width: `${widthPct}%`, background: colour }}
      />
    </div>
  </div>
);
