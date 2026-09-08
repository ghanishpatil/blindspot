import type { ReactNode } from 'react';

interface PhaseNoticeProps {
  /** The build phase that implements this area, e.g. "Phase 11". */
  phase: string;
  title: string;
  children?: ReactNode;
}

/**
 * Honest placeholder for functionality whose phase has not landed.
 *
 * The specification is explicit that a static frontend with fabricated data
 * must not stand in for the real pipeline. So unbuilt screens say what is
 * missing and which phase delivers it, rather than showing sample findings that
 * a viewer could mistake for real output.
 */
export function PhaseNotice({ phase, title, children }: PhaseNoticeProps) {
  return (
    <section className="rounded-lg border border-dashed border-border-subtle bg-surface/50 p-6">
      <div className="flex items-center gap-3">
        <span className="rounded-full border border-brand/40 bg-brand/10 px-2.5 py-0.5 text-xs font-medium text-brand">
          {phase}
        </span>
        <h2 className="text-sm font-medium text-ink">{title}</h2>
      </div>
      {children ? (
        <div className="mt-3 text-sm leading-relaxed text-ink-muted">{children}</div>
      ) : null}
    </section>
  );
}
