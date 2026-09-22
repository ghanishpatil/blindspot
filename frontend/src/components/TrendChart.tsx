import { useEffect, useMemo, useState } from 'react';
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { Icon } from '@/components/Icon';
import { getScanTrend, type ScanTrendPoint } from '@/services/scansApi';

interface TrendChartProps {
  projectId: string;
  /**
   * Height in pixels of the chart canvas. Kept configurable so the same
   * component fits both a full-width dashboard section and a smaller
   * side panel.
   */
  height?: number;
}

type State =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ok'; points: ScanTrendPoint[] };

/**
 * Per-Risk_Tier trend across every scan of a project.
 *
 * Three lines: **overdue** (red), **transitional** (amber), **low-risk**
 * (green). Each dot is one scan. Reading left-to-right shows whether the
 * organisation's cryptographic posture is improving, stable, or
 * regressing over time -- the "trend-over-time" acceptance criterion in
 * PS Req 13.
 *
 * A trend with fewer than two points is informationally worthless (a
 * line needs two points), so the component surfaces an explicit empty
 * state rather than drawing a misleading single-dot line. This matches
 * the honesty rule the rest of the tool follows.
 */
export function TrendChart({ projectId, height = 260 }: TrendChartProps) {
  const [state, setState] = useState<State>({ kind: 'loading' });

  useEffect(() => {
    const controller = new AbortController();
    setState({ kind: 'loading' });
    getScanTrend(projectId, controller.signal)
      .then((res) => setState({ kind: 'ok', points: res.points }))
      .catch((err: unknown) => {
        if (controller.signal.aborted) {
          return;
        }
        setState({
          kind: 'error',
          message: err instanceof Error ? err.message : 'Trend unavailable.',
        });
      });
    return () => controller.abort();
  }, [projectId]);

  const chartData = useMemo(() => {
    if (state.kind !== 'ok') {
      return [];
    }
    // Format the timestamp for the X axis. Keep the raw value on the
    // record so the tooltip shows the full ISO string too.
    return state.points.map((p) => ({
      ...p,
      label: p.startedAt ? formatTick(p.startedAt) : '?',
    }));
  }, [state]);

  return (
    <section className="surface-panel p-6" data-testid="trend-chart">
      <div className="mb-4 flex flex-wrap items-baseline justify-between gap-3">
        <div>
          <div className="eyebrow">Trend</div>
          <h2 className="mt-1 text-lg font-semibold text-[color:var(--color-ink)]">
            Risk tier over time
          </h2>
          <p className="mt-1 max-w-2xl text-[11px] text-[color:var(--color-ink-muted)]">
            Each point is one scan of <span className="font-mono">{projectId}</span>. Reading
            left-to-right shows how the posture has shifted across runs.
          </p>
        </div>
        {state.kind === 'ok' ? (
          <span className="rounded border border-[color:var(--color-border-subtle)] bg-[color:var(--color-panel)] px-2 py-0.5 font-mono text-[10px] uppercase tracking-widest text-[color:var(--color-ink-muted)]">
            {state.points.length} scan{state.points.length === 1 ? '' : 's'}
          </span>
        ) : null}
      </div>

      {state.kind === 'loading' ? (
        <div
          className="flex items-center justify-center gap-2 text-[11px] text-[color:var(--color-ink-muted)]"
          style={{ height }}
        >
          <Icon name="refresh" size={14} className="animate-spin" />
          Loading trend…
        </div>
      ) : null}

      {state.kind === 'error' ? (
        <div
          className="flex flex-col items-center justify-center gap-1 text-center text-[11px] text-[color:var(--color-ink-muted)]"
          style={{ height }}
        >
          <Icon name="alert-triangle" size={16} className="text-amber-400" />
          <span>Trend unavailable: {state.message}</span>
        </div>
      ) : null}

      {state.kind === 'ok' && chartData.length < 2 ? (
        <div
          className="flex flex-col items-center justify-center gap-2 text-center text-[11px] text-[color:var(--color-ink-muted)]"
          style={{ height }}
          data-testid="trend-empty"
        >
          <Icon name="barchart" size={20} className="text-slate-500" />
          <p className="max-w-sm">
            A trend line needs at least two scans. Run another scan and this
            chart populates automatically.
          </p>
          <span className="font-mono text-[10px] uppercase tracking-widest text-[color:var(--color-ink-faint)]">
            {chartData.length} of &ge; 2 scans
          </span>
        </div>
      ) : null}

      {state.kind === 'ok' && chartData.length >= 2 ? (
        <div style={{ width: '100%', height }}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart
              data={chartData}
              margin={{ top: 8, right: 24, left: 0, bottom: 8 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
              <XAxis
                dataKey="label"
                stroke="#7C8595"
                tick={{ fontSize: 11 }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                stroke="#7C8595"
                tick={{ fontSize: 11 }}
                allowDecimals={false}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                contentStyle={{
                  background: '#0C1117',
                  border: '1px solid #222B35',
                  borderRadius: '6px',
                  fontSize: '11px',
                  color: '#E6EAF0',
                }}
                labelFormatter={(_label, payload) => {
                  const first = Array.isArray(payload) ? payload[0] : null;
                  const raw = first?.payload as ScanTrendPoint | undefined;
                  return raw?.startedAt ?? String(_label);
                }}
              />
              <Legend
                wrapperStyle={{ fontSize: '11px', color: '#B7BEC9' }}
                iconType="plainline"
              />
              <Line
                type="monotone"
                dataKey="overdue"
                stroke="#E85D5D"
                strokeWidth={2}
                dot={{ r: 3 }}
                name="Overdue"
              />
              <Line
                type="monotone"
                dataKey="transitional"
                stroke="#E9A73A"
                strokeWidth={2}
                dot={{ r: 3 }}
                name="Transitional"
              />
              <Line
                type="monotone"
                dataKey="lowRisk"
                stroke="#4FB37A"
                strokeWidth={2}
                dot={{ r: 3 }}
                name="Low-risk"
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      ) : null}
    </section>
  );
}

/**
 * Compact X-axis tick.
 *
 * Full ISO strings (`2026-09-07T10:31:00+00:00`) are too long to render on
 * the axis and get squashed together. We keep the local date + short
 * time so the chart stays readable at demo resolution.
 */
function formatTick(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return iso;
  }
  const day = date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  const time = date.toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
  return `${day} ${time}`;
}
