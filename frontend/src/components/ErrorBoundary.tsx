import React from 'react';

interface Props {
  children: React.ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

/**
 * Top-level React error boundary.
 *
 * Any render-time exception in the tree below this component gets caught and
 * rendered as a friendly panel instead of a blank white page. Without this,
 * one uncaught `TypeError` in a leaf component unmounts the entire app and the
 * demo dies silently in front of judges.
 */
export class ErrorBoundary extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo): void {
    // Keep this in the console so we can grab the real stack from DevTools.
    // eslint-disable-next-line no-console
    console.error('[Blindspot ErrorBoundary]', error, info);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  handleReload = () => {
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#080B0F] p-6 text-slate-100">
          <div className="mx-auto max-w-2xl rounded-xl border border-red-500/40 bg-red-500/5 p-6 mt-16">
            <div className="flex items-center gap-2">
              <span className="h-3 w-3 rounded-full bg-red-400" />
              <h1 className="text-lg font-semibold text-red-400">
                Something threw in the UI
              </h1>
            </div>
            <p className="mt-3 text-sm text-slate-300">
              A component crashed while rendering. The backend may be fine — this
              is a client-side error. Open the browser console for the exact
              stack trace.
            </p>
            <pre className="mt-4 max-h-64 overflow-auto rounded bg-black/40 p-3 font-mono text-[11px] text-red-300">
              {this.state.error?.message ?? 'Unknown error'}
              {this.state.error?.stack ? `\n\n${this.state.error.stack}` : ''}
            </pre>
            <div className="mt-4 flex flex-wrap gap-2">
              <button
                type="button"
                onClick={this.handleReset}
                className="rounded-md border border-slate-600 bg-slate-800 px-4 py-2 text-xs font-semibold text-slate-100 hover:border-slate-500"
              >
                Try again
              </button>
              <button
                type="button"
                onClick={this.handleReload}
                className="rounded-md border border-[#7DB7E8]/40 bg-[#7DB7E8]/10 px-4 py-2 text-xs font-semibold text-[#7DB7E8] hover:bg-[#7DB7E8]/20"
              >
                Reload page
              </button>
              <a
                href="/"
                className="rounded-md border border-slate-700 px-4 py-2 text-xs font-semibold text-slate-300 hover:border-slate-500 hover:text-white"
              >
                Return to landing
              </a>
            </div>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
