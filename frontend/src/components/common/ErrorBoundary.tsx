import React, { Component, ErrorInfo, ReactNode } from 'react';

interface ErrorBoundaryProps {
  children: ReactNode;
  fallbackTitle?: string;
  fallbackMessage?: string;
  onReset?: () => void;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

/**
 * Robust React Error Boundary preventing application blank-screen crashes.
 * Displays a styled dark-theme fallback with SOC diagnostics and recovery options.
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
    };
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    console.error('SnareSight UI Error Boundary caught an unhandled exception:', error, errorInfo);
    this.setState({ errorInfo });
  }

  handleReset = (): void => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    if (this.props.onReset) {
      this.props.onReset();
    }
  };

  handleReload = (): void => {
    window.location.reload();
  };

  handleGoHome = (): void => {
    window.location.href = '/overview';
  };

  render(): ReactNode {
    if (this.state.hasError) {
      const { fallbackTitle, fallbackMessage } = this.props;
      const { error, errorInfo } = this.state;

      return (
        <div className="min-h-[400px] flex items-center justify-center p-6 bg-slate-950 text-slate-100 font-sans">
          <div className="w-full max-w-xl p-6 rounded-2xl bg-slate-900 border border-rose-500/30 shadow-2xl space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-xl shrink-0 text-rose-400">
                🛡️
              </div>
              <div>
                <h2 className="text-base font-bold text-slate-100 tracking-wide">
                  {fallbackTitle || 'Component Rendering Error'}
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  {fallbackMessage ||
                    'An unexpected client-side error occurred while rendering this view. The application remains operational.'}
                </p>
              </div>
            </div>

            {error && (
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 text-xs font-mono text-rose-300 break-all">
                <span className="text-slate-500 select-none mr-2 font-bold">[Error]</span>
                {error.name}: {error.message}
              </div>
            )}

            {errorInfo && (
              <details className="text-[11px] text-slate-400 bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80">
                <summary className="cursor-pointer text-slate-400 hover:text-slate-200 select-none font-medium">
                  Technical Diagnostics & Stack Trace
                </summary>
                <pre className="mt-2 text-[10px] text-slate-500 overflow-x-auto whitespace-pre-wrap font-mono p-2 bg-slate-950 rounded">
                  {errorInfo.componentStack}
                </pre>
              </details>
            )}

            <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-slate-800/80">
              <button
                type="button"
                onClick={this.handleReset}
                className="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium transition-colors"
              >
                Retry Component
              </button>
              <button
                type="button"
                onClick={this.handleGoHome}
                className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-colors"
              >
                Return to Overview
              </button>
              <button
                type="button"
                onClick={this.handleReload}
                className="px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 text-xs font-medium border border-slate-800 transition-colors ml-auto"
              >
                Reload Page
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

