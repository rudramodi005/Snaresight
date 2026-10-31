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
    window.location.href = '/app/overview';
  };

  render(): ReactNode {
    if (this.state.hasError) {
      const { fallbackTitle, fallbackMessage } = this.props;
      const { error, errorInfo } = this.state;

      return (
        <div className="min-h-[400px] flex items-center justify-center p-6 bg-[#000F08] text-[#FB3640] font-sans selection:bg-[#FB3640] selection:text-[#000F08]">
          <div className="w-full max-w-xl p-6 rounded-2xl bg-[#000F08] border border-[#FB3640]/30 shadow-crimson-lg space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-[#FB3640]/10 border border-[#FB3640]/30 flex items-center justify-center text-xl shrink-0 text-[#FB3640]">
                🛡️
              </div>
              <div>
                <h2 className="text-base font-bold text-[#FB3640] tracking-wide">
                  {fallbackTitle || 'Component Rendering Error'}
                </h2>
                <p className="text-xs text-[#FB3640]/70 mt-0.5">
                  {fallbackMessage ||
                    'An unexpected client-side error occurred while rendering this view. The application remains operational.'}
                </p>
              </div>
            </div>

            {error && (
              <div className="p-3 bg-[#000F08] rounded-xl border border-[#FB3640]/30 text-xs font-mono text-[#FB3640] break-all">
                <span className="text-[#FB3640]/60 select-none mr-2 font-bold">[Error]</span>
                {error.name}: {error.message}
              </div>
            )}

            {errorInfo && (
              <details className="text-[11px] text-[#FB3640]/70 bg-[#000F08] p-2.5 rounded-lg border border-[#FB3640]/20">
                <summary className="cursor-pointer text-[#FB3640]/80 hover:text-[#FB3640] select-none font-medium">
                  Technical Diagnostics & Stack Trace
                </summary>
                <pre className="mt-2 text-[10px] text-[#FB3640]/60 overflow-x-auto whitespace-pre-wrap font-mono p-2 bg-[#000F08] rounded border border-[#FB3640]/15">
                  {errorInfo.componentStack}
                </pre>
              </details>
            )}

            <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-[#FB3640]/20">
              <button
                type="button"
                onClick={this.handleReset}
                className="px-3.5 py-1.5 rounded-lg bg-[#FB3640] hover:bg-[#FB3640]/90 text-[#000F08] text-xs font-bold transition-all shadow-crimson-sm"
              >
                Retry Component
              </button>
              <button
                type="button"
                onClick={this.handleGoHome}
                className="px-3.5 py-1.5 rounded-lg bg-[#000F08] hover:bg-[#FB3640]/10 text-[#FB3640] text-xs font-semibold border border-[#FB3640]/30 transition-colors"
              >
                Return to Overview
              </button>
              <button
                type="button"
                onClick={this.handleReload}
                className="px-3.5 py-1.5 rounded-lg bg-[#000F08] hover:bg-[#FB3640]/10 text-[#FB3640]/70 hover:text-[#FB3640] text-xs font-medium border border-[#FB3640]/20 transition-colors ml-auto"
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

