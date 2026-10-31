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
        <div className="min-h-[400px] flex items-center justify-center p-6 bg-[#181A2F] text-[#E2E8F0] font-sans selection:bg-[#B4182D] selection:text-white">
          <div className="w-full max-w-xl p-6 rounded-2xl bg-[#242E49] border border-[#37415C] shadow-crimson-lg space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-[#54162B] border border-[#B4182D] flex items-center justify-center text-xl shrink-0 text-[#FDA481]">
                🛡️
              </div>
              <div>
                <h2 className="text-base font-bold text-[#FDA481] tracking-wide">
                  {fallbackTitle || 'Component Rendering Error'}
                </h2>
                <p className="text-xs text-[#94A3B8] mt-0.5">
                  {fallbackMessage ||
                    'An unexpected client-side error occurred while rendering this view. The application remains operational.'}
                </p>
              </div>
            </div>

            {error && (
              <div className="p-3 bg-[#181A2F] rounded-xl border border-[#B4182D]/40 text-xs font-mono text-[#FDA481] break-all">
                <span className="text-[#B4182D] select-none mr-2 font-bold">[Error]</span>
                {error.name}: {error.message}
              </div>
            )}

            {errorInfo && (
              <details className="text-[11px] text-[#94A3B8] bg-[#181A2F] p-2.5 rounded-lg border border-[#37415C]">
                <summary className="cursor-pointer text-[#FDA481] hover:underline select-none font-medium">
                  Technical Diagnostics & Stack Trace
                </summary>
                <pre className="mt-2 text-[10px] text-[#94A3B8] overflow-x-auto whitespace-pre-wrap font-mono p-2 bg-[#181A2F] rounded border border-[#37415C]/60">
                  {errorInfo.componentStack}
                </pre>
              </details>
            )}

            <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-[#37415C]">
              <button
                type="button"
                onClick={this.handleReset}
                className="px-3.5 py-1.5 rounded-lg bg-[#B4182D] hover:bg-[#B4182D]/90 text-white text-xs font-bold transition-all shadow-crimson-sm"
              >
                Retry Component
              </button>
              <button
                type="button"
                onClick={this.handleGoHome}
                className="px-3.5 py-1.5 rounded-lg bg-[#181A2F] hover:bg-[#37415C]/50 text-[#FDA481] text-xs font-semibold border border-[#37415C] transition-colors"
              >
                Return to Overview
              </button>
              <button
                type="button"
                onClick={this.handleReload}
                className="px-3.5 py-1.5 rounded-lg bg-[#181A2F] hover:bg-[#37415C]/50 text-[#94A3B8] hover:text-[#FDA481] text-xs font-medium border border-[#37415C] transition-colors ml-auto"
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

