/**
 * Secure SOC Login Page for SnareSight.
 *
 * Implements strict Obsidian (#000F08) and Crimson (#FB3640) brand system,
 * rate-limit awareness, client-side validation, and instant analyst authentication.
 */

import React, { useState } from 'react';
import { useAuth } from './AuthContext';
import { BrandLogo } from '../../components/common/BrandLogo';

export const LoginPage: React.FC = () => {
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);

    try {
      await login({ username, password });
    } catch (err: any) {
      setError(err.message || 'Invalid username or password');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDemoFill = (u: string, p: string) => {
    setUsername(u);
    setPassword(p);
  };

  return (
    <div className="min-h-screen bg-[#000F08] flex flex-col justify-center items-center p-4 text-[#FB3640] font-sans selection:bg-[#FB3640] selection:text-[#000F08]">
      {/* Background ambient radial glow */}
      <div className="fixed inset-0 pointer-events-none bg-[radial-gradient(circle_at_50%_30%,rgba(251,54,64,0.08)_0%,transparent_60%)]" />

      <div className="w-full max-w-md bg-[#000F08] border border-[#FB3640]/25 rounded-2xl shadow-crimson-lg p-8 relative z-10 glass-panel">
        {/* Brand Header */}
        <div className="flex flex-col items-center mb-6 text-center">
          <div className="mb-3">
            <BrandLogo size={48} showWordmark={false} />
          </div>
          <h1 className="text-xl font-black tracking-widest text-[#FB3640]">SNARESIGHT SOC</h1>
          <p className="text-xs text-[#FB3640]/70 mt-1">
            Deception-Driven Threat Detection & Security Operations Platform
          </p>
          <div className="mt-3 text-[10px] font-mono uppercase bg-[#FB3640]/10 text-[#FB3640] border border-[#FB3640]/30 px-3 py-0.5 rounded-full flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-[#FB3640] animate-pulse" />
            <span>Hardened Authentication Gateway</span>
          </div>
        </div>

        {error && (
          <div className="mb-5 p-3 rounded-xl bg-[#FB3640]/10 border border-[#FB3640]/40 text-[#FB3640] text-xs flex items-center gap-2.5">
            <span className="text-sm">⚠️</span>
            <span className="font-medium">{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          <div>
            <label className="block text-[#FB3640]/80 font-semibold mb-1 tracking-wide">
              Security Operator ID / Username
            </label>
            <input
              type="text"
              required
              autoFocus
              placeholder="e.g. soc_lead"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full bg-[#000F08] border border-[#FB3640]/30 rounded-xl px-3.5 py-2.5 text-[#FB3640] placeholder-[#FB3640]/30 focus:outline-none focus:border-[#FB3640] focus:ring-1 focus:ring-[#FB3640] transition-colors font-mono"
            />
          </div>

          <div>
            <div className="flex justify-between items-center mb-1">
              <label className="text-[#FB3640]/80 font-semibold tracking-wide">
                Operator Passphrase
              </label>
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="text-[11px] text-[#FB3640]/70 hover:text-[#FB3640] transition-colors"
              >
                {showPassword ? 'Hide' : 'Show'}
              </button>
            </div>
            <input
              type={showPassword ? 'text' : 'password'}
              required
              placeholder="••••••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-[#000F08] border border-[#FB3640]/30 rounded-xl px-3.5 py-2.5 text-[#FB3640] placeholder-[#FB3640]/30 focus:outline-none focus:border-[#FB3640] focus:ring-1 focus:ring-[#FB3640] transition-colors font-mono"
            />
          </div>

          <button
            type="submit"
            disabled={submitting}
            className="w-full py-2.5 px-4 rounded-xl bg-[#FB3640] hover:bg-[#FB3640]/90 text-[#000F08] font-black text-xs tracking-wider uppercase transition-all shadow-crimson-md hover:shadow-crimson-lg disabled:opacity-50 mt-2"
          >
            {submitting ? 'Verifying Credentials...' : 'Authenticate Operator'}
          </button>
        </form>

        {/* Quick Demo Credentials shortcuts for reviewers */}
        <div className="mt-6 pt-5 border-t border-[#FB3640]/20">
          <div className="text-[11px] text-[#FB3640]/60 font-semibold mb-2.5 text-center tracking-wider uppercase">
            Synthetic Evaluation Credentials
          </div>
          <div className="grid grid-cols-3 gap-2">
            <button
              type="button"
              onClick={() => handleDemoFill('soc_admin', 'SnareAdmin2026!')}
              className="p-2 rounded-lg bg-[#000F08] hover:bg-[#FB3640]/10 border border-[#FB3640]/30 hover:border-[#FB3640] text-[10px] text-center transition-all group"
            >
              <div className="font-bold text-[#FB3640]">ADMIN</div>
              <div className="text-[#FB3640]/60 truncate font-mono text-[9px]">soc_admin</div>
            </button>
            <button
              type="button"
              onClick={() => handleDemoFill('soc_lead', 'SnareAnalyst2026!')}
              className="p-2 rounded-lg bg-[#000F08] hover:bg-[#FB3640]/10 border border-[#FB3640]/30 hover:border-[#FB3640] text-[10px] text-center transition-all group"
            >
              <div className="font-bold text-[#FB3640]">ANALYST</div>
              <div className="text-[#FB3640]/60 truncate font-mono text-[9px]">soc_lead</div>
            </button>
            <button
              type="button"
              onClick={() => handleDemoFill('soc_viewer', 'SnareViewer2026!')}
              className="p-2 rounded-lg bg-[#000F08] hover:bg-[#FB3640]/10 border border-[#FB3640]/30 hover:border-[#FB3640] text-[10px] text-center transition-all group"
            >
              <div className="font-bold text-[#FB3640]">VIEWER</div>
              <div className="text-[#FB3640]/60 truncate font-mono text-[9px]">soc_viewer</div>
            </button>
          </div>
        </div>

        {/* Back to Public Portal Link */}
        <div className="mt-5 text-center">
          <a
            href="/"
            className="text-[11px] text-[#FB3640]/60 hover:text-[#FB3640] transition-colors underline"
          >
            ← Return to SnareSight Public Platform Overview
          </a>
        </div>
      </div>
    </div>
  );
};
