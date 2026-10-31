/**
 * Secure SOC Login Page for SnareSight.
 *
 * Implements sophisticated security color palette:
 * #181A2F (Midnight), #242E49 (Dark Slate), #37415C (Muted Slate),
 * #FDA481 (Peach Coral), #B4182D (Crimson), #54162B (Maroon Wine).
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
    <div className="min-h-screen bg-[#181A2F] flex flex-col justify-center items-center p-4 text-[#E2E8F0] font-sans selection:bg-[#B4182D] selection:text-white">
      {/* Background ambient radial glow */}
      <div className="fixed inset-0 pointer-events-none bg-[radial-gradient(circle_at_50%_30%,rgba(180,24,45,0.12)_0%,transparent_60%)]" />

      <div className="w-full max-w-md bg-[#242E49] border border-[#37415C] rounded-2xl shadow-2xl p-8 relative z-10 glass-panel">
        {/* Brand Header */}
        <div className="flex flex-col items-center mb-6 text-center">
          <div className="mb-3">
            <BrandLogo size={48} showWordmark={false} />
          </div>
          <h1 className="text-xl font-black tracking-widest text-white">SNARESIGHT SOC</h1>
          <p className="text-xs text-[#94A3B8] mt-1">
            Deception-Driven Threat Detection & Security Operations Platform
          </p>
          <div className="mt-3 text-[10px] font-mono uppercase bg-[#181A2F] text-[#FDA481] border border-[#37415C] px-3 py-0.5 rounded-full flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-[#10B981] animate-pulse shadow-[0_0_6px_#10B981]" />
            <span>Hardened Authentication Gateway</span>
          </div>
        </div>

        {error && (
          <div className="mb-5 p-3 rounded-xl bg-[#54162B] border border-[#B4182D] text-[#FDA481] text-xs flex items-center gap-2.5">
            <span className="text-sm">⚠️</span>
            <span className="font-medium">{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          <div>
            <label className="block text-[#CBD5E1] font-semibold mb-1 tracking-wide">
              Security Operator ID / Username
            </label>
            <input
              type="text"
              required
              autoFocus
              placeholder="e.g. soc_lead"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full bg-[#181A2F] border border-[#37415C] rounded-xl px-3.5 py-2.5 text-white placeholder-[#94A3B8]/50 focus:outline-none focus:border-[#FDA481] focus:ring-1 focus:ring-[#FDA481] transition-colors font-mono"
            />
          </div>

          <div>
            <div className="flex justify-between items-center mb-1">
              <label className="text-[#CBD5E1] font-semibold tracking-wide">
                Operator Passphrase
              </label>
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="text-[11px] text-[#FDA481] hover:underline transition-colors"
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
              className="w-full bg-[#181A2F] border border-[#37415C] rounded-xl px-3.5 py-2.5 text-white placeholder-[#94A3B8]/50 focus:outline-none focus:border-[#FDA481] focus:ring-1 focus:ring-[#FDA481] transition-colors font-mono"
            />
          </div>

          <button
            type="submit"
            disabled={submitting}
            className="w-full py-2.5 px-4 rounded-xl bg-[#B4182D] hover:bg-[#B4182D]/90 text-white font-black text-xs tracking-wider uppercase transition-all shadow-crimson-md hover:shadow-crimson-lg disabled:opacity-50 mt-2"
          >
            {submitting ? 'Verifying Credentials...' : 'Authenticate Operator'}
          </button>
        </form>

        {/* Quick Demo Credentials shortcuts for reviewers */}
        <div className="mt-6 pt-5 border-t border-[#37415C]">
          <div className="text-[11px] text-[#94A3B8] font-semibold mb-2.5 text-center tracking-wider uppercase">
            Synthetic Evaluation Credentials
          </div>
          <div className="grid grid-cols-3 gap-2">
            <button
              type="button"
              onClick={() => handleDemoFill('soc_admin', 'SnareAdmin2026!')}
              className="p-2 rounded-lg bg-[#181A2F] hover:bg-[#37415C]/40 border border-[#37415C] hover:border-[#FDA481] text-[10px] text-center transition-all group"
            >
              <div className="font-bold text-[#FDA481]">ADMIN</div>
              <div className="text-[#94A3B8] truncate font-mono text-[9px]">soc_admin</div>
            </button>
            <button
              type="button"
              onClick={() => handleDemoFill('soc_lead', 'SnareAnalyst2026!')}
              className="p-2 rounded-lg bg-[#181A2F] hover:bg-[#37415C]/40 border border-[#37415C] hover:border-[#FDA481] text-[10px] text-center transition-all group"
            >
              <div className="font-bold text-[#FDA481]">ANALYST</div>
              <div className="text-[#94A3B8] truncate font-mono text-[9px]">soc_lead</div>
            </button>
            <button
              type="button"
              onClick={() => handleDemoFill('soc_viewer', 'SnareViewer2026!')}
              className="p-2 rounded-lg bg-[#181A2F] hover:bg-[#37415C]/40 border border-[#37415C] hover:border-[#FDA481] text-[10px] text-center transition-all group"
            >
              <div className="font-bold text-[#FDA481]">VIEWER</div>
              <div className="text-[#94A3B8] truncate font-mono text-[9px]">soc_viewer</div>
            </button>
          </div>
        </div>

        {/* Back to Public Portal Link */}
        <div className="mt-5 text-center">
          <a
            href="/"
            className="text-[11px] text-[#94A3B8] hover:text-[#FDA481] transition-colors underline"
          >
            ← Return to SnareSight Public Platform Overview
          </a>
        </div>
      </div>
    </div>
  );
};
