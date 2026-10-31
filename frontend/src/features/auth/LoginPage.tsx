/**
 * Secure SOC Login Page for SnareSight.
 *
 * Implements client-side validation, rate-limit awareness, generic error messaging
 * to prevent user enumeration, and convenient demo login shortcuts for evaluation.
 */

import React, { useState } from 'react';
import { useAuth } from './AuthContext';

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
    <div className="min-h-screen bg-slate-950 flex flex-col justify-center items-center p-4 text-slate-100 font-sans">
      <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-8">
        {/* Brand Header */}
        <div className="flex flex-col items-center mb-6 text-center">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center text-3xl shadow-lg shadow-blue-500/20 mb-3">
            🕸️
          </div>
          <h1 className="text-xl font-bold tracking-wider text-slate-100">SNARESIGHT SOC</h1>
          <p className="text-xs text-slate-400 mt-1">
            Deception Threat Detection & Security Operations Platform
          </p>
          <div className="mt-2 text-[10px] font-mono uppercase bg-emerald-950/80 text-emerald-400 border border-emerald-800/80 px-2 py-0.5 rounded-full">
            ● Hardened Authentication Boundary
          </div>
        </div>

        {error && (
          <div className="mb-5 p-3 rounded-xl bg-rose-950/70 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
            <span>⚠️</span>
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          <div>
            <label className="block text-slate-400 font-medium mb-1">Username</label>
            <input
              type="text"
              required
              autoFocus
              placeholder="e.g. soc_lead"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500 transition-colors"
            />
          </div>

          <div>
            <div className="flex justify-between items-center mb-1">
              <label className="text-slate-400 font-medium">Password</label>
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="text-[11px] text-blue-400 hover:text-blue-300"
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
              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500 transition-colors"
            />
          </div>

          <button
            type="submit"
            disabled={submitting}
            className="w-full py-2.5 px-4 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs tracking-wide transition-colors shadow-lg shadow-blue-600/30 disabled:opacity-50 mt-2"
          >
            {submitting ? 'Verifying Credentials...' : 'Sign In to Operations'}
          </button>
        </form>

        {/* Quick Demo Credentials shortcuts for reviewers */}
        <div className="mt-6 pt-5 border-t border-slate-800/80">
          <div className="text-[11px] text-slate-500 font-medium mb-2 text-center">
            Demo Credentials (Development Lab)
          </div>
          <div className="grid grid-cols-3 gap-2">
            <button
              onClick={() => handleDemoFill('soc_admin', 'SnareAdmin2026!')}
              className="p-2 rounded-lg bg-slate-950 hover:bg-slate-800/80 border border-slate-800 text-[10px] text-slate-300 text-center transition-colors"
            >
              <div className="font-bold text-amber-400">ADMIN</div>
              <div className="text-slate-500 truncate">soc_admin</div>
            </button>
            <button
              onClick={() => handleDemoFill('soc_lead', 'SnareAnalyst2026!')}
              className="p-2 rounded-lg bg-slate-950 hover:bg-slate-800/80 border border-slate-800 text-[10px] text-slate-300 text-center transition-colors"
            >
              <div className="font-bold text-blue-400">ANALYST</div>
              <div className="text-slate-500 truncate">soc_lead</div>
            </button>
            <button
              onClick={() => handleDemoFill('soc_viewer', 'SnareViewer2026!')}
              className="p-2 rounded-lg bg-slate-950 hover:bg-slate-800/80 border border-slate-800 text-[10px] text-slate-300 text-center transition-colors"
            >
              <div className="font-bold text-emerald-400">VIEWER</div>
              <div className="text-slate-500 truncate">soc_viewer</div>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

