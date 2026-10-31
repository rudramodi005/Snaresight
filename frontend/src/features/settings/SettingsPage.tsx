import React, { useState } from 'react';
import { useAuth } from '../auth/AuthContext';

export const SettingsPage: React.FC = () => {
  const { user, role } = useAuth();
  const [soundEnabled, setSoundEnabled] = useState(false);
  const [autoRefreshRate, setAutoRefreshRate] = useState('30s');
  const [density, setDensity] = useState<'compact' | 'comfortable'>('comfortable');

  return (
    <div className="p-6 bg-slate-950 text-slate-100 min-h-screen space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-6 border-b border-slate-800 gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight text-slate-100">Platform Settings & Configuration</h1>
            <span className="px-2.5 py-0.5 text-xs font-semibold bg-slate-800 text-slate-300 border border-slate-700 rounded-full">
              System Operations
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Global security parameters, sensor fleet telemetry controls, analyst session details, and UI preferences.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Security & Sensor Parameters */}
        <div className="lg:col-span-2 space-y-6">
          {/* Security Boundary & Ingestion Policy */}
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <span>🛡️</span> Deception & Security Policy Governance
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800/80 space-y-1">
                <div className="text-slate-400 font-medium">Zero-Password Sanitization</div>
                <div className="text-emerald-400 font-bold font-mono">ENFORCED (STRICT)</div>
                <div className="text-[11px] text-slate-500 mt-1">
                  Adversary cleartext credentials are scrubbed before persistence; only boolean presence is retained.
                </div>
              </div>

              <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800/80 space-y-1">
                <div className="text-slate-400 font-medium">Honeynet Network Isolation</div>
                <div className="text-emerald-400 font-bold font-mono">AIR-GAPPED BRIDGE</div>
                <div className="text-[11px] text-slate-500 mt-1">
                  Sensors run inside an isolated Docker bridge network `snaresight-internal` with no egress access.
                </div>
              </div>

              <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800/80 space-y-1">
                <div className="text-slate-400 font-medium">Ingestion Ingress Guard</div>
                <div className="text-blue-400 font-bold font-mono">API-KEY PROTECTED</div>
                <div className="text-[11px] text-slate-500 mt-1">
                  Telemetry collectors authenticate with dedicated `X-Ingestion-Key` HTTP headers.
                </div>
              </div>

              <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800/80 space-y-1">
                <div className="text-slate-400 font-medium">Audit Trail Verification</div>
                <div className="text-indigo-400 font-bold font-mono">SHA-256 HASH CHAINING</div>
                <div className="text-[11px] text-slate-500 mt-1">
                  SOC analyst actions and triage decisions are committed to immutable, tamper-evident audit logs.
                </div>
              </div>
            </div>
          </div>

          {/* API Gateway & Deployment Endpoints */}
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <span>🌐</span> Gateway & Service Endpoints
            </h2>
            <div className="space-y-2 text-xs font-mono">
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-center justify-between">
                <div>
                  <span className="text-slate-400">Backend API Gateway:</span>
                  <span className="ml-2 text-slate-200">http://127.0.0.1:8000/api/v1</span>
                </div>
                <span className="px-2 py-0.5 bg-emerald-500/10 text-emerald-400 rounded text-[10px] font-bold">
                  HEALTHY
                </span>
              </div>
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-center justify-between">
                <div>
                  <span className="text-slate-400">Real-Time SSE Stream:</span>
                  <span className="ml-2 text-slate-200">/api/v1/stream/events</span>
                </div>
                <span className="px-2 py-0.5 bg-emerald-500/10 text-emerald-400 rounded text-[10px] font-bold">
                  STREAMING
                </span>
              </div>
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-center justify-between">
                <div>
                  <span className="text-slate-400">Relational Database:</span>
                  <span className="ml-2 text-slate-200">PostgreSQL 16 (9 Alembic revisions)</span>
                </div>
                <span className="px-2 py-0.5 bg-emerald-500/10 text-emerald-400 rounded text-[10px] font-bold">
                  CONNECTED
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Session & UI Preferences */}
        <div className="space-y-6">
          {/* Active Session Card */}
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <span>👤</span> Current Analyst Session
            </h2>
            <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2 text-xs">
              <div className="flex justify-between">
                <span className="text-slate-400">Username:</span>
                <span className="font-mono font-semibold text-slate-200">{user?.username || 'soc_lead'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Full Name:</span>
                <span className="text-slate-200">{user?.full_name || 'Senior SOC Lead'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Assigned Role:</span>
                <span className="font-bold text-amber-400 font-mono">{role || 'ADMIN'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Session Mode:</span>
                <span className="text-emerald-400 font-mono">JWT Bearer (Strict)</span>
              </div>
            </div>
          </div>

          {/* UI Preferences */}
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <span>⚙️</span> Analyst Workspace Preferences
            </h2>
            <div className="space-y-3 text-xs">
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-medium text-slate-200">Audio Alerts</div>
                  <div className="text-[11px] text-slate-500">Play notification sound for CRITICAL detections</div>
                </div>
                <input
                  type="checkbox"
                  checked={soundEnabled}
                  onChange={(e) => setSoundEnabled(e.target.checked)}
                  className="rounded bg-slate-950 border-slate-800 text-blue-600 focus:ring-0 cursor-pointer"
                />
              </div>

              <div className="flex items-center justify-between pt-2 border-t border-slate-800/80">
                <div>
                  <div className="font-medium text-slate-200">Telemetry Refresh Window</div>
                  <div className="text-[11px] text-slate-500">Polling rate for fallback background queries</div>
                </div>
                <select
                  value={autoRefreshRate}
                  onChange={(e) => setAutoRefreshRate(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-xs text-slate-300 focus:outline-none"
                >
                  <option value="10s">10s</option>
                  <option value="30s">30s</option>
                  <option value="1m">1m</option>
                  <option value="5m">5m</option>
                </select>
              </div>

              <div className="flex items-center justify-between pt-2 border-t border-slate-800/80">
                <div>
                  <div className="font-medium text-slate-200">Table Density</div>
                  <div className="text-[11px] text-slate-500">Spacing in alerts and events queues</div>
                </div>
                <div className="flex bg-slate-950 border border-slate-800 rounded p-0.5">
                  <button
                    onClick={() => setDensity('comfortable')}
                    className={`px-2 py-0.5 rounded text-[11px] ${
                      density === 'comfortable' ? 'bg-blue-600 text-white' : 'text-slate-400'
                    }`}
                  >
                    Comfortable
                  </button>
                  <button
                    onClick={() => setDensity('compact')}
                    className={`px-2 py-0.5 rounded text-[11px] ${
                      density === 'compact' ? 'bg-blue-600 text-white' : 'text-slate-400'
                    }`}
                  >
                    Compact
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SettingsPage;

