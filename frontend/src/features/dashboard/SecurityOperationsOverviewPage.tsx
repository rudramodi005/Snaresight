import React, { useState, useEffect } from 'react';
import { DashboardOverview, fetchDashboardOverview } from '../../services/dashboardApi';

export const SecurityOperationsOverviewPage: React.FC = () => {
  const [data, setData] = useState<DashboardOverview | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [timeRange, setTimeRange] = useState<string>('24h');

  const loadData = async (range: string) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetchDashboardOverview(range);
      setData(res);
    } catch (err: any) {
      setError(err.message || 'Failed to load dashboard overview');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData(timeRange);
  }, [timeRange]);

  return (
    <div className="p-6 bg-slate-950 text-slate-100 min-h-screen">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-6 border-b border-slate-800 gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight text-slate-100">Security Operations Overview</h1>
            <span className="px-2.5 py-0.5 text-xs font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20 rounded-full">
              Live SOC Telemetry
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Real-time deception-driven situational awareness across honeypot sensors, detections, and investigations.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Time range switcher */}
          <div className="flex bg-slate-900 border border-slate-800 rounded-lg p-0.5 text-xs font-medium">
            {['1h', '24h', '7d', '30d'].map((r) => (
              <button
                key={r}
                onClick={() => setTimeRange(r)}
                className={`px-3 py-1.5 rounded-md capitalize transition-colors ${
                  timeRange === r
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {r}
              </button>
            ))}
          </div>

          <button
            onClick={() => loadData(timeRange)}
            disabled={loading}
            className="px-3.5 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg text-sm font-medium text-slate-200 transition-colors flex items-center gap-2"
          >
            <span className={loading ? 'animate-spin inline-block' : ''}>🔄</span>
            Refresh
          </button>
        </div>
      </div>

      {loading && !data ? (
        <div className="py-24 text-center text-slate-500">
          <div className="inline-block animate-spin text-2xl mr-2">🔄</div>
          <p className="mt-2 text-sm">Aggregating SOC security metrics...</p>
        </div>
      ) : error ? (
        <div className="my-8 p-4 bg-rose-950/40 border border-rose-500/30 rounded-xl text-rose-400 text-sm">
          Failed to load overview: {error}
        </div>
      ) : data ? (
        <div className="space-y-6 mt-6">
          {/* 1. Key Metric Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Total Events */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
              <span className="text-xs text-slate-400 font-medium">{data.metrics.total_events.label}</span>
              <div className="text-2xl font-bold text-slate-100 mt-1">
                {Number(data.metrics.total_events.value).toLocaleString()}
              </div>
              <p className="text-xs text-slate-500 mt-1">{data.metrics.total_events.description}</p>
            </div>

            {/* Total Alerts */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
              <span className="text-xs text-slate-400 font-medium">{data.metrics.total_alerts.label}</span>
              <div className="text-2xl font-bold text-rose-400 mt-1">
                {Number(data.metrics.total_alerts.value).toLocaleString()}
              </div>
              <p className="text-xs text-slate-500 mt-1">{data.metrics.total_alerts.description}</p>
            </div>

            {/* Critical & High Alerts */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
              <div className="flex justify-between items-start">
                <div>
                  <span className="text-xs text-slate-400 font-medium">Critical / High Alerts</span>
                  <div className="text-2xl font-bold text-orange-400 mt-1">
                    {data.metrics.critical_alerts.value} / {data.metrics.high_severity_alerts.value}
                  </div>
                </div>
                <span className="px-2 py-0.5 text-[10px] font-bold bg-rose-500/20 text-rose-400 rounded">
                  PRIORITY
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-1">Requiring immediate analyst triage</p>
            </div>

            {/* Active Investigations */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
              <span className="text-xs text-slate-400 font-medium">{data.metrics.active_investigations.label}</span>
              <div className="text-2xl font-bold text-cyan-400 mt-1">
                {data.metrics.active_investigations.value}
              </div>
              <p className="text-xs text-slate-500 mt-1">{data.metrics.active_investigations.description}</p>
            </div>
          </div>

          {/* Secondary Metric Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="bg-slate-900/50 border border-slate-800/80 rounded-lg p-3">
              <span className="text-xs text-slate-400">Observed Sessions:</span>
              <div className="text-lg font-bold text-slate-200 mt-0.5">{data.metrics.observed_sessions.value}</div>
            </div>
            <div className="bg-slate-900/50 border border-slate-800/80 rounded-lg p-3">
              <span className="text-xs text-slate-400">Observed Source Profiles:</span>
              <div className="text-lg font-bold text-slate-200 mt-0.5">{data.metrics.observed_source_profiles.value}</div>
            </div>
            <div className="bg-slate-900/50 border border-slate-800/80 rounded-lg p-3">
              <span className="text-xs text-slate-400">Connected Decoy Sensors:</span>
              <div className="text-lg font-bold text-emerald-400 mt-0.5">{data.metrics.connected_sensors.value}</div>
            </div>
            <div className="bg-slate-900/50 border border-slate-800/80 rounded-lg p-3">
              <span className="text-xs text-slate-400">Pipeline Operational State:</span>
              <div className="text-lg font-bold text-emerald-400 mt-0.5">{data.pipeline_health.overall_status}</div>
            </div>
          </div>

          {/* 2. Middle Grid: Severity Distribution & Top Categories */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Severity Distribution */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
              <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300 mb-4 flex items-center justify-between">
                <span>Alert Severity Breakdown</span>
                <span className="text-xs font-normal text-slate-500">Past {timeRange}</span>
              </h2>
              <div className="space-y-3">
                {(data.severity_distribution || []).length === 0 ? (
                  <div className="py-8 text-center text-xs text-slate-500">
                    No alert severity activity recorded in selected time window.
                  </div>
                ) : (
                  data.severity_distribution.map((item) => (
                    <div key={item.severity}>
                      <div className="flex justify-between text-xs mb-1">
                        <span className="font-semibold text-slate-300">{item.severity}</span>
                        <span className="text-slate-400 font-mono">
                          {item.count} ({item.percentage}%)
                        </span>
                      </div>
                      <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
                        <div
                          className={`h-full rounded-full transition-all duration-500 ${
                            item.severity === 'CRITICAL'
                              ? 'bg-rose-500'
                              : item.severity === 'HIGH'
                              ? 'bg-orange-500'
                              : item.severity === 'MEDIUM'
                              ? 'bg-amber-500'
                              : item.severity === 'LOW'
                              ? 'bg-blue-500'
                              : 'bg-slate-500'
                          }`}
                          style={{ width: `${Math.max(item.percentage ?? 0, item.count > 0 ? 3 : 0)}%` }}
                        />
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Top Categories */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
              <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300 mb-4 flex items-center justify-between">
                <span>Top Detection Categories</span>
                <span className="text-xs font-normal text-slate-500">Rules Engine</span>
              </h2>
              <div className="space-y-2.5">
                {data.top_categories.length === 0 ? (
                  <div className="py-8 text-center text-xs text-slate-500">No detection categories observed.</div>
                ) : (
                  data.top_categories.map((cat, i) => (
                    <div key={i} className="flex items-center justify-between p-2.5 bg-slate-950 rounded-lg text-xs">
                      <div className="flex items-center gap-2">
                        <span className="w-5 h-5 flex items-center justify-center rounded bg-slate-800 text-slate-400 font-mono text-[10px]">
                          #{i + 1}
                        </span>
                        <span className="font-semibold text-slate-200">{cat.category}</span>
                      </div>
                      <span className="font-mono text-slate-400">
                        {cat.count} alerts ({cat.percentage}%)
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* 3. Lower Grid: Recent Alerts & Recent Investigations */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Recent Alerts */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300">
                  Recent Security Alerts
                </h2>
                <a href="/events" className="text-xs text-blue-400 hover:text-blue-300 underline">
                  View Events Explorer →
                </a>
              </div>
              <div className="space-y-2">
                {data.recent_alerts.length === 0 ? (
                  <div className="py-8 text-center text-xs text-slate-500">No security alerts triggered.</div>
                ) : (
                  data.recent_alerts.map((a) => (
                    <div
                      key={a.alert_id}
                      className="p-3 bg-slate-950 border border-slate-800/80 rounded-lg text-xs flex items-center justify-between"
                    >
                      <div>
                        <div className="flex items-center gap-2">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              a.severity === 'CRITICAL'
                                ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                                : a.severity === 'HIGH'
                                ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                                : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                            }`}
                          >
                            {a.severity}
                          </span>
                          <span className="font-semibold text-slate-200">{a.title}</span>
                        </div>
                        <div className="text-slate-400 font-mono mt-1 text-[11px]">
                          Src: {a.source_address} on {a.decoy_id} ({a.target_service})
                        </div>
                      </div>
                      <span className="text-[10px] font-mono text-slate-500">
                        {new Date(a.observed_at).toLocaleTimeString()}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Recent Investigations */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300">
                  Active Campaign Investigations
                </h2>
                <a href="/investigations" className="text-xs text-blue-400 hover:text-blue-300 underline">
                  All Investigations →
                </a>
              </div>
              <div className="space-y-2">
                {data.recent_investigations.length === 0 ? (
                  <div className="py-8 text-center text-xs text-slate-500">No active campaign investigations.</div>
                ) : (
                  data.recent_investigations.map((c) => (
                    <div
                      key={c.id}
                      className="p-3 bg-slate-950 border border-slate-800/80 rounded-lg text-xs flex items-center justify-between"
                    >
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-blue-400 font-semibold">{c.cluster_code}</span>
                          <span className="font-semibold text-slate-200">{c.title}</span>
                        </div>
                        <div className="text-slate-400 mt-1 text-[11px]">
                          Status: <span className="text-emerald-400">{c.lifecycle_status}</span> | Priority:{' '}
                          <span className="text-amber-400">{c.priority}</span>
                        </div>
                      </div>
                      <span className="text-[10px] font-mono text-slate-500">
                        {new Date(c.last_activity_at).toLocaleDateString()}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* 4. Sensors Telemetry Freshness */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300 mb-4">
              Honeypot Decoy Sensors (Telemetry Freshness Policy)
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {data.sensors.map((s) => (
                <div key={s.sensor_id} className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg text-xs">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-bold text-slate-200">{s.name}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        s.health_status === 'ONLINE'
                          ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                          : s.health_status === 'DEGRADED'
                          ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {s.health_status}
                    </span>
                  </div>
                  <div className="text-slate-400 font-mono text-[11px]">ID: {s.sensor_id} ({s.protocol})</div>
                  <div className="text-slate-500 mt-2 text-[11px]">
                    Events: <strong className="text-slate-300">{s.events_received}</strong>
                  </div>
                  <div className="text-slate-500 text-[11px] mt-0.5">{s.freshness_description}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
};

export default SecurityOperationsOverviewPage;

