import React, { useState, useEffect } from 'react';
import { DashboardOverview, fetchDashboardOverview } from '../../services/dashboardApi';
import { Badge } from '../../components/ui/Badge';
import { Button } from '../../components/ui/Button';
import { formatInteger } from '../../utils/format';

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
    <div className="p-6 bg-[#000F08] text-[#FB3640] min-h-screen selection:bg-[#FB3640] selection:text-[#000F08]">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-6 border-b border-[#FB3640]/20 gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-black tracking-tight text-[#FB3640]">Security Operations Overview</h1>
            <span className="px-2.5 py-0.5 text-xs font-mono font-semibold bg-[#FB3640]/10 text-[#FB3640] border border-[#FB3640]/30 rounded-full flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[#FB3640] animate-pulse" />
              LIVE SOC TELEMETRY
            </span>
          </div>
          <p className="text-xs text-[#FB3640]/70 mt-1">
            Real-time deception-driven situational awareness across honeypot decoy sensors, detection rules, and investigations.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Time range switcher */}
          <div className="flex bg-[#000F08] border border-[#FB3640]/30 rounded-xl p-1 text-xs font-semibold">
            {['1h', '24h', '7d', '30d'].map((r) => (
              <button
                key={r}
                onClick={() => setTimeRange(r)}
                className={`px-3 py-1.5 rounded-lg uppercase tracking-wider transition-all ${
                  timeRange === r
                    ? 'bg-[#FB3640] text-[#000F08] font-black shadow-crimson-sm'
                    : 'text-[#FB3640]/70 hover:text-[#FB3640] hover:bg-[#FB3640]/10'
                }`}
              >
                {r}
              </button>
            ))}
          </div>

          <button
            onClick={() => loadData(timeRange)}
            disabled={loading}
            className="px-4 py-2 bg-[#000F08] hover:bg-[#FB3640]/10 border border-[#FB3640]/35 rounded-xl text-xs font-bold text-[#FB3640] transition-all flex items-center gap-2"
          >
            <span className={loading ? 'animate-spin inline-block' : ''}>🔄</span>
            Refresh
          </button>
        </div>
      </div>

      {loading && !data ? (
        <div className="py-28 text-center text-[#FB3640]/60">
          <div className="inline-block animate-spin text-3xl mb-3">🔄</div>
          <p className="text-xs uppercase tracking-widest font-mono">Aggregating SOC security metrics & decoy telemetries...</p>
        </div>
      ) : error ? (
        <div className="my-8 p-4 bg-[#FB3640]/10 border border-[#FB3640]/40 rounded-2xl text-[#FB3640] text-sm">
          Failed to load overview: {error}
        </div>
      ) : data ? (
        <div className="space-y-6 mt-6">
          {/* 1. Key Metric Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Total Events */}
            <div className="bg-[#000F08] border border-[#FB3640]/25 rounded-2xl p-5 shadow-crimson-sm glass-panel">
              <span className="text-xs text-[#FB3640]/70 font-semibold uppercase tracking-wider">{data.metrics.total_events.label}</span>
              <div className="text-3xl font-black text-[#FB3640] mt-1.5 font-mono">
                {formatInteger(data.metrics.total_events.value, '0')}
              </div>
              <p className="text-[11px] text-[#FB3640]/60 mt-1">{data.metrics.total_events.description}</p>
            </div>

            {/* Total Alerts */}
            <div className="bg-[#000F08] border border-[#FB3640]/25 rounded-2xl p-5 shadow-crimson-sm glass-panel">
              <span className="text-xs text-[#FB3640]/70 font-semibold uppercase tracking-wider">{data.metrics.total_alerts.label}</span>
              <div className="text-3xl font-black text-[#FB3640] mt-1.5 font-mono">
                {formatInteger(data.metrics.total_alerts.value, '0')}
              </div>
              <p className="text-[11px] text-[#FB3640]/60 mt-1">{data.metrics.total_alerts.description}</p>
            </div>

            {/* Critical & High Alerts */}
            <div className="bg-[#000F08] border border-[#FB3640]/25 rounded-2xl p-5 shadow-crimson-sm glass-panel">
              <div className="flex justify-between items-start">
                <div>
                  <span className="text-xs text-[#FB3640]/70 font-semibold uppercase tracking-wider">Critical / High Alerts</span>
                  <div className="text-3xl font-black text-[#FB3640] mt-1.5 font-mono">
                    {data.metrics.critical_alerts.value} / {data.metrics.high_severity_alerts.value}
                  </div>
                </div>
                <span className="px-2 py-0.5 text-[9px] font-black bg-[#FB3640] text-[#000F08] rounded tracking-wider uppercase">
                  PRIORITY
                </span>
              </div>
              <p className="text-[11px] text-[#FB3640]/60 mt-1">Requiring immediate analyst triage</p>
            </div>

            {/* Active Investigations */}
            <div className="bg-[#000F08] border border-[#FB3640]/25 rounded-2xl p-5 shadow-crimson-sm glass-panel">
              <span className="text-xs text-[#FB3640]/70 font-semibold uppercase tracking-wider">{data.metrics.active_investigations.label}</span>
              <div className="text-3xl font-black text-[#FB3640] mt-1.5 font-mono">
                {data.metrics.active_investigations.value}
              </div>
              <p className="text-[11px] text-[#FB3640]/60 mt-1">{data.metrics.active_investigations.description}</p>
            </div>
          </div>

          {/* Secondary Metric Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="bg-[#000F08] border border-[#FB3640]/20 rounded-xl p-3.5 glass-panel">
              <span className="text-[11px] text-[#FB3640]/70 font-medium">Observed Sessions:</span>
              <div className="text-xl font-black text-[#FB3640] mt-0.5 font-mono">{data.metrics.observed_sessions.value}</div>
            </div>
            <div className="bg-[#000F08] border border-[#FB3640]/20 rounded-xl p-3.5 glass-panel">
              <span className="text-[11px] text-[#FB3640]/70 font-medium">Observed Source Profiles:</span>
              <div className="text-xl font-black text-[#FB3640] mt-0.5 font-mono">{data.metrics.observed_source_profiles.value}</div>
            </div>
            <div className="bg-[#000F08] border border-[#FB3640]/20 rounded-xl p-3.5 glass-panel">
              <span className="text-[11px] text-[#FB3640]/70 font-medium">Connected Decoy Sensors:</span>
              <div className="text-xl font-black text-[#FB3640] mt-0.5 font-mono">{data.metrics.connected_sensors.value}</div>
            </div>
            <div className="bg-[#000F08] border border-[#FB3640]/20 rounded-xl p-3.5 glass-panel">
              <span className="text-[11px] text-[#FB3640]/70 font-medium">Pipeline Operational State:</span>
              <div className="text-xl font-black text-[#FB3640] mt-0.5 font-mono">{data.pipeline_health.overall_status}</div>
            </div>
          </div>

          {/* 2. Middle Grid: Severity Distribution & Top Categories */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Severity Distribution */}
            <div className="bg-[#000F08] border border-[#FB3640]/25 rounded-2xl p-5 shadow-crimson-sm glass-panel">
              <h2 className="text-xs font-black uppercase tracking-wider text-[#FB3640] mb-4 flex items-center justify-between">
                <span>Alert Severity Breakdown</span>
                <span className="text-[11px] font-normal text-[#FB3640]/60">Past {timeRange}</span>
              </h2>
              <div className="space-y-3.5">
                {(data.severity_distribution || []).length === 0 ? (
                  <div className="py-8 text-center text-xs text-[#FB3640]/50 font-mono">
                    No alert severity activity recorded in selected time window.
                  </div>
                ) : (
                  data.severity_distribution.map((item) => (
                    <div key={item.severity}>
                      <div className="flex justify-between text-xs mb-1.5">
                        <span className="font-bold text-[#FB3640] tracking-wide">{item.severity}</span>
                        <span className="text-[#FB3640]/80 font-mono text-[11px]">
                          {item.count} ({item.percentage}%)
                        </span>
                      </div>
                      <div className="w-full bg-[#000F08] rounded-full h-2 overflow-hidden border border-[#FB3640]/20">
                        <div
                          className={`h-full rounded-full transition-all duration-500 ${
                            item.severity === 'CRITICAL'
                              ? 'bg-[#FB3640]'
                              : item.severity === 'HIGH'
                              ? 'bg-[#FB3640]/80'
                              : item.severity === 'MEDIUM'
                              ? 'bg-[#FB3640]/60'
                              : 'bg-[#FB3640]/30'
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
            <div className="bg-[#000F08] border border-[#FB3640]/25 rounded-2xl p-5 shadow-crimson-sm glass-panel">
              <h2 className="text-xs font-black uppercase tracking-wider text-[#FB3640] mb-4 flex items-center justify-between">
                <span>Top Detection Categories</span>
                <span className="text-[11px] font-normal text-[#FB3640]/60 font-mono">Rules Engine</span>
              </h2>
              <div className="space-y-2.5">
                {data.top_categories.length === 0 ? (
                  <div className="py-8 text-center text-xs text-[#FB3640]/50 font-mono">No detection categories observed.</div>
                ) : (
                  data.top_categories.map((cat, i) => (
                    <div key={i} className="flex items-center justify-between p-3 bg-[#000F08] border border-[#FB3640]/20 rounded-xl text-xs">
                      <div className="flex items-center gap-2.5">
                        <span className="w-5 h-5 flex items-center justify-center rounded bg-[#FB3640]/15 text-[#FB3640] font-mono text-[10px] font-bold">
                          #{i + 1}
                        </span>
                        <span className="font-bold text-[#FB3640]">{cat.category}</span>
                      </div>
                      <span className="font-mono text-[#FB3640]/80 text-[11px]">
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
            <div className="bg-[#000F08] border border-[#FB3640]/25 rounded-2xl p-5 shadow-crimson-sm glass-panel">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xs font-black uppercase tracking-wider text-[#FB3640]">
                  Recent Security Alerts
                </h2>
                <a href="/app/events" className="text-xs text-[#FB3640] hover:underline font-semibold">
                  View Events Explorer →
                </a>
              </div>
              <div className="space-y-2.5">
                {data.recent_alerts.length === 0 ? (
                  <div className="py-8 text-center text-xs text-[#FB3640]/50 font-mono">No security alerts triggered.</div>
                ) : (
                  data.recent_alerts.map((a) => (
                    <div
                      key={a.alert_id}
                      className="p-3 bg-[#000F08] border border-[#FB3640]/20 rounded-xl text-xs flex items-center justify-between hover:border-[#FB3640]/40 transition-colors"
                    >
                      <div>
                        <div className="flex items-center gap-2">
                          <Badge variant={a.severity.toLowerCase() as any} size="sm">
                            {a.severity}
                          </Badge>
                          <span className="font-bold text-[#FB3640]">{a.title}</span>
                        </div>
                        <div className="text-[#FB3640]/70 font-mono mt-1 text-[11px]">
                          Src: {a.source_address} on {a.decoy_id} ({a.target_service})
                        </div>
                      </div>
                      <span className="text-[10px] font-mono text-[#FB3640]/60">
                        {new Date(a.observed_at).toLocaleTimeString()}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Recent Investigations */}
            <div className="bg-[#000F08] border border-[#FB3640]/25 rounded-2xl p-5 shadow-crimson-sm glass-panel">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xs font-black uppercase tracking-wider text-[#FB3640]">
                  Active Campaign Investigations
                </h2>
                <a href="/app/investigations" className="text-xs text-[#FB3640] hover:underline font-semibold">
                  All Investigations →
                </a>
              </div>
              <div className="space-y-2.5">
                {data.recent_investigations.length === 0 ? (
                  <div className="py-8 text-center text-xs text-[#FB3640]/50 font-mono">No active campaign investigations.</div>
                ) : (
                  data.recent_investigations.map((c) => (
                    <div
                      key={c.id}
                      className="p-3 bg-[#000F08] border border-[#FB3640]/20 rounded-xl text-xs flex items-center justify-between hover:border-[#FB3640]/40 transition-colors"
                    >
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-[#FB3640] font-bold text-xs bg-[#FB3640]/10 px-1.5 py-0.5 rounded border border-[#FB3640]/30">{c.cluster_code}</span>
                          <span className="font-bold text-[#FB3640]">{c.title}</span>
                        </div>
                        <div className="text-[#FB3640]/70 mt-1 text-[11px]">
                          Status: <span className="font-semibold text-[#FB3640]">{c.lifecycle_status}</span> | Priority:{' '}
                          <span className="font-semibold text-[#FB3640]">{c.priority}</span>
                        </div>
                      </div>
                      <span className="text-[10px] font-mono text-[#FB3640]/60">
                        {new Date(c.last_activity_at).toLocaleDateString()}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* 4. Sensors Telemetry Freshness */}
          <div className="bg-[#000F08] border border-[#FB3640]/25 rounded-2xl p-5 shadow-crimson-sm glass-panel">
            <h2 className="text-xs font-black uppercase tracking-wider text-[#FB3640] mb-4">
              Honeypot Decoy Sensors (Telemetry Freshness Policy)
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
              {data.sensors.map((s) => (
                <div key={s.sensor_id} className="p-4 bg-[#000F08] border border-[#FB3640]/20 rounded-xl text-xs hover:border-[#FB3640]/40 transition-colors">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-bold text-[#FB3640] text-sm">{s.name}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                        s.health_status === 'ONLINE'
                          ? 'bg-[#FB3640]/20 text-[#FB3640] border border-[#FB3640]/40'
                          : 'bg-[#FB3640]/10 text-[#FB3640]/60 border border-[#FB3640]/20'
                      }`}
                    >
                      {s.health_status}
                    </span>
                  </div>
                  <div className="text-[#FB3640]/70 font-mono text-[11px]">ID: {s.sensor_id} ({s.protocol})</div>
                  <div className="text-[#FB3640]/60 mt-2 text-[11px]">
                    Events: <strong className="text-[#FB3640]">{s.events_received}</strong>
                  </div>
                  <div className="text-[#FB3640]/60 text-[11px] mt-0.5">{s.freshness_description}</div>
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
