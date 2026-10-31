import React, { useState, useEffect } from 'react';
import { ActivitySession, PaginatedSessions, SessionStatistics, SessionTimeline } from '../../types/session';
import { sessionApi } from '../../services/sessionApi';
import { SessionTimelineView } from '../../components/SessionTimeline';

export const SessionInvestigationPage: React.FC = () => {
  const [paginated, setPaginated] = useState<PaginatedSessions | null>(null);
  const [stats, setStats] = useState<SessionStatistics | null>(null);
  const [selectedSession, setSelectedSession] = useState<ActivitySession | null>(null);
  const [timeline, setTimeline] = useState<SessionTimeline | null>(null);
  const [loading, setLoading] = useState(true);
  const [timelineLoading, setTimelineLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [filterDecoy, setFilterDecoy] = useState('');
  const [filterStatus, setFilterStatus] = useState('');
  const [filterAddress, setFilterAddress] = useState('');
  const [filterWithDetections, setFilterWithDetections] = useState<boolean | undefined>(undefined);

  const loadSessions = async () => {
    setLoading(true);
    setError(null);
    try {
      const [sessionsData, statsData] = await Promise.all([
        sessionApi.listSessions({
          decoyId: filterDecoy || undefined,
          status: filterStatus || undefined,
          sourceAddress: filterAddress || undefined,
          hasDetections: filterWithDetections,
          pageSize: 25,
        }),
        sessionApi.getStatistics(),
      ]);
      setPaginated(sessionsData);
      setStats(statsData);

      if (sessionsData.items.length > 0 && !selectedSession) {
        loadSessionDetails(sessionsData.items[0].session_id);
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to load sessions data.');
    } finally {
      setLoading(false);
    }
  };

  const loadSessionDetails = async (sessionId: string) => {
    setTimelineLoading(true);
    try {
      const [detail, tl] = await Promise.all([
        sessionApi.getSession(sessionId),
        sessionApi.getSessionTimeline(sessionId),
      ]);
      setSelectedSession(detail);
      setTimeline(tl);
    } catch (err: any) {
      console.error('Error loading session timeline:', err);
    } finally {
      setTimelineLoading(false);
    }
  };

  useEffect(() => {
    loadSessions();
  }, [filterDecoy, filterStatus, filterAddress, filterWithDetections]);

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8 text-slate-100">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-100">
          Session-Based Investigation Workspace
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Trace visitor sessions, inspect contextual event timelines, and review threat detections across honeypot decoys.
        </p>
      </div>

      {/* KPI Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
            <span className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Total Sessions</span>
            <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">{stats.total_sessions}</div>
          </div>
          <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
            <span className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Active Sessions</span>
            <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">{stats.active_sessions}</div>
          </div>
          <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
            <span className="text-xs text-slate-400 uppercase tracking-wider font-semibold">With Detections</span>
            <div className="text-2xl font-bold font-mono text-rose-400 mt-1">{stats.sessions_with_detections}</div>
          </div>
          <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
            <span className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Correlated Events</span>
            <div className="text-2xl font-bold font-mono text-blue-400 mt-1">{stats.total_events_correlated}</div>
          </div>
          <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
            <span className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Avg Events / Session</span>
            <div className="text-2xl font-bold font-mono text-slate-300 mt-1">{stats.average_events_per_session}</div>
          </div>
        </div>
      )}

      {/* Filter Bar */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg flex flex-wrap gap-4 items-center">
        <input
          type="text"
          placeholder="Filter by Source IP..."
          value={filterAddress}
          onChange={(e) => setFilterAddress(e.target.value)}
          className="bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
        />

        <select
          value={filterDecoy}
          onChange={(e) => setFilterDecoy(e.target.value)}
          className="bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
        >
          <option value="">All Honeypots</option>
          <option value="WEB-001">WEB-001 (Web Login)</option>
        </select>

        <select
          value={filterStatus}
          onChange={(e) => setFilterStatus(e.target.value)}
          className="bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
        >
          <option value="">All Statuses</option>
          <option value="ACTIVE">ACTIVE</option>
          <option value="IDLE">IDLE</option>
          <option value="CLOSED">CLOSED</option>
          <option value="TIMED_OUT">TIMED_OUT</option>
        </select>

        <button
          onClick={() => setFilterWithDetections(filterWithDetections === true ? undefined : true)}
          className={`px-3 py-1.5 text-xs font-medium rounded border transition-colors ${
            filterWithDetections === true
              ? 'bg-rose-950 border-rose-500 text-rose-300'
              : 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700'
          }`}
        >
          {filterWithDetections === true ? 'With Detections Only ✓' : 'Filter Detections'}
        </button>

        <button
          onClick={loadSessions}
          className="px-3 py-1.5 text-xs font-medium rounded bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors ml-auto"
        >
          Refresh Sessions
        </button>
      </div>

      {error && (
        <div className="p-4 bg-rose-950/40 border border-rose-800/80 rounded-lg text-xs text-rose-300">
          {error}
        </div>
      )}

      {/* Main Investigation Split Pane */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Sessions List (5 cols) */}
        <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-lg overflow-hidden flex flex-col h-[700px]">
          <div className="p-4 border-b border-slate-800">
            <h3 className="text-sm font-semibold text-slate-200">
              Correlated Sessions ({paginated?.total || 0})
            </h3>
          </div>

          {loading ? (
            <div className="p-8 text-center text-xs text-slate-500">Loading sessions...</div>
          ) : (!paginated?.items || paginated.items.length === 0) ? (
            <div className="p-8 text-center text-xs text-slate-500">No activity sessions found.</div>
          ) : (
            <div className="divide-y divide-slate-800 overflow-y-auto flex-1">
              {(paginated?.items || []).map((s) => (
                <div
                  key={s.session_id}
                  onClick={() => loadSessionDetails(s.session_id)}
                  className={`p-4 cursor-pointer transition-colors ${
                    selectedSession?.session_id === s.session_id
                      ? 'bg-cyan-950/40 border-l-4 border-cyan-500'
                      : 'hover:bg-slate-800/50'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="font-mono font-bold text-cyan-400">
                      {s.session_id}
                    </span>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold ${
                      s.session_status === 'ACTIVE'
                        ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                        : 'bg-slate-800 text-slate-400 border border-slate-700'
                    }`}>
                      {s.session_status}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-xs text-slate-300 font-mono mt-1">
                    <span>{s.source_address}</span>
                    <span className="text-slate-500">{s.decoy_id} • {s.target_service}</span>
                  </div>

                  <div className="flex items-center justify-between text-[11px] text-slate-400 mt-2">
                    <span>Events: <strong className="text-slate-200">{s.event_count}</strong></span>
                    {s.detection_count > 0 && (
                      <span className="text-rose-400 font-semibold font-mono">
                        {s.detection_count} Alert{s.detection_count > 1 ? 's' : ''} ({s.highest_severity})
                      </span>
                    )}
                    <span className="text-slate-500">{s.correlation_method.replace('_', ' ')}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right: Selected Session Timeline & Context (7 cols) */}
        <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-lg p-6 overflow-y-auto h-[700px]">
          {timelineLoading ? (
            <div className="p-12 text-center text-xs text-slate-500 animate-pulse">
              Constructing chronological investigation timeline...
            </div>
          ) : timeline && selectedSession ? (
            <SessionTimelineView timeline={timeline} />
          ) : (
            <div className="p-12 text-center text-xs text-slate-500">
              Select an activity session on the left to inspect its timeline and forensic events.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

