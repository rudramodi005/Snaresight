import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  TimeRangeOption,
  AnalyticsOverviewResponse,
  EventTimelineResponse,
  AlertTimelineResponse,
  EventAlertOverviewResponse,
  DetectionAnalyticsResponse,
  SeverityAnalyticsResponse,
  ConfidenceAnalyticsResponse,
  SessionAnalyticsResponse,
  SourceAnalyticsResponse,
  InvestigationAnalyticsResponse,
  AttackAnalyticsResponse,
  SensorAnalyticsResponse,
  PipelineHealthAnalyticsResponse,
  ExecutiveSummaryResponse,
  ReportMetadataResponse,
} from '../../types/analytics';
import { analyticsApi, AnalyticsFilterParams } from '../../services/analyticsApi';
import { formatInteger, formatDateTime } from '../../utils/format';

export const SecurityAnalyticsPage: React.FC = () => {
  const navigate = useNavigate();

  // Active view tab
  const [activeTab, setActiveTab] = useState<
    'trends' | 'detections' | 'severity-confidence' | 'sessions-sources' | 'campaigns-attack' | 'health' | 'executive' | 'reports'
  >('trends');

  // Filters State
  const [timeRange, setTimeRange] = useState<TimeRangeOption>('24h');
  const [customStart, setCustomStart] = useState<string>('');
  const [customEnd, setCustomEnd] = useState<string>('');
  const [sensorFilter, setSensorFilter] = useState<string>('');
  const [categoryFilter, setCategoryFilter] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');

  // Data States
  const [overview, setOverview] = useState<AnalyticsOverviewResponse | null>(null);
  const [eventTimeline, setEventTimeline] = useState<EventTimelineResponse | null>(null);
  const [alertTimeline, setAlertTimeline] = useState<AlertTimelineResponse | null>(null);
  const [eventAlertOverview, setEventAlertOverview] = useState<EventAlertOverviewResponse | null>(null);
  const [detections, setDetections] = useState<DetectionAnalyticsResponse | null>(null);
  const [severityData, setSeverityData] = useState<SeverityAnalyticsResponse | null>(null);
  const [confidenceData, setConfidenceData] = useState<ConfidenceAnalyticsResponse | null>(null);
  const [sessionData, setSessionData] = useState<SessionAnalyticsResponse | null>(null);
  const [sourceData, setSourceData] = useState<SourceAnalyticsResponse | null>(null);
  const [investigationData, setInvestigationData] = useState<InvestigationAnalyticsResponse | null>(null);
  const [attackData, setAttackData] = useState<AttackAnalyticsResponse | null>(null);
  const [sensorData, setSensorData] = useState<SensorAnalyticsResponse | null>(null);
  const [pipelineData, setPipelineData] = useState<PipelineHealthAnalyticsResponse | null>(null);
  const [executiveSummary, setExecutiveSummary] = useState<ExecutiveSummaryResponse | null>(null);

  // Loading & Error States
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [notification, setNotification] = useState<string | null>(null);

  // Report Generation State
  const [reportTitle, setReportTitle] = useState<string>('SnareSight Security Operations Report');
  const [reportFormat, setReportFormat] = useState<'PDF' | 'CSV'>('PDF');
  const [reportAnalyst, setReportAnalyst] = useState<string>('analyst_soc_user');
  const [generatingReport, setGeneratingReport] = useState<boolean>(false);
  const [generatedReport, setGeneratedReport] = useState<ReportMetadataResponse | null>(null);

  const getFilterParams = useCallback((): AnalyticsFilterParams => {
    return {
      timeRange,
      startTime: timeRange === 'custom' && customStart ? new Date(customStart).toISOString() : undefined,
      endTime: timeRange === 'custom' && customEnd ? new Date(customEnd).toISOString() : undefined,
      sensorId: sensorFilter || undefined,
      eventCategory: categoryFilter || undefined,
      severity: severityFilter || undefined,
    };
  }, [timeRange, customStart, customEnd, sensorFilter, categoryFilter, severityFilter]);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = getFilterParams();
      const [
        ovRes,
        evTimeRes,
        altTimeRes,
        eaRes,
        detRes,
        sevRes,
        confRes,
        sessRes,
        srcRes,
        invRes,
        attRes,
        senRes,
        pipeRes,
        execRes,
      ] = await Promise.all([
        analyticsApi.getOverview(params),
        analyticsApi.getEventsTimeline(params),
        analyticsApi.getAlertsTimeline(params),
        analyticsApi.getEventAlertOverview(params),
        analyticsApi.getDetectionAnalytics(params),
        analyticsApi.getSeverityAnalytics(params),
        analyticsApi.getConfidenceAnalytics(params),
        analyticsApi.getSessionAnalytics(params),
        analyticsApi.getSourceAnalytics(params),
        analyticsApi.getInvestigationAnalytics(params),
        analyticsApi.getAttackCoverage(params),
        analyticsApi.getSensorAnalytics(params),
        analyticsApi.getPipelineHealth(params),
        analyticsApi.getExecutiveSummary(params),
      ]);

      setOverview(ovRes);
      setEventTimeline(evTimeRes);
      setAlertTimeline(altTimeRes);
      setEventAlertOverview(eaRes);
      setDetections(detRes);
      setSeverityData(sevRes);
      setConfidenceData(confRes);
      setSessionData(sessRes);
      setSourceData(srcRes);
      setInvestigationData(invRes);
      setAttackData(attRes);
      setSensorData(senRes);
      setPipelineData(pipeRes);
      setExecutiveSummary(execRes);
    } catch (err: any) {
      setError(err?.message || 'Failed to load security analytics data.');
    } finally {
      setLoading(false);
    }
  }, [getFilterParams]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleGenerateReport = async () => {
    setGeneratingReport(true);
    setError(null);
    try {
      const res = await analyticsApi.generateReport({
        report_title: reportTitle,
        report_type: 'EXECUTIVE_SUMMARY',
        time_range: timeRange,
        start_time: timeRange === 'custom' && customStart ? new Date(customStart).toISOString() : undefined,
        end_time: timeRange === 'custom' && customEnd ? new Date(customEnd).toISOString() : undefined,
        file_format: reportFormat,
        sensor_id: sensorFilter || undefined,
        event_category: categoryFilter || undefined,
        severity: severityFilter || undefined,
        analyst_id: reportAnalyst,
      });
      setGeneratedReport(res);
      setNotification(`Report generated successfully: ${res.report_title} (${res.file_format})`);
    } catch (err: any) {
      setError(err?.message || 'Failed to generate report.');
    } finally {
      setGeneratingReport(false);
    }
  };

  const renderComparisonBadge = (comp?: { percentage_change: number; absolute_change: number }) => {
    if (!comp) return null;
    const isPositive = comp.percentage_change > 0;
    const isZero = comp.percentage_change === 0;

    return (
      <span
        className={`inline-flex items-center text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${
          isZero
            ? 'bg-slate-800 text-slate-400'
            : isPositive
            ? 'bg-amber-950/80 text-amber-400 border border-amber-500/30'
            : 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/30'
        }`}
      >
        {isPositive ? '↑' : isZero ? '•' : '↓'} {Math.abs(comp.percentage_change)}%
      </span>
    );
  };

  return (
    <div className="p-6 max-w-[1720px] mx-auto space-y-6 text-slate-100 font-sans">
      {/* 1. Header Banner */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-3">
            <span className="text-3xl">📈</span>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-slate-100">Security Analytics & Reporting</h1>
              <p className="text-xs text-slate-400 mt-0.5">
                SOC Threat Trends, Behavioral Metrics, Sensor Pipeline Health & Executive Intelligence
              </p>
            </div>
          </div>
        </div>

        {/* Global Controls & Freshness */}
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center gap-2">
            <span className="text-slate-500 uppercase font-mono text-[10px]">Window:</span>
            <span className="font-semibold text-emerald-400">{timeRange.toUpperCase()}</span>
          </div>
          <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center gap-2">
            <span className="text-slate-500 uppercase font-mono text-[10px]">Status:</span>
            <span className="inline-flex items-center gap-1 font-semibold text-teal-300">
              <span className="w-1.5 h-1.5 rounded-full bg-teal-400 animate-pulse"></span>
              Live Telemetry
            </span>
          </div>
          <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center gap-2">
            <span className="text-slate-500 uppercase font-mono text-[10px]">Refreshed:</span>
            <span className="text-slate-300 font-mono text-[11px]">
              {overview?.data_freshness_timestamp ? new Date(overview.data_freshness_timestamp).toLocaleTimeString() : 'Live'}
            </span>
          </div>
          <button
            onClick={loadData}
            className="px-3 py-1.5 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 text-xs font-medium transition-colors"
          >
            ↻ Refresh
          </button>
        </div>
      </div>

      {/* 2. Non-Attribution Caveat */}
      <div className="p-3.5 rounded-lg bg-amber-950/20 border border-amber-500/30 text-amber-200/90 text-xs flex items-start gap-3">
        <span className="text-base shrink-0">⚠️</span>
        <div className="leading-relaxed">
          <strong className="font-semibold text-amber-300 uppercase tracking-wide mr-1">
            Analytics Interpretation Safeguard:
          </strong>
          SnareSight metrics measure observed interactions against deception honeypot assets. Total event volume reflects automated attacker tooling and network noise rather than attack success. Source IP addresses represent routing endpoints (VPNs, egress proxies) and must not be interpreted as confirmed human identities.
        </div>
      </div>

      {/* Notifications / Errors */}
      {error && (
        <div className="p-3 bg-rose-950/40 border border-rose-500/40 rounded-lg text-rose-300 text-xs flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-rose-400 hover:text-rose-200">✕</button>
        </div>
      )}
      {notification && (
        <div className="p-3 bg-emerald-950/40 border border-emerald-500/40 rounded-lg text-emerald-300 text-xs flex items-center justify-between">
          <span>{notification}</span>
          <button onClick={() => setNotification(null)} className="text-emerald-400 hover:text-emerald-200">✕</button>
        </div>
      )}

      {/* 3. Filter Bar (Time Range & Attributes) */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        {/* Time Range Pills */}
        <div className="flex items-center gap-1.5 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
          {(['15m', '1h', '24h', '7d', '30d', 'custom'] as TimeRangeOption[]).map((r) => (
            <button
              key={r}
              onClick={() => setTimeRange(r)}
              className={`px-3 py-1 rounded font-medium transition-colors ${
                timeRange === r
                  ? 'bg-emerald-600/30 text-emerald-300 border border-emerald-500/40'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {r.toUpperCase()}
            </button>
          ))}
        </div>

        {/* Custom Range Inputs */}
        {timeRange === 'custom' && (
          <div className="flex items-center gap-2 text-xs">
            <input
              type="datetime-local"
              value={customStart}
              onChange={(e) => setCustomStart(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200 text-xs"
            />
            <span className="text-slate-500">to</span>
            <input
              type="datetime-local"
              value={customEnd}
              onChange={(e) => setCustomEnd(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200 text-xs"
            />
            <button
              onClick={loadData}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs"
            >
              Apply
            </button>
          </div>
        )}

        {/* Attribute Dropdowns */}
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-300 focus:outline-none"
          >
            <option value="">All Categories</option>
            <option value="AUTHENTICATION">Authentication</option>
            <option value="WEB_REQUEST">Web Request</option>
            <option value="COMMAND_EXECUTION">Command Execution</option>
            <option value="NETWORK">Network Connection</option>
          </select>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-300 focus:outline-none"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>
        </div>
      </div>

      {/* 4. Security Overview Metric Cards (8 KPIs) */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
        <div
          onClick={() => navigate('/events')}
          className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 cursor-pointer transition-all flex flex-col justify-between"
        >
          <div className="text-[10px] font-medium uppercase tracking-wider text-slate-400">Total Events</div>
          <div className="mt-2 text-2xl font-bold font-mono text-slate-100">
            {formatInteger(overview?.total_events, '...')}
          </div>
          <div className="mt-1 flex items-center justify-between text-[10px]">
            <span className="text-slate-500">vs prev</span>
            {renderComparisonBadge(overview?.comparison?.['events'])}
          </div>
        </div>

        <div
          onClick={() => navigate('/alerts')}
          className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 cursor-pointer transition-all flex flex-col justify-between"
        >
          <div className="text-[10px] font-medium uppercase tracking-wider text-slate-400">Total Alerts</div>
          <div className="mt-2 text-2xl font-bold font-mono text-amber-400">
            {formatInteger(overview?.total_alerts, '...')}
          </div>
          <div className="mt-1 flex items-center justify-between text-[10px]">
            <span className="text-slate-500">vs prev</span>
            {renderComparisonBadge(overview?.comparison?.['alerts'])}
          </div>
        </div>

        <div
          onClick={() => navigate('/alerts?severity=CRITICAL')}
          className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 cursor-pointer transition-all flex flex-col justify-between"
        >
          <div className="text-[10px] font-medium uppercase tracking-wider text-rose-400">Critical Alerts</div>
          <div className="mt-2 text-2xl font-bold font-mono text-rose-400">
            {overview?.critical_alerts ?? '0'}
          </div>
          <div className="mt-1 flex items-center justify-between text-[10px]">
            <span className="text-slate-500">vs prev</span>
            {renderComparisonBadge(overview?.comparison?.['critical_alerts'])}
          </div>
        </div>

        <div
          onClick={() => navigate('/alerts?severity=HIGH')}
          className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 cursor-pointer transition-all flex flex-col justify-between"
        >
          <div className="text-[10px] font-medium uppercase tracking-wider text-orange-400">High Severity</div>
          <div className="mt-2 text-2xl font-bold font-mono text-orange-400">
            {overview?.high_alerts ?? '0'}
          </div>
          <div className="mt-1 flex items-center justify-between text-[10px]">
            <span className="text-slate-500">vs prev</span>
            {renderComparisonBadge(overview?.comparison?.['high_alerts'])}
          </div>
        </div>

        <div
          onClick={() => navigate('/sessions')}
          className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 cursor-pointer transition-all flex flex-col justify-between"
        >
          <div className="text-[10px] font-medium uppercase tracking-wider text-slate-400">Active Sessions</div>
          <div className="mt-2 text-2xl font-bold font-mono text-blue-400">
            {formatInteger(overview?.active_sessions, '...')}
          </div>
          <div className="mt-1 flex items-center justify-between text-[10px]">
            <span className="text-slate-500">vs prev</span>
            {renderComparisonBadge(overview?.comparison?.['active_sessions'])}
          </div>
        </div>

        <div
          onClick={() => navigate('/sessions')}
          className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 cursor-pointer transition-all flex flex-col justify-between"
        >
          <div className="text-[10px] font-medium uppercase tracking-wider text-purple-400">Suspicious Sessions</div>
          <div className="mt-2 text-2xl font-bold font-mono text-purple-400">
            {overview?.suspicious_sessions ?? '0'}
          </div>
          <div className="mt-1 flex items-center justify-between text-[10px]">
            <span className="text-slate-500">vs prev</span>
            {renderComparisonBadge(overview?.comparison['suspicious_sessions'])}
          </div>
        </div>

        <div
          onClick={() => navigate('/investigations')}
          className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 cursor-pointer transition-all flex flex-col justify-between"
        >
          <div className="text-[10px] font-medium uppercase tracking-wider text-slate-400">Active Campaigns</div>
          <div className="mt-2 text-2xl font-bold font-mono text-indigo-400">
            {overview?.active_investigations ?? '0'}
          </div>
          <div className="mt-1 text-[10px] text-slate-500">
            Evidence clusters
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-between">
          <div className="text-[10px] font-medium uppercase tracking-wider text-slate-400">Reporting Sensors</div>
          <div className="mt-2 text-2xl font-bold font-mono text-emerald-400">
            {overview?.reporting_sensors ?? '0'}
          </div>
          <div className="mt-1 text-[10px] text-emerald-500/80">
            Nominal streams
          </div>
        </div>
      </div>

      {/* 5. Tabbed Navigation Panels */}
      <div className="flex border-b border-slate-800 gap-2 overflow-x-auto">
        {[
          { id: 'trends', label: 'Trends & Volumes', icon: '📊' },
          { id: 'detections', label: 'Detection Performance', icon: '🎯' },
          { id: 'severity-confidence', label: 'Severity & Confidence', icon: '⚖️' },
          { id: 'sessions-sources', label: 'Sessions & Sources', icon: '⏱️' },
          { id: 'campaigns-attack', label: 'Campaigns & ATT&CK', icon: '🗺️' },
          { id: 'health', label: 'Sensor & Pipeline Health', icon: '🩺' },
          { id: 'executive', label: 'Executive Summary', icon: '📑' },
          { id: 'reports', label: 'Report Generation', icon: '📥' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`pb-3 px-3.5 text-xs font-semibold uppercase tracking-wider border-b-2 transition-colors whitespace-nowrap flex items-center gap-2 ${
              activeTab === tab.id
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <span>{tab.icon}</span>
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* TAB 1: TRENDS & VOLUMES */}
      {activeTab === 'trends' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Event Volume Over Time */}
            <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-slate-200">Event Volume Over Time</h3>
                  <p className="text-[11px] text-slate-400">Discrete telemetry ingestion volume across time intervals</p>
                </div>
                <span className="text-xs font-mono text-emerald-400 font-bold">
                  {formatInteger(eventTimeline?.total_events, '0')} Events
                </span>
              </div>
              <div className="h-56 flex items-end gap-1.5 pt-4 pb-2 border-b border-slate-800">
                {!eventTimeline?.buckets || eventTimeline.buckets.length === 0 ? (
                  <div className="w-full h-full flex items-center justify-center text-xs text-slate-500">
                    No event telemetry captured in selected time window.
                  </div>
                ) : (
                  eventTimeline.buckets.map((b, idx) => {
                    const counts = eventTimeline.buckets.map((x) => x.total_count);
                    const maxCount = Math.max(...(counts.length ? counts : [1]), 1);
                    const heightPct = Math.max(8, (b.total_count / maxCount) * 100);
                    return (
                      <div key={idx} className="flex-1 flex flex-col items-center gap-1.5 h-full justify-end group">
                        <div className="text-[9px] font-mono text-slate-400 opacity-0 group-hover:opacity-100 transition-opacity">
                          {b.total_count}
                        </div>
                        <div
                          className="w-full bg-blue-500/80 hover:bg-blue-400 rounded-t transition-all"
                          style={{ height: `${heightPct}%` }}
                          title={`${b.timestamp}: ${b.total_count} events`}
                        />
                        <span className="text-[9px] font-mono text-slate-500 truncate w-full text-center">
                          {b.timestamp}
                        </span>
                      </div>
                    );
                  })
                )}
              </div>
            </div>

            {/* Alert Volume Over Time */}
            <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-slate-200">Alert Volume Over Time</h3>
                  <p className="text-[11px] text-slate-400">Triggered security alerts grouped by severity and window</p>
                </div>
                <span className="text-xs font-mono text-amber-400 font-bold">
                  {formatInteger(alertTimeline?.total_alerts, '0')} Alerts
                </span>
              </div>
              <div className="h-56 flex items-end gap-1.5 pt-4 pb-2 border-b border-slate-800">
                {!alertTimeline?.buckets || alertTimeline.buckets.length === 0 ? (
                  <div className="w-full h-full flex items-center justify-center text-xs text-slate-500">
                    No security alerts recorded in selected time window.
                  </div>
                ) : (
                  alertTimeline.buckets.map((b, idx) => {
                    const counts = alertTimeline.buckets.map((x) => x.total_count);
                    const maxCount = Math.max(...(counts.length ? counts : [1]), 1);
                    const heightPct = Math.max(8, (b.total_count / maxCount) * 100);
                    return (
                      <div key={idx} className="flex-1 flex flex-col items-center gap-1.5 h-full justify-end group">
                        <div className="text-[9px] font-mono text-slate-400 opacity-0 group-hover:opacity-100 transition-opacity">
                          {b.total_count}
                        </div>
                        <div
                          className="w-full bg-amber-500/80 hover:bg-amber-400 rounded-t transition-all"
                          style={{ height: `${heightPct}%` }}
                          title={`${b.timestamp}: ${b.total_count} alerts`}
                        />
                        <span className="text-[9px] font-mono text-slate-500 truncate w-full text-center">
                          {b.timestamp}
                        </span>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          </div>

          {/* Event-to-Alert Correlation Card */}
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="space-y-1">
              <h3 className="text-sm font-semibold text-slate-200">Event-to-Alert Correlation Density</h3>
              <p className="text-xs text-slate-400 leading-relaxed max-w-3xl">
                {eventAlertOverview?.explanation_notice}
              </p>
            </div>
            <div className="flex items-center gap-6 shrink-0">
              <div className="text-right">
                <div className="text-[10px] font-mono uppercase text-slate-500">Density Ratio</div>
                <div className="text-2xl font-bold font-mono text-blue-400">
                  {eventAlertOverview?.event_to_alert_ratio} : 1
                </div>
              </div>
              <div className="text-right">
                <div className="text-[10px] font-mono uppercase text-slate-500">Supporting Telemetry</div>
                <div className="text-2xl font-bold font-mono text-emerald-400">
                  {eventAlertOverview?.events_supporting_alerts} Events
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: DETECTION PERFORMANCE */}
      {activeTab === 'detections' && (
        <div className="space-y-6">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
            <h3 className="text-sm font-semibold text-slate-200">Detection Rule Evaluation Performance</h3>
            <p className="text-xs text-slate-400 mt-0.5">{detections?.performance_caveat}</p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Top Triggered Rules */}
            <div className="lg:col-span-2 rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
              <div className="p-4 border-b border-slate-800">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                  Most Frequently Triggered Detection Rules
                </h4>
              </div>
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 font-mono text-[11px] uppercase">
                  <tr>
                    <th className="py-2.5 px-4">Rule ID</th>
                    <th className="py-2.5 px-4">Name</th>
                    <th className="py-2.5 px-4">Category</th>
                    <th className="py-2.5 px-4 text-right">Triggers</th>
                    <th className="py-2.5 px-4 text-right">Confidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 text-slate-300">
                  {(detections?.top_rules || []).map((r) => (
                    <tr key={r.rule_id} className="hover:bg-slate-800/40">
                      <td className="py-2.5 px-4 font-mono font-semibold text-emerald-400">{r.rule_id}</td>
                      <td className="py-2.5 px-4 font-medium text-slate-100">{r.rule_name}</td>
                      <td className="py-2.5 px-4 font-mono text-[11px] text-slate-400">{r.category}</td>
                      <td className="py-2.5 px-4 text-right font-mono font-bold text-amber-400">{r.trigger_count}</td>
                      <td className="py-2.5 px-4 text-right font-mono text-teal-400">{r.default_confidence}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Category Breakdown */}
            <div className="rounded-xl bg-slate-900 border border-slate-800 p-4 space-y-3">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                Detections by Attack Category
              </h4>
              <div className="space-y-3 pt-2">
                {(detections?.category_breakdown || []).map((cat) => (
                  <div key={cat.category} className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-slate-300">{cat.category}</span>
                      <span className="text-emerald-400 font-bold">{cat.alert_count} ({cat.percentage}%)</span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                      <div className="h-full bg-emerald-500 rounded-full" style={{ width: `${cat.percentage}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: SEVERITY & CONFIDENCE */}
      {activeTab === 'severity-confidence' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Severity Distribution */}
            <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
              <div>
                <h3 className="text-sm font-semibold text-slate-200">Alert Severity Distribution</h3>
                <p className="text-xs text-slate-400 mt-1">{severityData?.definitions_notice}</p>
              </div>
              <div className="space-y-3">
                {(severityData?.breakdown || []).map((item) => (
                  <div key={item.severity} className="space-y-1.5">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="font-semibold text-slate-200">{item.severity}</span>
                      <span className="text-slate-400">{item.count} alerts ({item.percentage}%)</span>
                    </div>
                    <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all"
                        style={{ width: `${item.percentage}%`, backgroundColor: item.color }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Confidence Distribution */}
            <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
              <div>
                <h3 className="text-sm font-semibold text-slate-200">Detection Confidence Scoring</h3>
                <p className="text-xs text-slate-400 mt-1">{confidenceData?.interpretation_guidelines}</p>
              </div>
              <div className="space-y-3">
                {(confidenceData?.buckets || []).map((b) => (
                  <div key={b.range_label} className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800 space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="font-semibold text-blue-300 font-mono">{b.range_label}</span>
                      <span className="font-mono text-emerald-400 font-bold">{b.count} ({b.percentage}%)</span>
                    </div>
                    <p className="text-[11px] text-slate-500 leading-tight">{b.description}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: SESSIONS & SOURCES */}
      {activeTab === 'sessions-sources' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Session Duration Distribution */}
            <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
              <div>
                <h3 className="text-sm font-semibold text-slate-200">Session Duration Distribution</h3>
                <p className="text-xs text-slate-400 mt-1">{sessionData?.interpretation_limits}</p>
              </div>
              <div className="space-y-3">
                {(sessionData?.duration_distribution || []).map((d) => (
                  <div key={d.bucket_label} className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-slate-300">{d.bucket_label}</span>
                      <span className="text-blue-400 font-bold">{d.count} ({d.percentage}%)</span>
                    </div>
                    <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div className="h-full bg-blue-500 rounded-full" style={{ width: `${d.percentage}%` }} />
                    </div>
                  </div>
                ))}
              </div>
              <div className="pt-2 flex items-center justify-between text-xs border-t border-slate-800 font-mono text-slate-400">
                <span>Avg Duration: <strong className="text-slate-200">{sessionData?.average_duration_seconds}s</strong></span>
                <span>Events/Session: <strong className="text-slate-200">{sessionData?.avg_events_per_session}</strong></span>
              </div>
            </div>

            {/* Top Recurring Source Profiles */}
            <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
              <div>
                <h3 className="text-sm font-semibold text-slate-200">Recurring Source IP Profiles</h3>
                <p className="text-xs text-slate-400 mt-1">{sourceData?.privacy_and_identity_caveat}</p>
              </div>
              <div className="space-y-2">
                {(sourceData?.top_recurring_profiles || []).slice(0, 5).map((p) => (
                  <div
                    key={p.profile_id}
                    onClick={() => navigate('/source-intelligence')}
                    className="p-3 rounded-lg bg-slate-950 border border-slate-800 hover:border-slate-700 cursor-pointer flex items-center justify-between text-xs"
                  >
                    <div>
                      <div className="font-mono font-semibold text-emerald-400">{p.source_ip}</div>
                      <div className="text-[10px] text-slate-500 font-mono">Recurrence: {p.recurrence_count} sessions</div>
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300">
                      {p.threat_category}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 5: CAMPAIGNS & ATT&CK */}
      {activeTab === 'campaigns-attack' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Campaign Clusters */}
            <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-slate-200">Investigation Campaign Clusters</h3>
                  <p className="text-xs text-slate-400 mt-0.5">{investigationData?.campaign_definition_notice}</p>
                </div>
                <button
                  onClick={() => navigate('/investigations')}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs"
                >
                  View All ↗
                </button>
              </div>
              <div className="space-y-2">
                {(investigationData?.top_investigations || []).map((inv) => (
                  <div
                    key={inv.cluster_id}
                    className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between text-xs"
                  >
                    <div>
                      <div className="font-semibold text-slate-200">{inv.cluster_name}</div>
                      <div className="text-[10px] text-slate-500 font-mono">
                        Lead: {inv.lead_analyst || 'Unassigned'} | Alerts: {inv.alert_count}
                      </div>
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-blue-950 text-blue-400 border border-blue-500/30">
                      {inv.status}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* ATT&CK Tactic Coverage */}
            <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-slate-200">MITRE ATT&CK Enterprise Coverage</h3>
                  <p className="text-xs text-slate-400 mt-0.5">{attackData?.coverage_caveat}</p>
                </div>
                <button
                  onClick={() => navigate('/mitre')}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs"
                >
                  Matrix View ↗
                </button>
              </div>
              <div className="space-y-2.5 max-h-72 overflow-y-auto pr-1">
                {(attackData?.tactics || []).map((t) => (
                  <div key={t.tactic_id} className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-slate-300">{t.tactic_id}: {t.tactic_name}</span>
                      <span className="text-emerald-400 font-bold">{t.mapped_techniques}/{t.total_techniques} ({t.coverage_percentage}%)</span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                      <div className="h-full bg-teal-500 rounded-full" style={{ width: `${t.coverage_percentage}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 6: SENSOR & PIPELINE HEALTH */}
      {activeTab === 'health' && (
        <div className="space-y-6">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Honeypot Sensor Operations & Telemetry Freshness</h3>
              <p className="text-xs text-slate-400 mt-0.5">{sensorData?.operational_notice}</p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {(sensorData?.sensors || []).map((s) => (
                <div key={s.sensor_id} className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-xs text-slate-200 truncate">{s.sensor_name}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono ${
                        s.status === 'ONLINE'
                          ? 'bg-emerald-950 text-emerald-400 border border-emerald-500/40'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {s.status}
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-500 space-y-0.5">
                    <div>Type: {s.honeypot_type}</div>
                    <div>Window Events: {s.event_count_window}</div>
                    <div>Last Telemetry: {s.last_telemetry ? new Date(s.last_telemetry).toLocaleTimeString() : 'Never'}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <h3 className="text-sm font-semibold text-slate-200">Pipeline Performance & Error Invariants</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono">
              <div className="p-3 bg-slate-950 rounded-lg">
                <div className="text-slate-500 uppercase text-[10px]">Ingested Events</div>
                <div className="text-xl font-bold text-slate-200 mt-1">{pipelineData?.total_events_ingested}</div>
              </div>
              <div className="p-3 bg-slate-950 rounded-lg">
                <div className="text-slate-500 uppercase text-[10px]">Duplicates Filtered</div>
                <div className="text-xl font-bold text-blue-400 mt-1">{pipelineData?.duplicate_events}</div>
              </div>
              <div className="p-3 bg-slate-950 rounded-lg">
                <div className="text-slate-500 uppercase text-[10px]">Validation Failures</div>
                <div className="text-xl font-bold text-emerald-400 mt-1">{pipelineData?.validation_failures}</div>
              </div>
              <div className="p-3 bg-slate-950 rounded-lg">
                <div className="text-slate-500 uppercase text-[10px]">Pipeline State</div>
                <div className="text-xl font-bold text-teal-400 mt-1">{pipelineData?.pipeline_state}</div>
              </div>
            </div>
            <p className="text-xs text-slate-400 pt-1">{pipelineData?.notes}</p>
          </div>
        </div>
      )}

      {/* TAB 7: EXECUTIVE SUMMARY */}
      {activeTab === 'executive' && (
        <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-6 max-w-5xl">
          <div>
            <h3 className="text-lg font-bold text-slate-100">Executive Security Operations Briefing</h3>
            <p className="text-xs text-slate-400 mt-1">
              Deterministic, evidence-grounded summary synthesized from live honeypot telemetry and investigation clusters.
            </p>
          </div>

          <div className="space-y-4 text-xs text-slate-300 leading-relaxed">
            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-1">
              <h4 className="font-semibold text-blue-300 uppercase font-mono text-[11px]">Observed Threat Activity</h4>
              <p>{executiveSummary?.observed_activity_narrative}</p>
            </div>

            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-1">
              <h4 className="font-semibold text-amber-300 uppercase font-mono text-[11px]">Alert Severity & Attack Vectors</h4>
              <p>{executiveSummary?.alert_trends_narrative}</p>
            </div>

            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-1">
              <h4 className="font-semibold text-emerald-300 uppercase font-mono text-[11px]">Detection Rule Operations</h4>
              <p>{executiveSummary?.detection_categories_narrative}</p>
            </div>

            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-1">
              <h4 className="font-semibold text-purple-300 uppercase font-mono text-[11px]">Investigation Developments</h4>
              <p>{executiveSummary?.investigation_developments_narrative}</p>
            </div>

            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-1">
              <h4 className="font-semibold text-teal-300 uppercase font-mono text-[11px]">Sensor & Pipeline Status</h4>
              <p>{executiveSummary?.sensor_and_pipeline_narrative}</p>
            </div>
          </div>

          {/* Limitations Box */}
          <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-500/30 text-amber-200/90 text-xs space-y-2">
            <h4 className="font-semibold text-amber-300 uppercase font-mono text-[11px]">Documented Operational Limitations</h4>
            <ul className="list-disc list-inside space-y-1 text-slate-300">
              {(executiveSummary?.operational_limitations || []).map((lim, idx) => (
                <li key={idx}>{lim}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* TAB 8: REPORT GENERATION */}
      {activeTab === 'reports' && (
        <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-6 max-w-4xl">
          <div>
            <h3 className="text-lg font-bold text-slate-100">Exportable Security Report Generator</h3>
            <p className="text-xs text-slate-400 mt-1">
              Produce formal PDF executive briefings or raw CSV forensic summaries with sensitive-data redaction and audit logging.
            </p>
          </div>

          <div className="space-y-4 text-xs">
            <div>
              <label className="block text-slate-400 font-mono text-[10px] uppercase mb-1">Report Title</label>
              <input
                type="text"
                value={reportTitle}
                onChange={(e) => setReportTitle(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200"
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-slate-400 font-mono text-[10px] uppercase mb-1">File Format</label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setReportFormat('PDF')}
                    className={`py-2 rounded-lg font-semibold border ${
                      reportFormat === 'PDF'
                        ? 'bg-emerald-950 text-emerald-400 border-emerald-500'
                        : 'bg-slate-950 text-slate-400 border-slate-800'
                    }`}
                  >
                    PDF Document
                  </button>
                  <button
                    type="button"
                    onClick={() => setReportFormat('CSV')}
                    className={`py-2 rounded-lg font-semibold border ${
                      reportFormat === 'CSV'
                        ? 'bg-blue-950 text-blue-400 border-blue-500'
                        : 'bg-slate-950 text-slate-400 border-slate-800'
                    }`}
                  >
                    CSV Data Export
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-slate-400 font-mono text-[10px] uppercase mb-1">Analyst Attribution</label>
                <input
                  type="text"
                  value={reportAnalyst}
                  onChange={(e) => setReportAnalyst(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200"
                />
              </div>
            </div>

            <div className="pt-2">
              <button
                disabled={generatingReport}
                onClick={handleGenerateReport}
                className="px-6 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 text-xs font-bold disabled:opacity-50"
              >
                {generatingReport ? 'Compiling Artifact...' : 'Generate Report Artifact'}
              </button>
            </div>
          </div>

          {generatedReport && (
            <div className="p-4 rounded-xl bg-slate-950 border border-emerald-500/30 flex items-center justify-between">
              <div>
                <div className="font-semibold text-xs text-slate-100">{generatedReport.report_title}</div>
                <div className="text-[11px] font-mono text-slate-400 mt-0.5">
                  Format: {generatedReport.file_format} | Size: {Math.round(generatedReport.file_size_bytes / 1024)} KB | Status: {generatedReport.status}
                </div>
              </div>
              <a
                href={generatedReport.download_url}
                download
                className="px-4 py-2 rounded-lg bg-emerald-600/30 hover:bg-emerald-600/40 text-emerald-300 border border-emerald-500/40 text-xs font-bold transition-colors"
              >
                Download {generatedReport.file_format} ⤓
              </a>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default SecurityAnalyticsPage;

