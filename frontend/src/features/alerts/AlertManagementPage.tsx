import React, { useState, useEffect, useCallback } from 'react';
import {
  AlertListItem,
  AlertSummaryResponse,
  AlertDetailResponse,
  AlertEvidenceItem,
  AlertRelationshipsResponse,
  AlertAuditLogItem,
  AlertNoteItem,
  AlertFilterState,
  AlertSeverity,
  AlertStatus,
  TriageDecisionType,
} from '../../types/alerts';
import * as alertsApi from '../../services/alertsApi';

export const AlertManagementPage: React.FC = () => {
  // State: Data
  const [alerts, setAlerts] = useState<AlertListItem[]>([]);
  const [totalAlerts, setTotalAlerts] = useState(0);
  const [summary, setSummary] = useState<AlertSummaryResponse | null>(null);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [alertDetail, setAlertDetail] = useState<AlertDetailResponse | null>(null);
  const [evidenceList, setEvidenceList] = useState<AlertEvidenceItem[]>([]);
  const [relationships, setRelationships] = useState<AlertRelationshipsResponse | null>(null);
  const [historyList, setHistoryList] = useState<AlertAuditLogItem[]>([]);
  const [notesList, setNotesList] = useState<AlertNoteItem[]>([]);

  // State: Loading & UI
  const [loading, setLoading] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [filterDrawerOpen, setFilterDrawerOpen] = useState(false);
  const [activeDetailTab, setActiveDetailTab] = useState<'overview' | 'evidence' | 'scoring' | 'prioritization' | 'context' | 'actions' | 'notes' | 'audit'>('overview');

  // State: Filter State
  const [filters, setFilters] = useState<AlertFilterState>({
    page: 1,
    limit: 25,
    sortBy: 'generated_at',
    sortOrder: 'desc',
    unassignedOnly: false,
  });

  // State: Form Inputs for Triage Actions
  const [assigneeInput, setAssigneeInput] = useState('analyst_current');
  const [assignNoteInput, setAssignNoteInput] = useState('');
  const [escalateReason, setEscalateReason] = useState('');
  const [escalateRole, setEscalateRole] = useState('TIER_2_ANALYST');
  const [resolveCategory, setResolveCategory] = useState('BENIGN_SCANNER');
  const [resolveReason, setResolveReason] = useState('');
  const [closeReason, setCloseReason] = useState('');
  const [newNoteContent, setNewNoteContent] = useState('');
  const [triageDecisionChoice, setTriageDecisionChoice] = useState<TriageDecisionType>('LIKELY_TRUE_POSITIVE');
  const [triageJustification, setTriageJustification] = useState('');

  // 1. Load Summary Metrics
  const loadSummary = useCallback(async () => {
    try {
      const data = await alertsApi.fetchAlertsSummary();
      setSummary(data);
    } catch (err: any) {
      console.error('Failed to load alert summary:', err);
    }
  }, []);

  // 2. Load Alert Queue
  const loadAlerts = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await alertsApi.fetchAlertsQueue(filters);
      setAlerts(data.items);
      setTotalAlerts(data.total);
    } catch (err: any) {
      setError(err.message || 'Error loading alerts');
    } finally {
      setLoading(false);
    }
  }, [filters]);

  // Initial & Filter Triggers
  useEffect(() => {
    loadSummary();
    loadAlerts();
  }, [loadSummary, loadAlerts]);

  // 3. Load Detail & Forensic Context
  const selectAlert = async (alertId: string) => {
    setSelectedAlertId(alertId);
    setDetailLoading(true);
    setActionError(null);
    try {
      const [detail, ev, rel, hist, notes] = await Promise.all([
        alertsApi.fetchAlertDetail(alertId),
        alertsApi.fetchAlertEvidence(alertId).catch(() => []),
        alertsApi.fetchAlertRelationships(alertId).catch(() => null),
        alertsApi.fetchAlertHistory(alertId).catch(() => []),
        alertsApi.fetchAlertNotes(alertId).catch(() => []),
      ]);
      setAlertDetail(detail);
      setEvidenceList(ev);
      setRelationships(rel);
      setHistoryList(hist);
      setNotesList(notes);
    } catch (err: any) {
      setActionError(err.message || 'Error loading alert details');
    } finally {
      setDetailLoading(false);
    }
  };

  // --- Action Handlers ---

  const handleAcknowledge = async () => {
    if (!selectedAlertId) return;
    try {
      const updated = await alertsApi.acknowledgeAlert(selectedAlertId, 'current_analyst', 'Acknowledged from queue view');
      setAlertDetail(updated);
      loadSummary();
      loadAlerts();
      const hist = await alertsApi.fetchAlertHistory(selectedAlertId);
      setHistoryList(hist);
    } catch (err: any) {
      setActionError(err.message);
    }
  };

  const handleAssign = async () => {
    if (!selectedAlertId || !assigneeInput.trim()) return;
    try {
      const updated = await alertsApi.assignAlert(selectedAlertId, assigneeInput.trim(), 'current_analyst', assignNoteInput.trim() || undefined);
      setAlertDetail(updated);
      setAssignNoteInput('');
      loadAlerts();
      const hist = await alertsApi.fetchAlertHistory(selectedAlertId);
      setHistoryList(hist);
    } catch (err: any) {
      setActionError(err.message);
    }
  };

  const handleStartInvestigation = async () => {
    if (!selectedAlertId) return;
    try {
      const updated = await alertsApi.startInvestigation(selectedAlertId, 'current_analyst');
      setAlertDetail(updated);
      loadSummary();
      loadAlerts();
      const hist = await alertsApi.fetchAlertHistory(selectedAlertId);
      setHistoryList(hist);
    } catch (err: any) {
      setActionError(err.message);
    }
  };

  const handleEscalate = async () => {
    if (!selectedAlertId || !escalateReason.trim()) {
      setActionError('Escalation reason is required.');
      return;
    }
    try {
      const updated = await alertsApi.escalateAlert(selectedAlertId, 'current_analyst', escalateReason.trim(), escalateRole);
      setAlertDetail(updated);
      setEscalateReason('');
      loadSummary();
      loadAlerts();
      const hist = await alertsApi.fetchAlertHistory(selectedAlertId);
      setHistoryList(hist);
    } catch (err: any) {
      setActionError(err.message);
    }
  };

  const handleResolve = async () => {
    if (!selectedAlertId || !resolveReason.trim()) {
      setActionError('Resolution reason is required.');
      return;
    }
    try {
      const updated = await alertsApi.resolveAlert(selectedAlertId, 'current_analyst', resolveCategory, resolveReason.trim());
      setAlertDetail(updated);
      setResolveReason('');
      loadSummary();
      loadAlerts();
      const hist = await alertsApi.fetchAlertHistory(selectedAlertId);
      setHistoryList(hist);
    } catch (err: any) {
      setActionError(err.message);
    }
  };

  const handleClose = async () => {
    if (!selectedAlertId || !closeReason.trim()) {
      setActionError('Closure reason is required.');
      return;
    }
    try {
      const updated = await alertsApi.closeAlert(selectedAlertId, 'current_analyst', closeReason.trim());
      setAlertDetail(updated);
      setCloseReason('');
      loadSummary();
      loadAlerts();
      const hist = await alertsApi.fetchAlertHistory(selectedAlertId);
      setHistoryList(hist);
    } catch (err: any) {
      setActionError(err.message);
    }
  };

  const handleAddNote = async () => {
    if (!selectedAlertId || !newNoteContent.trim()) return;
    try {
      const note = await alertsApi.addAlertNote(selectedAlertId, 'current_analyst', newNoteContent.trim());
      setNotesList((prev) => [note, ...prev]);
      setNewNoteContent('');
      const hist = await alertsApi.fetchAlertHistory(selectedAlertId);
      setHistoryList(hist);
    } catch (err: any) {
      setActionError(err.message);
    }
  };

  const handleTriageDecision = async () => {
    if (!selectedAlertId || !triageJustification.trim()) {
      setActionError('Triage decision requires an evidence-backed justification.');
      return;
    }
    try {
      const updated = await alertsApi.recordTriageDecision(selectedAlertId, 'current_analyst', triageDecisionChoice, triageJustification.trim());
      setAlertDetail(updated);
      setTriageJustification('');
      loadAlerts();
      const hist = await alertsApi.fetchAlertHistory(selectedAlertId);
      setHistoryList(hist);
    } catch (err: any) {
      setActionError(err.message);
    }
  };

  // Helper Badge Colors
  const getSeverityBadge = (sev: AlertSeverity) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-950/80 text-red-400 border-red-700 font-bold';
      case 'HIGH':
        return 'bg-orange-950/80 text-orange-400 border-orange-700';
      case 'MEDIUM':
        return 'bg-amber-950/80 text-amber-400 border-amber-700';
      case 'LOW':
        return 'bg-blue-950/80 text-blue-400 border-blue-700';
      default:
        return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  const getPriorityBadge = (p: string) => {
    if (p.includes('P1')) return 'bg-red-500/20 text-red-300 border-red-500/50';
    if (p.includes('P2')) return 'bg-amber-500/20 text-amber-300 border-amber-500/50';
    if (p.includes('P3')) return 'bg-blue-500/20 text-blue-300 border-blue-500/50';
    return 'bg-slate-800 text-slate-400 border-slate-700';
  };

  const getStatusBadge = (st: AlertStatus) => {
    switch (st) {
      case 'NEW':
        return 'bg-blue-900/40 text-blue-300 border-blue-700';
      case 'ACKNOWLEDGED':
        return 'bg-amber-900/40 text-amber-300 border-amber-700';
      case 'INVESTIGATING':
        return 'bg-purple-900/40 text-purple-300 border-purple-700';
      case 'ESCALATED':
        return 'bg-rose-900/40 text-rose-300 border-rose-700 animate-pulse';
      case 'RESOLVED':
        return 'bg-emerald-900/40 text-emerald-300 border-emerald-700';
      case 'CLOSED':
        return 'bg-slate-900 text-slate-500 border-slate-800';
    }
  };

  return (
    <div className="flex flex-col h-full bg-slate-950 text-slate-100 overflow-hidden font-sans">
      {/* 1. Header & Aggregate Metric Chips */}
      <div className="p-5 border-b border-slate-800 shrink-0 bg-slate-900/40">
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-xl font-bold tracking-tight text-slate-100">Alert Management & Triage Center</h1>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-blue-950 text-blue-400 border border-blue-800">
                SOC TIER 1/2
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Real-time honeypot threat alerts, explainable detections, independent severity/confidence, and auditable triage lifecycle.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => {
                loadSummary();
                loadAlerts();
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-300 transition-colors border border-slate-700"
              title="Refresh alerts"
            >
              🔄 Refresh
            </button>
            <span className="text-[11px] text-slate-500 font-mono">
              Last refresh: {summary ? new Date(summary.last_refreshed_at).toLocaleTimeString() : '...'}
            </span>
          </div>
        </div>

        {/* Global Metric Chips */}
        {summary && (
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-2.5 mt-4">
            <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800">
              <div className="text-[10px] uppercase font-bold text-slate-500">Total Alerts</div>
              <div className="text-lg font-bold text-slate-100 mt-0.5">{summary.total_matching}</div>
            </div>
            <div className="p-2.5 rounded-lg bg-blue-950/30 border border-blue-900/60">
              <div className="text-[10px] uppercase font-bold text-blue-400">New Alerts</div>
              <div className="text-lg font-bold text-blue-200 mt-0.5">{summary.new_alerts}</div>
            </div>
            <div className="p-2.5 rounded-lg bg-rose-950/30 border border-rose-900/60">
              <div className="text-[10px] uppercase font-bold text-rose-400">Requires Attention</div>
              <div className="text-lg font-bold text-rose-200 mt-0.5">{summary.requiring_attention}</div>
            </div>
            <div className="p-2.5 rounded-lg bg-amber-950/30 border border-amber-900/60">
              <div className="text-[10px] uppercase font-bold text-amber-400">Unassigned</div>
              <div className="text-lg font-bold text-amber-200 mt-0.5">{summary.unassigned_alerts}</div>
            </div>
            <div className="p-2.5 rounded-lg bg-purple-950/30 border border-purple-900/60">
              <div className="text-[10px] uppercase font-bold text-purple-400">Investigating</div>
              <div className="text-lg font-bold text-purple-200 mt-0.5">{summary.investigating_alerts}</div>
            </div>
            <div className="p-2.5 rounded-lg bg-emerald-950/30 border border-emerald-900/60">
              <div className="text-[10px] uppercase font-bold text-emerald-400">Resolved / Closed</div>
              <div className="text-lg font-bold text-emerald-200 mt-0.5">
                {summary.resolved_alerts + summary.closed_alerts}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* 2. Lifecycle Cards Bar (Click to Filter) */}
      {summary && (
        <div className="px-5 py-2.5 border-b border-slate-800 bg-slate-900/20 flex items-center gap-2 overflow-x-auto shrink-0 text-xs">
          <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mr-1">Lifecycle:</span>
          {(['NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'ESCALATED', 'RESOLVED', 'CLOSED'] as AlertStatus[]).map((st) => {
            const count =
              st === 'NEW'
                ? summary.new_alerts
                : st === 'ACKNOWLEDGED'
                ? summary.acknowledged_alerts
                : st === 'INVESTIGATING'
                ? summary.investigating_alerts
                : st === 'ESCALATED'
                ? summary.escalated_alerts
                : st === 'RESOLVED'
                ? summary.resolved_alerts
                : summary.closed_alerts;
            const isSelected = filters.status === st;

            return (
              <button
                key={st}
                onClick={() =>
                  setFilters((prev) => ({
                    ...prev,
                    status: isSelected ? undefined : st,
                    page: 1,
                  }))
                }
                className={`px-2.5 py-1 rounded border transition-all flex items-center gap-1.5 ${
                  isSelected
                    ? 'bg-blue-600 text-white border-blue-500 shadow-md shadow-blue-900/30 font-semibold'
                    : 'bg-slate-900/80 text-slate-300 border-slate-800 hover:bg-slate-800'
                }`}
              >
                <span>{st}</span>
                <span className={`text-[10px] px-1.5 py-0.2 rounded ${isSelected ? 'bg-blue-800 text-blue-100' : 'bg-slate-800 text-slate-400'}`}>
                  {count}
                </span>
              </button>
            );
          })}

          <div className="h-4 w-px bg-slate-800 mx-2" />

          {/* Unassigned quick filter */}
          <button
            onClick={() =>
              setFilters((prev) => ({
                ...prev,
                unassignedOnly: !prev.unassignedOnly,
                page: 1,
              }))
            }
            className={`px-2.5 py-1 rounded border transition-all ${
              filters.unassignedOnly
                ? 'bg-amber-600 text-white border-amber-500 font-semibold'
                : 'bg-slate-900/80 text-slate-400 border-slate-800 hover:bg-slate-800'
            }`}
          >
            👤 Unassigned Only
          </button>
        </div>
      )}

      {/* 3. Search & Filter Bar */}
      <div className="p-3 border-b border-slate-800 bg-slate-900/40 flex items-center justify-between gap-3 shrink-0">
        <div className="flex-1 flex items-center gap-2">
          <div className="relative flex-1 max-w-md">
            <input
              type="text"
              placeholder="Search by title, rule ID, source IP, or decoy..."
              value={filters.search || ''}
              onChange={(e) =>
                setFilters((prev) => ({
                  ...prev,
                  search: e.target.value || undefined,
                  page: 1,
                }))
              }
              className="w-full bg-slate-900 border border-slate-700/80 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
            {filters.search && (
              <button
                onClick={() => setFilters((prev) => ({ ...prev, search: undefined, page: 1 }))}
                className="absolute right-2.5 top-1.5 text-slate-400 hover:text-slate-200 text-xs"
              >
                ✕
              </button>
            )}
          </div>

          {/* Severity Dropdown */}
          <select
            value={filters.severity || ''}
            onChange={(e) =>
              setFilters((prev) => ({
                ...prev,
                severity: (e.target.value as AlertSeverity) || undefined,
                page: 1,
              }))
            }
            className="bg-slate-900 border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-blue-500"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
            <option value="INFO">INFO</option>
          </select>

          {/* Sort By */}
          <select
            value={`${filters.sortBy}:${filters.sortOrder}`}
            onChange={(e) => {
              const [sb, so] = e.target.value.split(':');
              setFilters((prev) => ({
                ...prev,
                sortBy: sb,
                sortOrder: so as 'asc' | 'desc',
                page: 1,
              }));
            }}
            className="bg-slate-900 border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-blue-500"
          >
            <option value="generated_at:desc">Newest First</option>
            <option value="generated_at:asc">Oldest First</option>
            <option value="priority_score:desc">Highest Priority First</option>
            <option value="confidence:desc">Highest Confidence First</option>
          </select>
        </div>

        <button
          onClick={() => setFilterDrawerOpen(!filterDrawerOpen)}
          className={`px-3 py-1.5 rounded-lg border text-xs font-medium flex items-center gap-1.5 ${
            filterDrawerOpen ? 'bg-blue-600 text-white border-blue-500' : 'bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-700'
          }`}
        >
          ⚙️ Advanced Filters
        </button>
      </div>

      {/* Collapsible Advanced Filters */}
      {filterDrawerOpen && (
        <div className="p-4 bg-slate-900 border-b border-slate-800 grid grid-cols-1 md:grid-cols-4 gap-3 text-xs shrink-0">
          <div>
            <label className="block text-slate-400 font-semibold mb-1">Category</label>
            <input
              type="text"
              placeholder="e.g. BRUTE_FORCE, RECON"
              value={filters.category || ''}
              onChange={(e) => setFilters((prev) => ({ ...prev, category: e.target.value || undefined, page: 1 }))}
              className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-slate-200"
            />
          </div>
          <div>
            <label className="block text-slate-400 font-semibold mb-1">Assigned Analyst</label>
            <input
              type="text"
              placeholder="Analyst ID"
              value={filters.assignedAnalyst || ''}
              onChange={(e) => setFilters((prev) => ({ ...prev, assignedAnalyst: e.target.value || undefined, page: 1 }))}
              className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-slate-200"
            />
          </div>
          <div>
            <label className="block text-slate-400 font-semibold mb-1">Date Start (ISO/UTC)</label>
            <input
              type="datetime-local"
              onChange={(e) => setFilters((prev) => ({ ...prev, dateStart: e.target.value ? new Date(e.target.value).toISOString() : undefined, page: 1 }))}
              className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-slate-200"
            />
          </div>
          <div className="flex items-end">
            <button
              onClick={() =>
                setFilters({
                  page: 1,
                  limit: 25,
                  sortBy: 'generated_at',
                  sortOrder: 'desc',
                  unassignedOnly: false,
                })
              }
              className="w-full py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 font-medium"
            >
              Reset All Filters
            </button>
          </div>
        </div>
      )}

      {/* 4. Main Body: Split View (Queue Table + Detail Drawer) */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left: Alerts Table */}
        <div className="flex-1 flex flex-col overflow-hidden border-r border-slate-800">
          <div className="flex-1 overflow-y-auto">
            {loading ? (
              <div className="p-8 text-center text-slate-400 text-xs">Loading security alerts...</div>
            ) : error ? (
              <div className="p-8 text-center text-red-400 text-xs">{error}</div>
            ) : alerts.length === 0 ? (
              <div className="p-12 text-center text-slate-500 text-xs">
                No alerts match current filter criteria.
              </div>
            ) : (
              <table className="w-full text-left text-xs border-collapse">
                <thead className="bg-slate-900/80 sticky top-0 border-b border-slate-800 text-[11px] font-semibold text-slate-400">
                  <tr>
                    <th className="p-2.5 pl-4">Priority</th>
                    <th className="p-2.5">Severity</th>
                    <th className="p-2.5">Finding / Title</th>
                    <th className="p-2.5">Status</th>
                    <th className="p-2.5">Confidence</th>
                    <th className="p-2.5">Target & Decoy</th>
                    <th className="p-2.5">Source IP</th>
                    <th className="p-2.5">Assigned</th>
                    <th className="p-2.5 pr-4">Generated</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-sans">
                  {alerts.map((a) => {
                    const isSelected = selectedAlertId === a.alert_id;
                    return (
                      <tr
                        key={a.alert_id}
                        onClick={() => selectAlert(a.alert_id)}
                        className={`cursor-pointer transition-colors ${
                          isSelected
                            ? 'bg-blue-950/40 border-l-4 border-l-blue-500'
                            : 'hover:bg-slate-900/60'
                        }`}
                      >
                        <td className="p-2.5 pl-4 whitespace-nowrap">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${getPriorityBadge(a.priority_level)}`}>
                            {a.priority_level.replace('_', ' ')}
                          </span>
                        </td>
                        <td className="p-2.5 whitespace-nowrap">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${getSeverityBadge(a.severity)}`}>
                            {a.severity}
                          </span>
                        </td>
                        <td className="p-2.5">
                          <div className="font-semibold text-slate-200 leading-tight">{a.title}</div>
                          <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                            Rule: {a.detection_rule_id} v{a.detection_rule_version}
                          </div>
                        </td>
                        <td className="p-2.5 whitespace-nowrap">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${getStatusBadge(a.assessment_status)}`}>
                            {a.assessment_status}
                          </span>
                        </td>
                        <td className="p-2.5 whitespace-nowrap">
                          <div className="flex items-center gap-1.5">
                            <div className="w-12 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                              <div
                                className="bg-blue-500 h-full rounded-full"
                                style={{ width: `${a.confidence}%` }}
                              />
                            </div>
                            <span className="font-mono text-[11px] text-slate-300">{a.confidence}%</span>
                          </div>
                        </td>
                        <td className="p-2.5 whitespace-nowrap text-slate-300">
                          <span className="font-mono text-emerald-400">{a.decoy_id}</span> ({a.target_service})
                        </td>
                        <td className="p-2.5 whitespace-nowrap font-mono text-slate-300">
                          {a.source_address}
                        </td>
                        <td className="p-2.5 whitespace-nowrap">
                          {a.assigned_analyst ? (
                            <span className="text-slate-300 font-medium">👤 {a.assigned_analyst}</span>
                          ) : (
                            <span className="text-slate-600 italic">Unassigned</span>
                          )}
                        </td>
                        <td className="p-2.5 pr-4 whitespace-nowrap text-slate-500 text-[11px]">
                          {a.generated_at ? new Date(a.generated_at).toLocaleTimeString() : '...'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>

          {/* Pagination Controls */}
          <div className="p-2.5 border-t border-slate-800 bg-slate-900/60 flex items-center justify-between text-xs text-slate-400 shrink-0">
            <div>
              Showing {alerts.length} of {totalAlerts} alerts
            </div>
            <div className="flex items-center gap-2">
              <button
                disabled={filters.page <= 1}
                onClick={() => setFilters((prev) => ({ ...prev, page: prev.page - 1 }))}
                className="px-2.5 py-1 rounded bg-slate-800 disabled:opacity-40 hover:bg-slate-700 text-slate-300 border border-slate-700"
              >
                Previous
              </button>
              <span className="font-mono">Page {filters.page}</span>
              <button
                disabled={filters.page * filters.limit >= totalAlerts}
                onClick={() => setFilters((prev) => ({ ...prev, page: prev.page + 1 }))}
                className="px-2.5 py-1 rounded bg-slate-800 disabled:opacity-40 hover:bg-slate-700 text-slate-300 border border-slate-700"
              >
                Next
              </button>
            </div>
          </div>
        </div>

        {/* Right: Forensic Detail & Triage Drawer */}
        <div className="w-[520px] bg-slate-900 flex flex-col overflow-hidden shrink-0 border-l border-slate-800">
          {detailLoading ? (
            <div className="p-10 text-center text-slate-400 text-xs">Loading forensic alert context...</div>
          ) : !alertDetail ? (
            <div className="p-12 text-center text-slate-500 text-xs">
              Select an alert from the queue to inspect supporting evidence, severity/confidence reasons, and execute triage actions.
            </div>
          ) : (
            <div className="flex flex-col h-full overflow-hidden">
              {/* Detail Header */}
              <div className="p-4 border-b border-slate-800 bg-slate-950/60 shrink-0">
                <div className="flex items-center justify-between">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${getSeverityBadge(alertDetail.severity)}`}>
                    {alertDetail.severity}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${getStatusBadge(alertDetail.assessment_status)}`}>
                    {alertDetail.assessment_status}
                  </span>
                </div>
                <h2 className="text-base font-bold text-slate-100 mt-2 leading-snug">{alertDetail.title}</h2>
                <div className="text-[11px] text-slate-500 font-mono mt-1">ID: {alertDetail.alert_id}</div>

                {actionError && (
                  <div className="mt-2.5 p-2 rounded bg-red-950/60 border border-red-800 text-red-300 text-xs">
                    {actionError}
                  </div>
                )}

                {/* Sub-tab Navigation */}
                <div className="flex items-center gap-1.5 mt-3 overflow-x-auto border-t border-slate-800 pt-2 text-xs">
                  {[
                    { id: 'overview', label: 'Overview' },
                    { id: 'evidence', label: `Evidence (${alertDetail.supporting_events_count})` },
                    { id: 'scoring', label: 'Severity/Confidence' },
                    { id: 'prioritization', label: 'Priority' },
                    { id: 'context', label: 'Context' },
                    { id: 'actions', label: 'Triage Actions' },
                    { id: 'notes', label: `Notes (${notesList.length})` },
                    { id: 'audit', label: 'Audit Trail' },
                  ].map((t) => (
                    <button
                      key={t.id}
                      onClick={() => setActiveDetailTab(t.id as any)}
                      className={`px-2.5 py-1 rounded whitespace-nowrap text-[11px] font-medium transition-colors ${
                        activeDetailTab === t.id
                          ? 'bg-blue-600 text-white font-semibold'
                          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                      }`}
                    >
                      {t.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Sub-tab Body */}
              <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
                {/* 1. Overview */}
                {activeDetailTab === 'overview' && (
                  <div className="space-y-3">
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                      <div className="font-semibold text-slate-300 mb-1">Detection Summary</div>
                      <p className="text-slate-400 leading-relaxed">{alertDetail.summary}</p>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                      <div className="font-semibold text-slate-300 mb-2">Detection Explanation</div>
                      <p className="text-slate-400 leading-relaxed font-mono text-[11px]">
                        {alertDetail.detection_explanation}
                      </p>
                    </div>

                    <div className="grid grid-cols-2 gap-2">
                      <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                        <span className="text-slate-500 text-[10px] uppercase block">Decoy Target</span>
                        <span className="font-mono text-emerald-400 font-semibold">{alertDetail.decoy_id}</span>
                        <span className="text-slate-400 text-[10px] ml-1">({alertDetail.target_service})</span>
                      </div>
                      <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                        <span className="text-slate-500 text-[10px] uppercase block">Source Address</span>
                        <span className="font-mono text-slate-200 font-semibold">{alertDetail.source_address}</span>
                      </div>
                      <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                        <span className="text-slate-500 text-[10px] uppercase block">Assigned Analyst</span>
                        <span className="text-slate-200">{alertDetail.assigned_analyst || 'Unassigned'}</span>
                      </div>
                      <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                        <span className="text-slate-500 text-[10px] uppercase block">Triage Decision</span>
                        <span className="text-blue-400 font-semibold">{alertDetail.triage_decision || 'Pending'}</span>
                      </div>
                    </div>

                    {alertDetail.recommendations && (
                      <div className="p-3 rounded-lg bg-blue-950/20 border border-blue-900/60">
                        <div className="font-semibold text-blue-300 mb-1">Triage Recommendations</div>
                        <p className="text-slate-400">{alertDetail.recommendations.triage_guidance}</p>
                      </div>
                    )}
                  </div>
                )}

                {/* 2. Evidence */}
                {activeDetailTab === 'evidence' && (
                  <div className="space-y-2.5">
                    <p className="text-slate-400 text-[11px]">
                      Supporting telemetry events linked to this alert. Click any event to open full inspection in Security Events Explorer.
                    </p>
                    {evidenceList.map((ev) => (
                      <div key={ev.event_id} className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-blue-400 font-bold">{ev.event_type}</span>
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300">
                            {ev.evidence_role}
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-400 font-mono">
                          Source: {ev.source_ip} | Protocol: {ev.protocol || 'TCP'} | Outcome: {ev.outcome}
                        </div>
                        <div className="text-[10px] text-slate-500">
                          Observed: {ev.observed_at ? new Date(ev.observed_at).toLocaleString() : 'N/A'}
                        </div>
                        <div className="pt-1">
                          <a
                            href={ev.investigation_url}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 text-[11px] text-emerald-400 hover:text-emerald-300 font-semibold underline"
                          >
                            🔍 Inspect in Security Events Explorer →
                          </a>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* 3. Severity & Confidence */}
                {activeDetailTab === 'scoring' && (
                  <div className="space-y-3">
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-semibold text-slate-300">Severity Assessment</span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${getSeverityBadge(alertDetail.severity)}`}>
                          {alertDetail.severity}
                        </span>
                      </div>
                      <p className="text-slate-400 text-[11px] leading-relaxed">
                        Evaluated independently of confidence. Reflects the potential security impact of the attack pattern against corporate decoy systems.
                      </p>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-semibold text-slate-300">Confidence Score</span>
                        <span className="font-mono text-blue-400 font-bold text-sm">{alertDetail.confidence}%</span>
                      </div>
                      <div className="w-full bg-slate-800 rounded-full h-2 mb-2 overflow-hidden">
                        <div className="bg-blue-500 h-full rounded-full" style={{ width: `${alertDetail.confidence}%` }} />
                      </div>
                      <p className="text-slate-400 text-[11px] leading-relaxed">
                        Evidence strength: <span className="font-semibold text-slate-200">{alertDetail.evidence_strength}</span>. Represents analytical certainty based on specific threshold corroboration and telemetry volume.
                      </p>
                    </div>
                  </div>
                )}

                {/* 4. Priority */}
                {activeDetailTab === 'prioritization' && (
                  <div className="space-y-3">
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                      <div className="flex items-center justify-between mb-2">
                        <div>
                          <div className="font-bold text-slate-100 text-sm">Operational Priority Index</div>
                          <div className="text-[10px] text-slate-500 font-mono">Formula v{alertDetail.prioritization.formula_version}</div>
                        </div>
                        <div className="text-right">
                          <span className={`px-2.5 py-1 rounded text-xs font-mono font-bold border ${getPriorityBadge(alertDetail.prioritization.priority_level)}`}>
                            {alertDetail.prioritization.priority_level} ({alertDetail.prioritization.priority_score})
                          </span>
                        </div>
                      </div>

                      <p className="text-slate-400 text-[11px] leading-relaxed mb-3">
                        {alertDetail.prioritization.rationale}
                      </p>

                      {/* Component Breakdown */}
                      <div className="space-y-1.5 border-t border-slate-800 pt-2.5 text-[11px]">
                        <div className="flex justify-between text-slate-400">
                          <span>Severity Component (Max 40)</span>
                          <span className="font-mono text-slate-200 font-semibold">{alertDetail.prioritization.severity_component} pts</span>
                        </div>
                        <div className="flex justify-between text-slate-400">
                          <span>Confidence Component (Max 25)</span>
                          <span className="font-mono text-slate-200 font-semibold">{alertDetail.prioritization.confidence_component} pts</span>
                        </div>
                        <div className="flex justify-between text-slate-400">
                          <span>Evidence Strength & Volume (Max 20)</span>
                          <span className="font-mono text-slate-200 font-semibold">{alertDetail.prioritization.evidence_component} pts</span>
                        </div>
                        <div className="flex justify-between text-slate-400">
                          <span>Cross-Subsystem Context Link (Max 10)</span>
                          <span className="font-mono text-slate-200 font-semibold">{alertDetail.prioritization.context_component} pts</span>
                        </div>
                        <div className="flex justify-between text-slate-400">
                          <span>Recency Urgency Bonus (Max 5)</span>
                          <span className="font-mono text-slate-200 font-semibold">{alertDetail.prioritization.recency_component} pts</span>
                        </div>
                      </div>
                    </div>

                    <div className="p-2.5 rounded bg-amber-950/20 border border-amber-900/60 text-[10px] text-amber-300 leading-relaxed">
                      ⚠️ {alertDetail.prioritization.non_attribution_notice}
                    </div>
                  </div>
                )}

                {/* 5. Context */}
                {activeDetailTab === 'context' && relationships && (
                  <div className="space-y-3">
                    {/* Session */}
                    {relationships.session && (
                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                        <div className="font-semibold text-slate-300">Activity Session</div>
                        <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                          {relationships.session.session_id} ({relationships.session.event_count} events)
                        </div>
                        <a href={relationships.session.navigation_url} className="text-[11px] text-blue-400 hover:underline block mt-1">
                          View Session Timeline →
                        </a>
                      </div>
                    )}

                    {/* Source Profile */}
                    {relationships.source_profile && (
                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                        <div className="font-semibold text-slate-300">Source Profile</div>
                        <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                          {relationships.source_profile.source_address} | Priority: {relationships.source_profile.profile_priority}
                        </div>
                        <a href={relationships.source_profile.navigation_url} className="text-[11px] text-blue-400 hover:underline block mt-1">
                          Inspect Source Profile →
                        </a>
                      </div>
                    )}

                    {/* MITRE */}
                    {relationships.mitre_techniques.length > 0 && (
                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                        <div className="font-semibold text-slate-300 mb-1.5">MITRE ATT&CK Techniques</div>
                        {relationships.mitre_techniques.map((mt) => (
                          <div key={mt.technique_id} className="text-[11px] flex justify-between items-center py-0.5">
                            <span className="font-mono text-purple-400">{mt.technique_id}: {mt.technique_name}</span>
                            <a href={mt.navigation_url} className="text-blue-400 hover:underline">
                              Mapping →
                            </a>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* 6. Actions */}
                {activeDetailTab === 'actions' && (
                  <div className="space-y-4">
                    {/* Acknowledge */}
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                      <div className="font-semibold text-slate-200">1. Acknowledge Alert</div>
                      <p className="text-[11px] text-slate-400 mt-0.5 mb-2">Mark alert as received and begin analyst oversight.</p>
                      <button
                        onClick={handleAcknowledge}
                        disabled={alertDetail.assessment_status !== 'NEW'}
                        className="px-3 py-1.5 rounded bg-blue-600 disabled:opacity-40 hover:bg-blue-500 text-white font-medium text-xs"
                      >
                        Acknowledge Alert
                      </button>
                    </div>

                    {/* Assign */}
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                      <div className="font-semibold text-slate-200">2. Assign / Reassign Analyst</div>
                      <input
                        type="text"
                        placeholder="Target Analyst ID"
                        value={assigneeInput}
                        onChange={(e) => setAssigneeInput(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1 text-slate-200"
                      />
                      <button
                        onClick={handleAssign}
                        className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-medium text-xs"
                      >
                        Assign Alert
                      </button>
                    </div>

                    {/* Escalate */}
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                      <div className="font-semibold text-rose-400">3. Escalate Alert</div>
                      <select
                        value={escalateRole}
                        onChange={(e) => setEscalateRole(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1 text-slate-200"
                      >
                        <option value="TIER_2_ANALYST">Tier 2 Senior Analyst</option>
                        <option value="INCIDENT_RESPONSE_LEAD">Incident Response Lead</option>
                        <option value="SECURITY_DIRECTOR">Security Director</option>
                      </select>
                      <textarea
                        rows={2}
                        placeholder="Required escalation justification..."
                        value={escalateReason}
                        onChange={(e) => setEscalateReason(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1 text-slate-200 text-xs"
                      />
                      <button
                        onClick={handleEscalate}
                        className="px-3 py-1.5 rounded bg-rose-600 hover:bg-rose-500 text-white font-medium text-xs"
                      >
                        Escalate Alert
                      </button>
                    </div>

                    {/* Resolve */}
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                      <div className="font-semibold text-emerald-400">4. Resolve Alert</div>
                      <select
                        value={resolveCategory}
                        onChange={(e) => setResolveCategory(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1 text-slate-200"
                      >
                        <option value="BENIGN_SCANNER">Benign Internet Scanner</option>
                        <option value="CONTAINED_HONEYPOT">Contained Decoy Interaction</option>
                        <option value="FALSE_POSITIVE">False Positive Detection</option>
                        <option value="SECURITY_TESTING">Authorized Security Testing</option>
                      </select>
                      <textarea
                        rows={2}
                        placeholder="Required resolution explanation..."
                        value={resolveReason}
                        onChange={(e) => setResolveReason(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1 text-slate-200 text-xs"
                      />
                      <button
                        onClick={handleResolve}
                        className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs"
                      >
                        Resolve Alert
                      </button>
                    </div>

                    {/* Close */}
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                      <div className="font-semibold text-slate-400">5. Close Alert</div>
                      <textarea
                        rows={2}
                        placeholder="Required final disposition and closure reason..."
                        value={closeReason}
                        onChange={(e) => setCloseReason(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1 text-slate-200 text-xs"
                      />
                      <button
                        onClick={handleClose}
                        className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 font-medium text-xs"
                      >
                        Close Alert
                      </button>
                    </div>

                    {/* Triage Decision */}
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                      <div className="font-semibold text-blue-300">6. Structured Triage Decision</div>
                      <select
                        value={triageDecisionChoice}
                        onChange={(e) => setTriageDecisionChoice(e.target.value as any)}
                        className="w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1 text-slate-200"
                      >
                        <option value="TRUE_POSITIVE">True Positive</option>
                        <option value="LIKELY_TRUE_POSITIVE">Likely True Positive</option>
                        <option value="NEEDS_INVESTIGATION">Needs Further Investigation</option>
                        <option value="BENIGN_ACTIVITY">Benign Activity</option>
                        <option value="FALSE_POSITIVE">False Positive</option>
                        <option value="INSUFFICIENT_EVIDENCE">Insufficient Evidence</option>
                      </select>
                      <textarea
                        rows={2}
                        placeholder="Evidence justification for triage classification..."
                        value={triageJustification}
                        onChange={(e) => setTriageJustification(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1 text-slate-200 text-xs"
                      />
                      <button
                        onClick={handleTriageDecision}
                        className="px-3 py-1.5 rounded bg-blue-700 hover:bg-blue-600 text-white font-medium text-xs"
                      >
                        Record Triage Decision
                      </button>
                    </div>
                  </div>
                )}

                {/* 7. Notes */}
                {activeDetailTab === 'notes' && (
                  <div className="space-y-3">
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                      <div className="font-semibold text-slate-200">Add Analyst Note</div>
                      <textarea
                        rows={3}
                        placeholder="Append an immutable triage or investigation note..."
                        value={newNoteContent}
                        onChange={(e) => setNewNoteContent(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1.5 text-slate-200 text-xs"
                      />
                      <button
                        onClick={handleAddNote}
                        className="px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs"
                      >
                        Append Note
                      </button>
                    </div>

                    <div className="space-y-2">
                      {notesList.map((n) => (
                        <div key={n.id} className="p-2.5 rounded bg-slate-950 border border-slate-800">
                          <div className="flex justify-between text-[10px] text-slate-500">
                            <span className="font-semibold text-slate-300">👤 {n.author_id} ({n.author_role})</span>
                            <span>{new Date(n.created_at).toLocaleString()}</span>
                          </div>
                          <p className="text-slate-300 text-[11px] mt-1 leading-relaxed whitespace-pre-wrap">{n.content}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* 8. Audit */}
                {activeDetailTab === 'audit' && (
                  <div className="space-y-2">
                    <p className="text-slate-500 text-[11px]">
                      Immutable audit trail of all analyst actions and lifecycle transitions.
                    </p>
                    {historyList.map((h) => (
                      <div key={h.id} className="p-2.5 rounded bg-slate-950 border border-slate-800 text-[11px]">
                        <div className="flex justify-between items-center text-[10px] text-slate-500 mb-1">
                          <span className="font-bold text-blue-400">{h.action_type}</span>
                          <span>{new Date(h.created_at).toLocaleString()}</span>
                        </div>
                        <div className="text-slate-300">
                          Actor: <span className="font-semibold">{h.analyst_id}</span>
                          {h.previous_status && h.new_status && (
                            <span className="ml-2">({h.previous_status} → {h.new_status})</span>
                          )}
                        </div>
                        {h.reason && <p className="text-slate-400 mt-0.5 italic">"{h.reason}"</p>}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AlertManagementPage;

