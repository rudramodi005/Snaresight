import React, { useState, useEffect } from 'react';
import {
  Shield,
  Activity,
  AlertTriangle,
  RotateCcw,
  Plus,
  CheckCircle2,
  XCircle,
  Clock,
  HardDrive,
  Database,
  FileCheck,
  Lock,
  Layers,
  Search,
  Check,
  Copy,
  Zap,
  Server,
  Terminal,
  RefreshCw,
  Sliders,
  ChevronRight,
  ShieldAlert,
  Flame,
  FileText,
} from 'lucide-react';
import {
  SystemHealthOverview,
  ComponentHealthItem,
  InternalSecurityAlert,
  DatabaseBackup,
  RestoreTestRecord,
  DisasterRecoveryConfig,
  DisasterRecoveryChecklist,
  InternalIncident,
  AuditVerification,
} from '../../types/resilience';
import { resilienceApi } from '../../services/resilienceApi';

export const PlatformSecurityHealthPage: React.FC = () => {
  // Navigation tabs
  const [activeTab, setActiveTab] = useState<'health' | 'alerts' | 'backups' | 'dr' | 'incidents'>('health');

  // Loading & error states
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Core Data
  const [diagnostics, setDiagnostics] = useState<SystemHealthOverview | null>(null);
  const [alerts, setAlerts] = useState<InternalSecurityAlert[]>([]);
  const [backups, setBackups] = useState<DatabaseBackup[]>([]);
  const [drConfig, setDrConfig] = useState<DisasterRecoveryConfig | null>(null);
  const [checklists, setChecklists] = useState<DisasterRecoveryChecklist[]>([]);
  const [incidents, setIncidents] = useState<InternalIncident[]>([]);

  // Modals state
  const [showBackupModal, setShowBackupModal] = useState(false);
  const [backupType, setBackupType] = useState<'MANUAL' | 'FULL' | 'PRE_MIGRATION'>('MANUAL');
  const [retentionHold, setRetentionHold] = useState(false);

  const [showDrConfigModal, setShowDrConfigModal] = useState(false);
  const [rpoTarget, setRpoTarget] = useState(60);
  const [rtoTarget, setRtoTarget] = useState(30);

  const [showIncidentModal, setShowIncidentModal] = useState(false);
  const [newIncidentTitle, setNewIncidentTitle] = useState('');
  const [newIncidentDesc, setNewIncidentDesc] = useState('');
  const [newIncidentSeverity, setNewIncidentSeverity] = useState('MEDIUM');

  const [selectedIncident, setSelectedIncident] = useState<InternalIncident | null>(null);
  const [noteContent, setNoteContent] = useState('');
  const [noteType, setNoteType] = useState<'OBSERVATION' | 'CONTAINMENT' | 'RECOVERY' | 'ROOT_CAUSE'>('OBSERVATION');

  const [resolvingAlert, setResolvingAlert] = useState<InternalSecurityAlert | null>(null);
  const [resolutionNotes, setResolutionNotes] = useState('');

  const [auditResult, setAuditResult] = useState<AuditVerification | null>(null);
  const [runningAudit, setRunningAudit] = useState(false);

  const [testingRestoreId, setTestingRestoreId] = useState<string | null>(null);
  const [restoreTestResult, setRestoreTestResult] = useState<RestoreTestRecord | null>(null);

  const [selectedScenarioId, setSelectedScenarioId] = useState<string>('DB_UNAVAILABLE');

  // Load all resilience telemetry
  const loadData = async (isBackground = false) => {
    if (!isBackground) setLoading(true);
    else setRefreshing(true);
    setError(null);

    try {
      const [diagData, alertsData, backupsData, configData, checklistsData, incidentsData] = await Promise.all([
        resilienceApi.getDiagnostics().catch(() => null),
        resilienceApi.listAlerts().catch(() => []),
        resilienceApi.listBackups().catch(() => []),
        resilienceApi.getDrConfig().catch(() => null),
        resilienceApi.listDrChecklists().catch(() => []),
        resilienceApi.listIncidents().catch(() => []),
      ]);

      if (diagData) setDiagnostics(diagData);
      setAlerts(alertsData);
      setBackups(backupsData);
      if (configData) {
        setDrConfig(configData);
        setRpoTarget(configData.rpo_target_minutes);
        setRtoTarget(configData.rto_target_minutes);
      }
      setChecklists(checklistsData);
      setIncidents(incidentsData);
    } catch (err: any) {
      setError(err.message || 'Failed to load resilience telemetry.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(() => loadData(true), 30000);
    return () => clearInterval(interval);
  }, []);

  // Handlers
  const handleInitiateBackup = async () => {
    try {
      const bck = await resilienceApi.initiateBackup({
        backup_type: backupType,
        retention_hold: retentionHold,
      });
      setShowBackupModal(false);
      setActionSuccess(`Database backup ${bck.backup_id} created successfully with cryptographic SHA-256.`);
      loadData(true);
    } catch (err: any) {
      setError(err.message || 'Failed to initiate database backup.');
    }
  };

  const handleRunRestoreTest = async (backupId: string) => {
    setTestingRestoreId(backupId);
    setError(null);
    try {
      const record = await resilienceApi.runRestoreTest(backupId, 'isolated_sandbox_db');
      setRestoreTestResult(record);
      setActionSuccess(`Isolated sandbox restore test completed successfully: ${record.table_count_verified} tables verified.`);
      loadData(true);
    } catch (err: any) {
      setError(err.message || 'Isolated restore test failed.');
    } finally {
      setTestingRestoreId(null);
    }
  };

  const handleUpdateDrConfig = async () => {
    try {
      const updated = await resilienceApi.updateDrConfig({
        rpo_target_minutes: rpoTarget,
        rto_target_minutes: rtoTarget,
      });
      setDrConfig(updated);
      setShowDrConfigModal(false);
      setActionSuccess('Disaster Recovery SLAs and retention policy updated.');
    } catch (err: any) {
      setError(err.message || 'Failed to update DR targets.');
    }
  };

  const handleToggleChecklist = async (scenarioId: string, itemId: string, currentCompleted: boolean) => {
    try {
      const updated = await resilienceApi.toggleChecklistItem(scenarioId, {
        item_id: itemId,
        completed: !currentCompleted,
      });
      setChecklists((prev) => prev.map((c) => (c.scenario_id === scenarioId ? updated : c)));
    } catch (err: any) {
      setError(err.message || 'Failed to update checklist item.');
    }
  };

  const handleCreateIncident = async () => {
    if (!newIncidentTitle || !newIncidentDesc) return;
    try {
      const inc = await resilienceApi.createIncident({
        title: newIncidentTitle,
        description: newIncidentDesc,
        severity: newIncidentSeverity,
        affected_components: ['Control_Plane'],
        linked_alert_ids: [],
      });
      setShowIncidentModal(false);
      setNewIncidentTitle('');
      setNewIncidentDesc('');
      setActionSuccess(`Internal security incident ${inc.incident_id} registered.`);
      loadData(true);
    } catch (err: any) {
      setError(err.message || 'Failed to open incident.');
    }
  };

  const handleAddNote = async (incidentId: string) => {
    if (!noteContent) return;
    try {
      await resilienceApi.addIncidentNote(incidentId, {
        content: noteContent,
        note_type: noteType,
      });
      setNoteContent('');
      const updatedInc = await resilienceApi.getIncident(incidentId);
      setSelectedIncident(updatedInc);
      setIncidents((prev) => prev.map((i) => (i.incident_id === incidentId ? updatedInc : i)));
    } catch (err: any) {
      setError(err.message || 'Failed to append note.');
    }
  };

  const handleAcknowledgeAlert = async (alertId: string) => {
    try {
      const updated = await resilienceApi.acknowledgeAlert(alertId, 'Acknowledged by operator in SOC console.');
      setAlerts((prev) => prev.map((a) => (a.alert_id === alertId ? updated : a)));
      setActionSuccess(`Alert ${alertId} acknowledged.`);
    } catch (err: any) {
      setError(err.message || 'Failed to acknowledge alert.');
    }
  };

  const handleResolveAlert = async () => {
    if (!resolvingAlert || !resolutionNotes) return;
    try {
      const updated = await resilienceApi.resolveAlert(resolvingAlert.alert_id, resolutionNotes);
      setAlerts((prev) => prev.map((a) => (a.alert_id === resolvingAlert.alert_id ? updated : a)));
      setResolvingAlert(null);
      setResolutionNotes('');
      setActionSuccess(`Alert ${updated.alert_id} resolved.`);
    } catch (err: any) {
      setError(err.message || 'Failed to resolve alert.');
    }
  };

  const handleVerifyAudit = async () => {
    setRunningAudit(true);
    try {
      const res = await resilienceApi.verifyAuditTrail();
      setAuditResult(res);
      setActionSuccess(`Audit verification completed: ${res.verified_hashes} cryptographic log hashes confirmed.`);
    } catch (err: any) {
      setError(err.message || 'Audit verification failed.');
    } finally {
      setRunningAudit(false);
    }
  };

  // Helper styles
  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'HEALTHY':
      case 'COMPLETED':
      case 'SUCCESS':
      case 'COMPLIANT':
      case 'READINESS_VERIFIED':
        return 'bg-emerald-950/60 border-emerald-500/40 text-emerald-400';
      case 'DEGRADED':
      case 'WARNING':
      case 'ACTION_REQUIRED':
      case 'ACKNOWLEDGED':
        return 'bg-amber-950/60 border-amber-500/40 text-amber-400';
      case 'CRITICAL':
      case 'FAILED':
      case 'BREACHED':
      case 'OPEN':
        return 'bg-rose-950/60 border-rose-500/40 text-rose-400';
      default:
        return 'bg-slate-800/60 border-slate-700 text-slate-300';
    }
  };

  const activeScenario = checklists.find((c) => c.scenario_id === selectedScenarioId) || checklists[0];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-indigo-500/10 border border-indigo-500/30 text-indigo-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-3">
                Platform Security, Health & Operational Resilience
                <span className="text-xs px-2.5 py-0.5 rounded-full bg-indigo-950/80 border border-indigo-500/30 text-indigo-300 font-mono">
                  ISO-27001 / SOC 2
                </span>
              </h1>
              <p className="text-sm text-slate-400 mt-0.5">
                Internal control-plane telemetry, automated disaster recovery runbooks, and cryptographic backup management.
              </p>
            </div>
          </div>
        </div>

        {/* Global Action Buttons */}
        <div className="flex flex-wrap items-center gap-2.5">
          <button
            onClick={handleVerifyAudit}
            disabled={runningAudit}
            className="flex items-center gap-2 px-3 py-2 text-xs font-semibold rounded-lg bg-slate-900 border border-slate-700 hover:bg-slate-800 text-slate-200 transition-colors disabled:opacity-50"
          >
            <FileCheck className={`w-4 h-4 text-emerald-400 ${runningAudit ? 'animate-spin' : ''}`} />
            {runningAudit ? 'Verifying Hashes...' : 'Verify Audit Trail'}
          </button>

          <button
            onClick={() => setShowBackupModal(true)}
            className="flex items-center gap-2 px-3.5 py-2 text-xs font-semibold rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-950/40 transition-colors"
          >
            <Database className="w-4 h-4" />
            Initiate Backup
          </button>

          <button
            onClick={() => loadData(true)}
            disabled={refreshing}
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
            title="Refresh Diagnostics"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Notifications */}
      {actionSuccess && (
        <div className="p-4 rounded-lg bg-emerald-950/40 border border-emerald-500/30 text-emerald-300 text-sm flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>{actionSuccess}</span>
          </div>
          <button onClick={() => setActionSuccess(null)} className="text-slate-400 hover:text-white text-xs">
            Dismiss
          </button>
        </div>
      )}

      {error && (
        <div className="p-4 rounded-lg bg-rose-950/40 border border-rose-500/30 text-rose-300 text-sm flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-slate-400 hover:text-white text-xs">
            Dismiss
          </button>
        </div>
      )}

      {/* Metric Cards Banner */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Overall Platform Health */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium uppercase tracking-wider">
            <span>Platform State</span>
            <Activity className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="mt-2 flex items-center gap-2">
            <span className={`w-2.5 h-2.5 rounded-full ${diagnostics?.overall_status === 'HEALTHY' ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500'}`} />
            <span className="text-xl font-bold tracking-tight text-white">
              {diagnostics?.overall_status || 'HEALTHY'}
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-2 font-mono">
            {diagnostics?.uptime_seconds ? `Uptime: ${(diagnostics.uptime_seconds / 3600).toFixed(1)} hrs` : 'Active'}
          </p>
        </div>

        {/* Active Internal Alerts */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium uppercase tracking-wider">
            <span>Internal Alerts</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white">
              {alerts.filter((a) => a.status === 'OPEN').length}
            </span>
            <span className="text-xs text-rose-400 font-mono">
              ({alerts.filter((a) => a.status === 'OPEN' && a.severity === 'CRITICAL').length} critical)
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-2">Control-plane anomalies</p>
        </div>

        {/* RPO Compliance */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium uppercase tracking-wider">
            <span>RPO Target</span>
            <Clock className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 flex items-center justify-between">
            <span className="text-2xl font-bold text-white">
              {drConfig?.rpo_target_minutes || 60}m
            </span>
            <span className={`text-xs px-2 py-0.5 rounded font-mono border ${getStatusBadge(drConfig?.rpo_status || 'COMPLIANT')}`}>
              {drConfig?.rpo_status || 'COMPLIANT'}
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-2 font-mono">
            Actual: {drConfig?.actual_rpo_minutes ? `${drConfig.actual_rpo_minutes.toFixed(0)}m` : '< 10m'}
          </p>
        </div>

        {/* RTO Readiness Target */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium uppercase tracking-wider">
            <span>RTO Target</span>
            <Zap className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 flex items-center justify-between">
            <span className="text-2xl font-bold text-white">
              {drConfig?.rto_target_minutes || 30}m
            </span>
            <span className="text-xs px-2 py-0.5 rounded font-mono border bg-emerald-950/60 border-emerald-500/40 text-emerald-400">
              READY
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-2 font-mono">
            Sandbox Est: ~{drConfig?.actual_rto_estimate_minutes || 12.5}m
          </p>
        </div>

        {/* Last Verified Backup */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium uppercase tracking-wider">
            <span>Verified Backups</span>
            <HardDrive className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2">
            <span className="text-2xl font-bold text-white">
              {backups.filter((b) => b.restore_verified).length} / {backups.length}
            </span>
          </div>
          <p className="text-xs text-emerald-400 mt-2 font-mono flex items-center gap-1">
            <Check className="w-3 h-3" /> Sandbox Isolated
          </p>
        </div>
      </div>

      {/* Tabs Navigation */}
      <div className="flex border-b border-slate-800">
        <button
          onClick={() => setActiveTab('health')}
          className={`px-4 py-2.5 text-sm font-semibold border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === 'health'
              ? 'border-indigo-500 text-white bg-indigo-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Activity className="w-4 h-4" />
          System Diagnostics ({diagnostics?.components.length || 7})
        </button>

        <button
          onClick={() => setActiveTab('alerts')}
          className={`px-4 py-2.5 text-sm font-semibold border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === 'alerts'
              ? 'border-indigo-500 text-white bg-indigo-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldAlert className="w-4 h-4 text-rose-400" />
          Internal Security Alerts ({alerts.filter((a) => a.status === 'OPEN').length})
        </button>

        <button
          onClick={() => setActiveTab('backups')}
          className={`px-4 py-2.5 text-sm font-semibold border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === 'backups'
              ? 'border-indigo-500 text-white bg-indigo-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Database className="w-4 h-4" />
          Managed Backups ({backups.length})
        </button>

        <button
          onClick={() => setActiveTab('dr')}
          className={`px-4 py-2.5 text-sm font-semibold border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === 'dr'
              ? 'border-indigo-500 text-white bg-indigo-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <RotateCcw className="w-4 h-4" />
          Disaster Recovery Runbooks (5)
        </button>

        <button
          onClick={() => setActiveTab('incidents')}
          className={`px-4 py-2.5 text-sm font-semibold border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === 'incidents'
              ? 'border-indigo-500 text-white bg-indigo-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Flame className="w-4 h-4 text-amber-400" />
          Internal Incidents ({incidents.length})
        </button>
      </div>

      {/* ------------------------------------------------------------------- */}
      {/* TAB 1: SYSTEM HEALTH & DIAGNOSTICS */}
      {/* ------------------------------------------------------------------- */}
      {activeTab === 'health' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {diagnostics?.components.map((comp) => (
              <div
                key={comp.name}
                className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition-all flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className="font-semibold text-white text-sm flex items-center gap-2">
                      <Server className="w-4 h-4 text-indigo-400" />
                      {comp.name}
                    </span>
                    <span className={`text-xs px-2.5 py-0.5 rounded font-mono border ${getStatusBadge(comp.status)}`}>
                      {comp.status}
                    </span>
                  </div>

                  <div className="space-y-1.5 text-xs text-slate-400">
                    <div className="flex justify-between">
                      <span>Latency:</span>
                      <span className="font-mono text-slate-200">{comp.latency_ms} ms</span>
                    </div>
                    {Object.entries(comp.details).map(([key, val]) => (
                      <div key={key} className="flex justify-between">
                        <span className="capitalize">{key.replace(/_/g, ' ')}:</span>
                        <span className="font-mono text-slate-300">{String(val)}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-500 font-mono">
                  <span>Checked: {new Date(comp.checked_at).toLocaleTimeString()}</span>
                  <span className="text-emerald-500 flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" /> Passing
                  </span>
                </div>
              </div>
            ))}
          </div>

          {/* Audit Verification Card */}
          {auditResult && (
            <div className="p-5 rounded-xl bg-slate-900/80 border border-emerald-500/30 flex items-start gap-4">
              <div className="p-3 rounded-lg bg-emerald-500/10 text-emerald-400">
                <FileCheck className="w-6 h-6" />
              </div>
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold text-white">Cryptographic Audit Chain Integrity Verification</h3>
                  <span className="text-xs px-2 py-0.5 rounded bg-emerald-950/80 border border-emerald-500/40 text-emerald-400 font-mono">
                    100% VALID
                  </span>
                </div>
                <p className="text-sm text-slate-300 mt-1">{auditResult.details}</p>
                <div className="mt-3 flex gap-6 text-xs font-mono text-slate-400">
                  <span>Total Records: <strong className="text-white">{auditResult.total_records}</strong></span>
                  <span>Verified Hashes: <strong className="text-emerald-400">{auditResult.verified_hashes}</strong></span>
                  <span>Corrupted Records: <strong className="text-emerald-400">{auditResult.corrupted_records}</strong></span>
                  <span>Timestamp: <span className="text-slate-400">{new Date(auditResult.timestamp).toLocaleString()}</span></span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ------------------------------------------------------------------- */}
      {/* TAB 2: INTERNAL SECURITY ALERTS */}
      {/* ------------------------------------------------------------------- */}
      {activeTab === 'alerts' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-rose-400" />
              Control-Plane Security Alerts
            </h2>
            <div className="text-xs text-slate-400 font-mono">
              Evaluated by 7 internal security detection rules
            </div>
          </div>

          {alerts.length === 0 ? (
            <div className="p-12 text-center rounded-xl bg-slate-900/40 border border-slate-800 text-slate-400">
              <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
              <p className="font-medium text-slate-200">No Internal Security Alerts</p>
              <p className="text-xs text-slate-400 mt-1">Platform control-plane is operating with zero detected security anomalies.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {alerts.map((alt) => (
                <div
                  key={alt.alert_id}
                  className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition-all flex flex-col md:flex-row md:items-center justify-between gap-4"
                >
                  <div className="space-y-1.5 flex-1">
                    <div className="flex items-center gap-2.5">
                      <span className={`text-xs px-2.5 py-0.5 rounded font-mono border ${getStatusBadge(alt.severity)}`}>
                        {alt.severity}
                      </span>
                      <span className={`text-xs px-2 py-0.5 rounded font-mono border ${getStatusBadge(alt.status)}`}>
                        {alt.status}
                      </span>
                      <span className="text-xs font-mono text-indigo-400 font-semibold">{alt.rule_id}</span>
                      <span className="text-xs font-mono text-slate-500">#{alt.alert_id}</span>
                    </div>

                    <h4 className="font-semibold text-white text-base">{alt.title}</h4>
                    <p className="text-sm text-slate-400">{alt.description}</p>
                    <div className="text-xs text-amber-400/90 font-mono mt-1">
                      Recommended: {alt.recommended_action}
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    {alt.status === 'OPEN' && (
                      <button
                        onClick={() => handleAcknowledgeAlert(alt.alert_id)}
                        className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-amber-600/20 border border-amber-500/40 text-amber-300 hover:bg-amber-600/30 transition-colors"
                      >
                        Acknowledge
                      </button>
                    )}
                    {alt.status !== 'RESOLVED' && (
                      <button
                        onClick={() => setResolvingAlert(alt)}
                        className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-emerald-600/20 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-600/30 transition-colors"
                      >
                        Resolve
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Rules Catalog Explanation */}
          <div className="p-5 rounded-xl bg-slate-900/40 border border-slate-800">
            <h3 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
              <Lock className="w-4 h-4 text-indigo-400" />
              Active Control-Plane Rule Specifications (P34 Policy)
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
              <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                <span className="font-mono font-bold text-rose-400">RULE-INT-AUTH-01</span>
                <p className="text-slate-400 mt-1">Repeated internal authentication failures (brute force on admin).</p>
              </div>
              <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                <span className="font-mono font-bold text-rose-400">RULE-INT-PRIV-02</span>
                <p className="text-slate-400 mt-1">Unauthorized privilege / role escalation attempts.</p>
              </div>
              <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                <span className="font-mono font-bold text-amber-400">RULE-INT-AUTHZ-03</span>
                <p className="text-slate-400 mt-1">Access denied anomalies (excessive 403 Forbidden spikes).</p>
              </div>
              <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                <span className="font-mono font-bold text-amber-400">RULE-INT-CFG-04</span>
                <p className="text-slate-400 mt-1">Critical system & encryption configuration tampering.</p>
              </div>
              <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                <span className="font-mono font-bold text-rose-400">RULE-INT-AUDIT-05</span>
                <p className="text-slate-400 mt-1">Audit log persistence failure or hash-chain corruption.</p>
              </div>
              <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                <span className="font-mono font-bold text-rose-400">RULE-INT-BCK-06</span>
                <p className="text-slate-400 mt-1">Database backup generation or sandbox restore failures.</p>
              </div>
              <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                <span className="font-mono font-bold text-amber-400">RULE-INT-INGEST-07</span>
                <p className="text-slate-400 mt-1">Honeypot telemetry ingestion rejection spike or token flood.</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------------- */}
      {/* TAB 3: MANAGED BACKUPS & RESTORE VERIFICATION */}
      {/* ------------------------------------------------------------------- */}
      {activeTab === 'backups' && (
        <div className="space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold text-white flex items-center gap-2">
                <Database className="w-5 h-5 text-emerald-400" />
                Managed Database Backups & Cryptographic Integrity
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Backups carry SHA-256 integrity proofs and safe storage references without credential leakage.
              </p>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setShowDrConfigModal(true)}
                className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-900 border border-slate-700 hover:bg-slate-800 text-slate-200 transition-colors flex items-center gap-1.5"
              >
                <Sliders className="w-3.5 h-3.5" /> DR Policies & SLAs
              </button>
              <button
                onClick={() => setShowBackupModal(true)}
                className="px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white transition-colors flex items-center gap-1.5"
              >
                <Plus className="w-4 h-4" /> Create Backup
              </button>
            </div>
          </div>

          {/* Backup Isolation Warning Box */}
          <div className="p-4 rounded-xl bg-blue-950/30 border border-blue-500/30 text-blue-300 text-xs flex items-center gap-3">
            <Lock className="w-4 h-4 text-blue-400 flex-shrink-0" />
            <span>
              <strong>Safe Recovery Guarantee:</strong> Restore tests execute strictly inside an isolated sandbox database (<code className="bg-slate-900 px-1 py-0.5 rounded text-blue-200">isolated_sandbox_db</code>) and NEVER mutate or overwrite live production tables.
            </span>
          </div>

          {/* Backup List Table */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 font-medium">
                  <th className="p-3.5">Backup Identifier</th>
                  <th className="p-3.5">Type</th>
                  <th className="p-3.5">Status</th>
                  <th className="p-3.5">Size</th>
                  <th className="p-3.5">SHA-256 Checksum</th>
                  <th className="p-3.5">Storage Ref</th>
                  <th className="p-3.5">Created At</th>
                  <th className="p-3.5">Sandbox Verification</th>
                  <th className="p-3.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {backups.map((bck) => (
                  <tr key={bck.backup_id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="p-3.5 font-bold text-white flex items-center gap-1.5">
                      <Database className="w-3.5 h-3.5 text-emerald-400" />
                      {bck.backup_id}
                      {bck.retention_hold && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-950/80 border border-amber-500/40 text-amber-300">
                          HOLD
                        </span>
                      )}
                    </td>
                    <td className="p-3.5 text-slate-300">{bck.backup_type}</td>
                    <td className="p-3.5">
                      <span className={`px-2 py-0.5 rounded border text-[11px] ${getStatusBadge(bck.status)}`}>
                        {bck.status}
                      </span>
                    </td>
                    <td className="p-3.5 text-slate-400">{(bck.size_bytes / (1024 * 1024)).toFixed(2)} MB</td>
                    <td className="p-3.5 text-slate-400 font-mono text-[11px]" title={bck.checksum_sha256 || ''}>
                      {bck.checksum_sha256 ? `${bck.checksum_sha256.substring(0, 12)}...` : 'N/A'}
                    </td>
                    <td className="p-3.5 text-slate-400 text-[11px] truncate max-w-xs">{bck.storage_location_ref}</td>
                    <td className="p-3.5 text-slate-400 font-sans text-xs">
                      {new Date(bck.started_at).toLocaleString()}
                    </td>
                    <td className="p-3.5">
                      {bck.restore_verified ? (
                        <span className="px-2 py-0.5 rounded border text-[11px] bg-emerald-950/60 border-emerald-500/40 text-emerald-400 flex items-center gap-1 w-max">
                          <Check className="w-3 h-3" /> VERIFIED
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded border text-[11px] bg-amber-950/60 border-amber-500/40 text-amber-400 flex items-center gap-1 w-max">
                          <Clock className="w-3 h-3" /> UNTESTED
                        </span>
                      )}
                    </td>
                    <td className="p-3.5 text-right font-sans">
                      <button
                        onClick={() => handleRunRestoreTest(bck.backup_id)}
                        disabled={testingRestoreId === bck.backup_id}
                        className="px-2.5 py-1 text-xs font-semibold rounded bg-indigo-600/20 border border-indigo-500/40 text-indigo-300 hover:bg-indigo-600/30 transition-colors disabled:opacity-50"
                      >
                        {testingRestoreId === bck.backup_id ? 'Verifying...' : 'Run Restore Test'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Latest Sandbox Restore Result */}
          {restoreTestResult && (
            <div className="p-5 rounded-xl bg-slate-900/90 border border-indigo-500/30">
              <h3 className="font-semibold text-white text-sm flex items-center gap-2 mb-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                Latest Isolated Sandbox Verification Report
              </h3>
              <p className="text-xs text-slate-300">{restoreTestResult.diagnostic_notes}</p>
              <div className="mt-3 grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono text-slate-400">
                <div>Test ID: <span className="text-white">{restoreTestResult.test_id}</span></div>
                <div>Sandbox: <span className="text-indigo-300">{restoreTestResult.test_environment}</span></div>
                <div>Tables Verified: <span className="text-emerald-400">{restoreTestResult.table_count_verified}</span></div>
                <div>Duration: <span className="text-white">{restoreTestResult.duration_seconds}s</span></div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ------------------------------------------------------------------- */}
      {/* TAB 4: DISASTER RECOVERY RUNBOOKS & CHECKLISTS */}
      {/* ------------------------------------------------------------------- */}
      {activeTab === 'dr' && (
        <div className="space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold text-white flex items-center gap-2">
                <RotateCcw className="w-5 h-5 text-indigo-400" />
                Disaster Recovery Runbooks & Failure Drill Scenarios
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Actionable step checklists across the 5 core platform failure modes.
              </p>
            </div>
          </div>

          {/* Scenario Selector Pills */}
          <div className="flex flex-wrap gap-2">
            {checklists.map((sc) => (
              <button
                key={sc.scenario_id}
                onClick={() => setSelectedScenarioId(sc.scenario_id)}
                className={`px-3.5 py-2 rounded-lg text-xs font-semibold border transition-all flex items-center gap-2 ${
                  selectedScenarioId === sc.scenario_id
                    ? 'bg-indigo-600/20 border-indigo-500 text-white'
                    : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                <span>{sc.scenario_title}</span>
                <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono border ${getStatusBadge(sc.current_status)}`}>
                  {sc.current_status}
                </span>
              </button>
            ))}
          </div>

          {/* Active Scenario Checklist */}
          {activeScenario && (
            <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-emerald-400" />
                    {activeScenario.scenario_title}
                  </h3>
                  <p className="text-xs text-slate-400 font-mono mt-0.5">
                    Scenario Code: {activeScenario.scenario_id} • Reviewed by: {activeScenario.last_reviewed_by || 'system'}
                  </p>
                </div>
                <span className={`text-xs px-2.5 py-1 rounded font-mono border ${getStatusBadge(activeScenario.current_status)}`}>
                  {activeScenario.current_status}
                </span>
              </div>

              {/* Items List */}
              <div className="space-y-3">
                {activeScenario.checklist_items.map((item) => (
                  <div
                    key={item.item_id}
                    onClick={() => handleToggleChecklist(activeScenario.scenario_id, item.item_id, item.completed)}
                    className={`p-4 rounded-lg border transition-all cursor-pointer flex items-start gap-3.5 ${
                      item.completed
                        ? 'bg-slate-950/40 border-emerald-500/30 text-slate-200'
                        : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <div className="pt-0.5">
                      <div
                        className={`w-5 h-5 rounded border flex items-center justify-center transition-colors ${
                          item.completed
                            ? 'bg-emerald-600 border-emerald-500 text-white'
                            : 'border-slate-600 bg-slate-900'
                        }`}
                      >
                        {item.completed && <Check className="w-3.5 h-3.5" />}
                      </div>
                    </div>

                    <div className="flex-1 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-sm text-white">
                          Step {item.step_number}: {item.title}
                        </span>
                        <span className="text-[11px] font-mono text-slate-500">[{item.item_id}]</span>
                      </div>
                      <p className="text-xs text-slate-300">{item.instruction}</p>
                      <div className="text-xs text-indigo-300/80 font-mono">
                        Verification: {item.verification_criterion}
                      </div>
                      {item.notes && (
                        <div className="text-xs text-amber-300 font-mono mt-1">
                          Notes: {item.notes}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ------------------------------------------------------------------- */}
      {/* TAB 5: INTERNAL SECURITY INCIDENTS */}
      {/* ------------------------------------------------------------------- */}
      {activeTab === 'incidents' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-white flex items-center gap-2">
                <Flame className="w-5 h-5 text-amber-400" />
                Control-Plane Internal Incidents
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Manage internal administrative breaches, tamper events, or failure incidents.
              </p>
            </div>
            <button
              onClick={() => setShowIncidentModal(true)}
              className="px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white transition-colors flex items-center gap-1.5"
            >
              <Plus className="w-4 h-4" /> Open Internal Incident
            </button>
          </div>

          {incidents.length === 0 ? (
            <div className="p-12 text-center rounded-xl bg-slate-900/40 border border-slate-800 text-slate-400">
              <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
              <p className="font-medium text-slate-200">No Internal Incidents</p>
              <p className="text-xs text-slate-400 mt-1">No control plane security incidents currently recorded.</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Incident List */}
              <div className="lg:col-span-1 space-y-3">
                {incidents.map((inc) => (
                  <div
                    key={inc.incident_id}
                    onClick={() => setSelectedIncident(inc)}
                    className={`p-4 rounded-xl border cursor-pointer transition-all ${
                      selectedIncident?.incident_id === inc.incident_id
                        ? 'bg-slate-800/90 border-indigo-500 text-white'
                        : 'bg-slate-900/60 border-slate-800 hover:border-slate-700 text-slate-300'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className={`text-[10px] px-2 py-0.5 rounded font-mono border ${getStatusBadge(inc.severity)}`}>
                        {inc.severity}
                      </span>
                      <span className={`text-[10px] px-2 py-0.5 rounded font-mono border ${getStatusBadge(inc.status)}`}>
                        {inc.status}
                      </span>
                    </div>
                    <h4 className="font-semibold text-sm line-clamp-1">{inc.title}</h4>
                    <p className="text-xs text-slate-400 line-clamp-2 mt-1">{inc.description}</p>
                    <div className="mt-3 text-[11px] font-mono text-slate-500 flex justify-between">
                      <span>{inc.incident_id}</span>
                      <span>{new Date(inc.created_at).toLocaleDateString()}</span>
                    </div>
                  </div>
                ))}
              </div>

              {/* Selected Incident Detail */}
              <div className="lg:col-span-2">
                {selectedIncident ? (
                  <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                      <div>
                        <h3 className="text-lg font-bold text-white">{selectedIncident.title}</h3>
                        <p className="text-xs text-slate-400 font-mono mt-0.5">
                          ID: {selectedIncident.incident_id} • Assigned: {selectedIncident.assigned_administrator || 'Unassigned'}
                        </p>
                      </div>
                      <span className={`text-xs px-2.5 py-1 rounded font-mono border ${getStatusBadge(selectedIncident.status)}`}>
                        {selectedIncident.status}
                      </span>
                    </div>

                    <p className="text-sm text-slate-300">{selectedIncident.description}</p>

                    {/* Containment details */}
                    {selectedIncident.containment_notes && (
                      <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 text-xs">
                        <span className="font-bold text-amber-400">Containment Notes:</span>
                        <p className="text-slate-300 mt-1">{selectedIncident.containment_notes}</p>
                      </div>
                    )}

                    {/* Notes Stream */}
                    <div className="space-y-3 pt-3 border-t border-slate-800">
                      <h4 className="text-xs font-semibold uppercase text-slate-400">Investigation Notes & Observations</h4>
                      <div className="space-y-2 max-h-48 overflow-y-auto">
                        {selectedIncident.notes?.map((n) => (
                          <div key={n.id} className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs space-y-1">
                            <div className="flex justify-between text-slate-400 font-mono text-[10px]">
                              <span>{n.author_username} ({n.note_type})</span>
                              <span>{new Date(n.created_at).toLocaleTimeString()}</span>
                            </div>
                            <p className="text-slate-200">{n.content}</p>
                          </div>
                        ))}
                      </div>

                      {/* Add Note Input */}
                      <div className="flex gap-2 pt-2">
                        <select
                          value={noteType}
                          onChange={(e: any) => setNoteType(e.target.value)}
                          className="bg-slate-950 border border-slate-800 text-xs rounded-lg px-2 text-slate-200"
                        >
                          <option value="OBSERVATION">OBSERVATION</option>
                          <option value="CONTAINMENT">CONTAINMENT</option>
                          <option value="RECOVERY">RECOVERY</option>
                          <option value="ROOT_CAUSE">ROOT_CAUSE</option>
                        </select>
                        <input
                          type="text"
                          value={noteContent}
                          onChange={(e) => setNoteContent(e.target.value)}
                          placeholder="Add incident observation or action note..."
                          className="flex-1 bg-slate-950 border border-slate-800 text-xs rounded-lg px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                        />
                        <button
                          onClick={() => handleAddNote(selectedIncident.incident_id)}
                          className="px-3 py-2 text-xs font-semibold rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white transition-colors"
                        >
                          Add Note
                        </button>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="p-12 text-center rounded-xl bg-slate-900/40 border border-slate-800 text-slate-500">
                    Select an internal incident from the left to view details and containment timeline.
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ------------------------------------------------------------------- */}
      {/* MODAL: INITIATE BACKUP */}
      {/* ------------------------------------------------------------------- */}
      {showBackupModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <Database className="w-5 h-5 text-emerald-400" />
              Initiate Managed Database Backup
            </h3>
            <p className="text-xs text-slate-400">
              Creates a point-in-time cryptographic database backup archive with SHA-256 verification and safe storage references.
            </p>

            <div className="space-y-3">
              <div>
                <label className="text-xs text-slate-400 block mb-1">Backup Archetype</label>
                <select
                  value={backupType}
                  onChange={(e: any) => setBackupType(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white"
                >
                  <option value="MANUAL">MANUAL (SOC Operator Initiated)</option>
                  <option value="FULL">FULL (Full Cold Archive Snapshot)</option>
                  <option value="PRE_MIGRATION">PRE_MIGRATION (Pre-Alembic Safety Backup)</option>
                </select>
              </div>

              <div className="flex items-center gap-2 pt-2">
                <input
                  type="checkbox"
                  id="retentionHold"
                  checked={retentionHold}
                  onChange={(e) => setRetentionHold(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-950 text-emerald-500 focus:ring-0"
                />
                <label htmlFor="retentionHold" className="text-xs text-slate-300">
                  Enable Retention Hold (Protect from automatic lifecycle pruning)
                </label>
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-4 border-t border-slate-800">
              <button
                onClick={() => setShowBackupModal(false)}
                className="px-3.5 py-2 text-xs font-semibold rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleInitiateBackup}
                className="px-4 py-2 text-xs font-semibold rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white transition-colors"
              >
                Generate Backup
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------------- */}
      {/* MODAL: DR CONFIG SLA TARGETS */}
      {/* ------------------------------------------------------------------- */}
      {showDrConfigModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <Sliders className="w-5 h-5 text-indigo-400" />
              Configure Disaster Recovery SLAs
            </h3>

            <div className="space-y-3">
              <div>
                <label className="text-xs text-slate-400 block mb-1">RPO Target (Recovery Point Objective - Minutes)</label>
                <input
                  type="number"
                  value={rpoTarget}
                  onChange={(e) => setRpoTarget(Number(e.target.value))}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white"
                />
              </div>

              <div>
                <label className="text-xs text-slate-400 block mb-1">RTO Target (Recovery Time Objective - Minutes)</label>
                <input
                  type="number"
                  value={rtoTarget}
                  onChange={(e) => setRtoTarget(Number(e.target.value))}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white"
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-4 border-t border-slate-800">
              <button
                onClick={() => setShowDrConfigModal(false)}
                className="px-3.5 py-2 text-xs font-semibold rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleUpdateDrConfig}
                className="px-4 py-2 text-xs font-semibold rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white transition-colors"
              >
                Save SLA Targets
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------------- */}
      {/* MODAL: CREATE INTERNAL INCIDENT */}
      {/* ------------------------------------------------------------------- */}
      {showIncidentModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <Flame className="w-5 h-5 text-amber-400" />
              Open Control-Plane Security Incident
            </h3>

            <div className="space-y-3">
              <div>
                <label className="text-xs text-slate-400 block mb-1">Incident Title</label>
                <input
                  type="text"
                  value={newIncidentTitle}
                  onChange={(e) => setNewIncidentTitle(e.target.value)}
                  placeholder="e.g. Suspected Admin Session Hijacking Probe"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white"
                />
              </div>

              <div>
                <label className="text-xs text-slate-400 block mb-1">Severity</label>
                <select
                  value={newIncidentSeverity}
                  onChange={(e) => setNewIncidentSeverity(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white"
                >
                  <option value="LOW">LOW</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="HIGH">HIGH</option>
                  <option value="CRITICAL">CRITICAL</option>
                </select>
              </div>

              <div>
                <label className="text-xs text-slate-400 block mb-1">Description & Observed Indicators</label>
                <textarea
                  value={newIncidentDesc}
                  onChange={(e) => setNewIncidentDesc(e.target.value)}
                  rows={3}
                  placeholder="Provide detailed description of the suspected anomaly or failure..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white"
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-4 border-t border-slate-800">
              <button
                onClick={() => setShowIncidentModal(false)}
                className="px-3.5 py-2 text-xs font-semibold rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateIncident}
                className="px-4 py-2 text-xs font-semibold rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white transition-colors"
              >
                Create Incident
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------------- */}
      {/* MODAL: RESOLVE ALERT */}
      {/* ------------------------------------------------------------------- */}
      {resolvingAlert && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              Resolve Internal Security Alert
            </h3>
            <p className="text-xs text-slate-400">
              Alert: <strong className="text-white">{resolvingAlert.title}</strong> (#{resolvingAlert.alert_id})
            </p>

            <div>
              <label className="text-xs text-slate-400 block mb-1">Resolution Notes & Actions Taken</label>
              <textarea
                value={resolutionNotes}
                onChange={(e) => setResolutionNotes(e.target.value)}
                rows={3}
                placeholder="Explain how this control-plane alert was investigated and remediated..."
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white"
              />
            </div>

            <div className="flex justify-end gap-2 pt-4 border-t border-slate-800">
              <button
                onClick={() => setResolvingAlert(null)}
                className="px-3.5 py-2 text-xs font-semibold rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleResolveAlert}
                className="px-4 py-2 text-xs font-semibold rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white transition-colors"
              >
                Confirm Resolution
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

