import React, { useState, useEffect } from 'react';
import {
  Server,
  Activity,
  AlertTriangle,
  RotateCcw,
  Plus,
  Key,
  ShieldCheck,
  Search,
  Clock,
  CheckCircle2,
  XCircle,
  Cpu,
  HardDrive,
  Copy,
  Check,
  Layers,
  Wrench,
  Power,
  Sliders,
  History,
  FileText,
  Radio,
  Zap,
} from 'lucide-react';
import {
  Sensor,
  SensorDetail,
  SensorOperationsSummary,
  OperationalAlert,
  SensorOperationalStatus,
  SensorHealthStatus,
  OperationalAlertSeverity,
} from '../../types/sensors';
import { sensorsApi } from '../../services/sensorsApi';
import { formatNumber } from '../../utils/format';

export const SensorOperationsPage: React.FC = () => {
  // Summary & inventory state
  const [summary, setSummary] = useState<SensorOperationsSummary | null>(null);
  const [sensors, setSensors] = useState<Sensor[]>([]);
  const [totalSensors, setTotalSensors] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [envFilter, setEnvFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [page, setPage] = useState(1);

  // Selected sensor detail
  const [selectedSensorId, setSelectedSensorId] = useState<string | null>(null);
  const [selectedSensor, setSelectedSensor] = useState<SensorDetail | null>(null);
  const [activeTab, setActiveTab] = useState<
    'vitals' | 'heartbeats' | 'credentials' | 'configurations' | 'alerts'
  >('vitals');

  // Modals
  const [showRegisterModal, setShowRegisterModal] = useState(false);
  const [showKeyRevealModal, setShowKeyRevealModal] = useState(false);
  const [revealedKey, setRevealedKey] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);
  const [showStatusModal, setShowStatusModal] = useState(false);
  const [showMaintenanceModal, setShowMaintenanceModal] = useState(false);
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [showResolveAlertModal, setShowResolveAlertModal] = useState(false);
  const [selectedAlertToResolve, setSelectedAlertToResolve] = useState<string | null>(null);
  const [resolveNotes, setResolveNotes] = useState('');

  // Forms
  const [registerForm, setRegisterForm] = useState({
    sensor_id: '',
    name: '',
    sensor_type: 'WEB_LOGIN_DECOY',
    sensor_version: '1.0.0',
    deployment_environment: 'isolated_lab',
    lab_zone: 'dmz_zone_alpha',
    heartbeat_interval_seconds: 60,
    supported_telemetry_types: ['http_request', 'auth_attempt', 'session_event'],
    admin_notes: '',
  });

  const [statusForm, setStatusForm] = useState({
    operational_status: 'ACTIVE',
    reason: '',
  });

  const [maintenanceForm, setMaintenanceForm] = useState({
    enabled: true,
    reason: '',
  });

  const [configForm, setConfigForm] = useState({
    version: '1.1.0',
    change_reason: '',
    config_json: '{\n  "log_level": "INFO",\n  "deception_latency_ms": 0,\n  "canary_tokens_enabled": true\n}',
  });

  // Load overview and inventory
  const loadData = async () => {
    try {
      setLoading(true);
      const [sum, list] = await Promise.all([
        sensorsApi.getSummary(),
        sensorsApi.listSensors({
          status: statusFilter,
          sensor_type: typeFilter,
          environment: envFilter,
          search: searchQuery,
          page,
          limit: 25,
        }),
      ]);
      setSummary(sum);
      setSensors(list.items);
      setTotalSensors(list.total);

      if (list.items.length > 0 && !selectedSensorId) {
        setSelectedSensorId(list.items[0].sensor_id);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load sensor operations data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [statusFilter, typeFilter, envFilter, page]);

  // Load detail workspace
  const loadDetail = async (id: string) => {
    try {
      const detail = await sensorsApi.getSensorDetail(id);
      setSelectedSensor(detail);
    } catch (err: any) {
      console.error('Failed to load sensor detail:', err);
    }
  };

  useEffect(() => {
    if (selectedSensorId) {
      loadDetail(selectedSensorId);
    }
  }, [selectedSensorId]);

  // Action handlers
  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await sensorsApi.registerSensor(registerForm);
      setShowRegisterModal(false);
      setRevealedKey(res.raw_api_key);
      setShowKeyRevealModal(true);
      await loadData();
      setSelectedSensorId(res.sensor.sensor_id);
    } catch (err: any) {
      alert(`Registration failed: ${err.message}`);
    }
  };

  const handleRotateCredentials = async () => {
    if (!selectedSensor) return;
    if (!window.confirm(`Rotate API credentials for sensor '${selectedSensor.sensor_id}'? Active key will be revoked immediately.`)) {
      return;
    }
    try {
      const res = await sensorsApi.rotateCredentials(selectedSensor.sensor_id);
      setRevealedKey(res.raw_api_key);
      setShowKeyRevealModal(true);
      await loadDetail(selectedSensor.sensor_id);
    } catch (err: any) {
      alert(`Credential rotation failed: ${err.message}`);
    }
  };

  const handleRevokeCredential = async (keyId: string) => {
    if (!selectedSensor) return;
    const reason = window.prompt('Enter justification for key revocation:') || 'Administrative revocation';
    try {
      await sensorsApi.revokeCredential(selectedSensor.sensor_id, keyId, reason);
      await loadDetail(selectedSensor.sensor_id);
    } catch (err: any) {
      alert(`Revocation failed: ${err.message}`);
    }
  };

  const handleStatusUpdate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedSensor) return;
    try {
      await sensorsApi.updateStatus(selectedSensor.sensor_id, statusForm);
      setShowStatusModal(false);
      await loadDetail(selectedSensor.sensor_id);
      await loadData();
    } catch (err: any) {
      alert(`Status update failed: ${err.message}`);
    }
  };

  const handleMaintenanceToggle = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedSensor) return;
    try {
      await sensorsApi.setMaintenanceMode(selectedSensor.sensor_id, maintenanceForm);
      setShowMaintenanceModal(false);
      await loadDetail(selectedSensor.sensor_id);
      await loadData();
    } catch (err: any) {
      alert(`Maintenance toggle failed: ${err.message}`);
    }
  };

  const handleCommitConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedSensor) return;
    try {
      const parsedPayload = JSON.parse(configForm.config_json);
      await sensorsApi.commitConfiguration(selectedSensor.sensor_id, {
        version: configForm.version,
        change_reason: configForm.change_reason,
        config_payload: parsedPayload,
      });
      setShowConfigModal(false);
      await loadDetail(selectedSensor.sensor_id);
    } catch (err: any) {
      alert(`Configuration update failed: ${err.message}`);
    }
  };

  const handleRollbackConfig = async (targetVersion: string) => {
    if (!selectedSensor) return;
    const reason = window.prompt(`Confirm rollback to configuration v${targetVersion}. Enter reason:`);
    if (!reason) return;
    try {
      await sensorsApi.rollbackConfiguration(selectedSensor.sensor_id, {
        target_version: targetVersion,
        change_reason: reason,
      });
      await loadDetail(selectedSensor.sensor_id);
    } catch (err: any) {
      alert(`Rollback failed: ${err.message}`);
    }
  };

  const handleAcknowledgeAlert = async (alertId: string) => {
    try {
      await sensorsApi.acknowledgeAlert(alertId);
      if (selectedSensorId) await loadDetail(selectedSensorId);
      await loadData();
    } catch (err: any) {
      alert(`Acknowledgement failed: ${err.message}`);
    }
  };

  const handleResolveAlertSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAlertToResolve) return;
    try {
      await sensorsApi.resolveAlert(selectedAlertToResolve, resolveNotes);
      setShowResolveAlertModal(false);
      setSelectedAlertToResolve(null);
      setResolveNotes('');
      if (selectedSensorId) await loadDetail(selectedSensorId);
      await loadData();
    } catch (err: any) {
      alert(`Resolution failed: ${err.message}`);
    }
  };

  const handleSweepHealth = async () => {
    try {
      await sensorsApi.sweepHealth();
      await loadData();
      if (selectedSensorId) await loadDetail(selectedSensorId);
    } catch (err: any) {
      alert(`Health sweep failed: ${err.message}`);
    }
  };

  // Status badge styling helper
  const getStatusBadge = (status: SensorOperationalStatus) => {
    switch (status) {
      case 'ACTIVE':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">ACTIVE</span>;
      case 'DEGRADED':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/30">DEGRADED</span>;
      case 'OFFLINE':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/30">OFFLINE</span>;
      case 'MAINTENANCE':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-orange-500/20 text-orange-400 border border-orange-500/30">MAINTENANCE</span>;
      case 'DISABLED':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-slate-700 text-slate-300">DISABLED</span>;
      case 'RETIRED':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-slate-900 text-slate-500 border border-slate-800">RETIRED</span>;
      default:
        return <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-blue-500/20 text-blue-400 border border-blue-500/30">{status}</span>;
    }
  };

  const getHealthBadge = (health: SensorHealthStatus) => {
    switch (health) {
      case 'HEALTHY':
        return <span className="text-[11px] font-semibold text-emerald-400 flex items-center gap-1"><CheckCircle2 className="w-3 h-3" /> Healthy</span>;
      case 'DEGRADED':
        return <span className="text-[11px] font-semibold text-amber-400 flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> Degraded</span>;
      case 'CRITICAL':
        return <span className="text-[11px] font-semibold text-rose-400 flex items-center gap-1"><XCircle className="w-3 h-3" /> Critical</span>;
      default:
        return <span className="text-[11px] text-slate-400">Unknown</span>;
    }
  };

  const getSeverityBadge = (sev: OperationalAlertSeverity) => {
    switch (sev) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-rose-500/20 text-rose-400 border border-rose-500/30">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-orange-500/20 text-orange-400 border border-orange-500/30">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2 py-0.5 text-[10px] font-semibold rounded bg-amber-500/20 text-amber-400 border border-amber-500/30">MEDIUM</span>;
      default:
        return <span className="px-2 py-0.5 text-[10px] font-medium rounded bg-slate-800 text-slate-400">LOW</span>;
    }
  };

  return (
    <div className="flex flex-col h-full bg-slate-950 text-slate-100">
      {/* 1. Top Header & Operational Metrics */}
      <div className="border-b border-slate-800 bg-slate-900/60 px-6 py-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
          <div>
            <div className="flex items-center gap-3">
              <Radio className="w-6 h-6 text-cyan-400 animate-pulse" />
              <h1 className="text-xl font-bold tracking-tight text-white">Sensor Operations & Health</h1>
              <span className="px-2 py-0.5 text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 rounded-full">
                Telemetry Fleet Monitoring
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Centralized honeypot sensor inventory, heartbeat vitals, versioned configurations, and operational reliability.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleSweepHealth}
              className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg flex items-center gap-1.5 transition"
            >
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              Sweep Health
            </button>
            <button
              onClick={() => loadData()}
              className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg flex items-center gap-1.5 transition"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Refresh
            </button>
            <button
              onClick={() => setShowRegisterModal(true)}
              className="px-3 py-1.5 text-xs font-medium bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg flex items-center gap-1.5 shadow-sm transition"
            >
              <Plus className="w-3.5 h-3.5" />
              Register Sensor
            </button>
          </div>
        </div>

        {/* Fleet Metrics Overview */}
        {summary && (
          <div className="grid grid-cols-2 md:grid-cols-7 gap-3">
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-3">
              <span className="text-xs font-medium text-slate-400">Total Sensors</span>
              <div className="text-xl font-bold text-slate-100 mt-1">{summary.total_registered_sensors}</div>
            </div>
            <div className="bg-slate-900 border border-emerald-500/20 rounded-lg p-3 bg-emerald-500/5">
              <span className="text-xs font-medium text-emerald-400">Active</span>
              <div className="text-xl font-bold text-emerald-400 mt-1">{summary.active_sensors}</div>
            </div>
            <div className="bg-slate-900 border border-amber-500/20 rounded-lg p-3 bg-amber-500/5">
              <span className="text-xs font-medium text-amber-400">Degraded</span>
              <div className="text-xl font-bold text-amber-400 mt-1">{summary.degraded_sensors}</div>
            </div>
            <div className="bg-slate-900 border border-rose-500/20 rounded-lg p-3 bg-rose-500/5">
              <span className="text-xs font-medium text-rose-400">Offline</span>
              <div className="text-xl font-bold text-rose-400 mt-1">{summary.offline_sensors}</div>
            </div>
            <div className="bg-slate-900 border border-orange-500/20 rounded-lg p-3 bg-orange-500/5">
              <span className="text-xs font-medium text-orange-400">Maintenance</span>
              <div className="text-xl font-bold text-orange-400 mt-1">{summary.maintenance_sensors}</div>
            </div>
            <div className="bg-slate-900 border border-cyan-500/20 rounded-lg p-3 bg-cyan-500/5">
              <span className="text-xs font-medium text-cyan-400">Ingestion Reliability</span>
              <div className="text-xl font-bold text-cyan-300 mt-1">{summary.ingestion_success_rate}%</div>
            </div>
            <div className="bg-slate-900 border border-rose-500/40 rounded-lg p-3 bg-rose-500/10">
              <span className="text-xs font-medium text-rose-300 flex items-center gap-1">
                <AlertTriangle className="w-3 h-3 text-rose-400" />
                Operational Alerts
              </span>
              <div className="text-xl font-bold text-rose-400 mt-1">{summary.open_operational_alerts_count}</div>
            </div>
          </div>
        )}
      </div>

      {/* 2. Split Workspace Layout */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Column: Sensor Inventory List */}
        <div className="w-80 md:w-96 border-r border-slate-800 flex flex-col bg-slate-900/40 shrink-0">
          {/* Search & Filter Header */}
          <div className="p-3 border-b border-slate-800 space-y-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
              <input
                type="text"
                placeholder="Search sensors..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && loadData()}
                className="w-full pl-8 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-md text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="text-xs bg-slate-950 border border-slate-800 rounded-md px-2 py-1 text-slate-300 focus:outline-none"
              >
                <option value="ALL">All Statuses</option>
                <option value="ACTIVE">Active</option>
                <option value="DEGRADED">Degraded</option>
                <option value="OFFLINE">Offline</option>
                <option value="MAINTENANCE">Maintenance</option>
                <option value="DISABLED">Disabled</option>
                <option value="REGISTERED">Registered</option>
              </select>
              <select
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
                className="text-xs bg-slate-950 border border-slate-800 rounded-md px-2 py-1 text-slate-300 focus:outline-none"
              >
                <option value="ALL">All Archetypes</option>
                <option value="WEB_LOGIN_DECOY">Web Decoy</option>
                <option value="COWRIE_SSH">Cowrie SSH</option>
                <option value="GENERIC_COLLECTOR">Collector Forwarder</option>
              </select>
            </div>
          </div>

          {/* Sensor Cards List */}
          <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60">
            {loading && sensors.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500">Loading sensor inventory...</div>
            ) : sensors.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500">No sensors match current filters</div>
            ) : (
              sensors.map((s) => {
                const isSelected = selectedSensorId === s.sensor_id;
                return (
                  <div
                    key={s.sensor_id}
                    onClick={() => setSelectedSensorId(s.sensor_id)}
                    className={`p-3.5 cursor-pointer transition border-l-2 ${
                      isSelected
                        ? 'bg-slate-800/80 border-cyan-500'
                        : 'hover:bg-slate-800/40 border-transparent'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <span className="font-mono text-xs font-semibold text-slate-200">{s.sensor_id}</span>
                      {getStatusBadge(s.operational_status)}
                    </div>
                    <h4 className="text-xs font-medium text-slate-100 line-clamp-1">{s.name}</h4>
                    <div className="flex items-center justify-between text-[11px] text-slate-400 mt-2">
                      <div className="flex items-center gap-1.5">
                        <span className="font-mono text-[10px] px-1.5 py-0.2 bg-slate-800 rounded text-slate-300 border border-slate-700">
                          {s.sensor_type}
                        </span>
                      </div>
                      <div>{getHealthBadge(s.health_status)}</div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Sensor Detail Workspace */}
        <div className="flex-1 flex flex-col bg-slate-950 overflow-hidden">
          {selectedSensor ? (
            <>
              {/* Workspace Header */}
              <div className="p-5 border-b border-slate-800 bg-slate-900/30">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-mono text-xs text-cyan-400 font-semibold">{selectedSensor.sensor_id}</span>
                      {getStatusBadge(selectedSensor.operational_status)}
                      {getHealthBadge(selectedSensor.health_status)}
                      <span className="text-xs text-slate-500">
                        Env: <strong className="text-slate-300">{selectedSensor.deployment_environment}</strong>
                      </span>
                    </div>
                    <h2 className="text-lg font-bold text-white">{selectedSensor.name}</h2>
                    <p className="text-xs text-slate-400 mt-1 max-w-2xl">{selectedSensor.admin_notes || 'No administrative notes recorded.'}</p>
                  </div>

                  {/* Actions Toolbar */}
                  <div className="flex items-center gap-2">
                    <button
                      onClick={handleRotateCredentials}
                      className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg flex items-center gap-1 transition"
                    >
                      <Key className="w-3.5 h-3.5 text-amber-400" />
                      Rotate Key
                    </button>
                    <button
                      onClick={() => {
                        setMaintenanceForm({
                          enabled: selectedSensor.operational_status !== 'MAINTENANCE',
                          reason: '',
                        });
                        setShowMaintenanceModal(true);
                      }}
                      className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg flex items-center gap-1 transition"
                    >
                      <Wrench className="w-3.5 h-3.5 text-orange-400" />
                      {selectedSensor.operational_status === 'MAINTENANCE' ? 'Exit Maintenance' : 'Maintenance Mode'}
                    </button>
                    <button
                      onClick={() => {
                        setStatusForm({
                          operational_status: selectedSensor.operational_status,
                          reason: '',
                        });
                        setShowStatusModal(true);
                      }}
                      className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg flex items-center gap-1 transition"
                    >
                      <Power className="w-3.5 h-3.5 text-cyan-400" />
                      Change Status
                    </button>
                  </div>
                </div>

                {/* Workspace Navigation Tabs */}
                <div className="flex items-center gap-4 mt-5 border-b border-slate-800/80 -mb-5 text-xs font-medium text-slate-400">
                  <button
                    onClick={() => setActiveTab('vitals')}
                    className={`pb-3 px-1 border-b-2 transition ${
                      activeTab === 'vitals'
                        ? 'border-cyan-500 text-cyan-400 font-semibold'
                        : 'border-transparent hover:text-slate-200'
                    }`}
                  >
                    Vitals & Telemetry
                  </button>
                  <button
                    onClick={() => setActiveTab('heartbeats')}
                    className={`pb-3 px-1 border-b-2 transition flex items-center gap-1.5 ${
                      activeTab === 'heartbeats'
                        ? 'border-cyan-500 text-cyan-400 font-semibold'
                        : 'border-transparent hover:text-slate-200'
                    }`}
                  >
                    Heartbeats & Vitals
                    {selectedSensor.recent_heartbeats.length > 0 && (
                      <span className="px-1.5 py-0.2 rounded-full bg-slate-800 text-slate-300 text-[10px]">
                        {selectedSensor.recent_heartbeats.length}
                      </span>
                    )}
                  </button>
                  <button
                    onClick={() => setActiveTab('credentials')}
                    className={`pb-3 px-1 border-b-2 transition flex items-center gap-1.5 ${
                      activeTab === 'credentials'
                        ? 'border-cyan-500 text-cyan-400 font-semibold'
                        : 'border-transparent hover:text-slate-200'
                    }`}
                  >
                    Credentials & Auth
                    <span className="px-1.5 py-0.2 rounded-full bg-slate-800 text-slate-300 text-[10px]">
                      {selectedSensor.credentials.length}
                    </span>
                  </button>
                  <button
                    onClick={() => setActiveTab('configurations')}
                    className={`pb-3 px-1 border-b-2 transition flex items-center gap-1.5 ${
                      activeTab === 'configurations'
                        ? 'border-cyan-500 text-cyan-400 font-semibold'
                        : 'border-transparent hover:text-slate-200'
                    }`}
                  >
                    Configuration History
                  </button>
                  <button
                    onClick={() => setActiveTab('alerts')}
                    className={`pb-3 px-1 border-b-2 transition flex items-center gap-1.5 ${
                      activeTab === 'alerts'
                        ? 'border-cyan-500 text-cyan-400 font-semibold'
                        : 'border-transparent hover:text-slate-200'
                    }`}
                  >
                    Operational Alerts
                    {selectedSensor.open_operational_alerts.length > 0 && (
                      <span className="px-1.5 py-0.2 rounded-full bg-rose-500/20 text-rose-300 text-[10px]">
                        {selectedSensor.open_operational_alerts.length}
                      </span>
                    )}
                  </button>
                </div>
              </div>

              {/* Workspace Content View */}
              <div className="flex-1 overflow-y-auto p-6">
                {/* 1. VITALS & TELEMETRY TAB */}
                {activeTab === 'vitals' && (
                  <div className="space-y-6 max-w-4xl">
                    <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
                      <h3 className="text-sm font-semibold text-white mb-3">Sensor Technical Specifications</h3>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                        <div>
                          <span className="text-slate-500">Archetype:</span>
                          <div className="font-medium text-slate-200 mt-0.5">{selectedSensor.sensor_type}</div>
                        </div>
                        <div>
                          <span className="text-slate-500">Software Version:</span>
                          <div className="font-medium text-slate-200 mt-0.5">v{selectedSensor.sensor_version}</div>
                        </div>
                        <div>
                          <span className="text-slate-500">Deployment Environment:</span>
                          <div className="font-medium text-slate-200 mt-0.5">{selectedSensor.deployment_environment}</div>
                        </div>
                        <div>
                          <span className="text-slate-500">Network / Lab Zone:</span>
                          <div className="font-medium text-slate-200 mt-0.5">{selectedSensor.lab_zone}</div>
                        </div>
                        <div>
                          <span className="text-slate-500">Heartbeat Interval:</span>
                          <div className="font-medium text-slate-200 mt-0.5">{selectedSensor.heartbeat_interval_seconds}s</div>
                        </div>
                        <div>
                          <span className="text-slate-500">Missed Heartbeats:</span>
                          <div className={`font-medium mt-0.5 ${selectedSensor.missed_heartbeat_count > 0 ? 'text-amber-400' : 'text-slate-200'}`}>
                            {selectedSensor.missed_heartbeat_count}
                          </div>
                        </div>
                        <div>
                          <span className="text-slate-500">Last Successful Heartbeat:</span>
                          <div className="font-medium text-slate-200 mt-0.5">
                            {selectedSensor.last_heartbeat_at ? new Date(selectedSensor.last_heartbeat_at).toLocaleString() : 'Never'}
                          </div>
                        </div>
                        <div>
                          <span className="text-slate-500">Last Telemetry Ingested:</span>
                          <div className="font-medium text-slate-200 mt-0.5">
                            {selectedSensor.last_telemetry_at ? new Date(selectedSensor.last_telemetry_at).toLocaleString() : 'Never'}
                          </div>
                        </div>
                      </div>

                      <div className="mt-4 pt-4 border-t border-slate-800">
                        <span className="text-xs font-semibold text-slate-400">Supported Telemetry Types:</span>
                        <div className="flex flex-wrap gap-1.5 mt-2">
                          {selectedSensor.supported_telemetry_types.map((t) => (
                            <span key={t} className="px-2 py-0.5 text-[11px] bg-slate-800 text-slate-300 border border-slate-700 rounded">
                              {t}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* 2. HEARTBEATS TAB */}
                {activeTab === 'heartbeats' && (
                  <div className="space-y-4 max-w-4xl">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-semibold text-white">Recent Heartbeat Submissions</h3>
                      <span className="text-xs text-slate-400">Telemetry process vitals reported via authenticated streams.</span>
                    </div>

                    {selectedSensor.recent_heartbeats.length > 0 ? (
                      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden text-xs">
                        <table className="w-full divide-y divide-slate-800">
                          <thead className="bg-slate-950/60 text-slate-400">
                            <tr>
                              <th className="px-4 py-2 text-left font-medium">Timestamp (UTC)</th>
                              <th className="px-4 py-2 text-left font-medium">Status</th>
                              <th className="px-4 py-2 text-left font-medium">Latency</th>
                              <th className="px-4 py-2 text-left font-medium">Vitals (CPU / Mem)</th>
                              <th className="px-4 py-2 text-left font-medium">Error Category</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-800/60">
                            {selectedSensor.recent_heartbeats.map((hb) => (
                              <tr key={hb.id} className="hover:bg-slate-800/30">
                                <td className="px-4 py-2.5 font-mono text-slate-300">{new Date(hb.timestamp).toLocaleString()}</td>
                                <td className="px-4 py-2.5">
                                  <span className={`px-2 py-0.5 text-[10px] font-semibold rounded ${hb.status === 'HEALTHY' ? 'bg-emerald-500/10 text-emerald-300' : 'bg-rose-500/10 text-rose-300'}`}>
                                    {hb.status}
                                  </span>
                                </td>
                                <td className="px-4 py-2.5 font-mono text-slate-300">
                                  {typeof hb.latency_ms === 'number' ? `${formatNumber(hb.latency_ms, 1)} ms` : 'N/A'}
                                </td>
                                <td className="px-4 py-2.5 text-slate-300">
                                  CPU: {hb.metrics_payload?.cpu_percent ?? 0}% | RAM: {hb.metrics_payload?.memory_mb ?? 0}MB
                                </td>
                                <td className="px-4 py-2.5 text-slate-400">{hb.error_category || 'None'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <div className="bg-slate-900 border border-slate-800 rounded-lg p-8 text-center text-xs text-slate-500">
                        No heartbeats recorded for this sensor yet.
                      </div>
                    )}
                  </div>
                )}

                {/* 3. CREDENTIALS TAB */}
                {activeTab === 'credentials' && (
                  <div className="space-y-4 max-w-4xl">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-sm font-semibold text-white">Sensor Authentication Credentials</h3>
                        <p className="text-xs text-slate-400">Cryptographic tokens with SHA-256 storage and rotation support.</p>
                      </div>
                      <button
                        onClick={handleRotateCredentials}
                        className="px-3 py-1.5 text-xs font-medium bg-amber-600 hover:bg-amber-500 text-white rounded-md flex items-center gap-1 transition"
                      >
                        <Key className="w-3.5 h-3.5" />
                        Rotate API Key
                      </button>
                    </div>

                    <div className="space-y-3">
                      {selectedSensor.credentials.map((cred) => (
                        <div key={cred.id} className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex items-center justify-between text-xs">
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="font-mono font-bold text-slate-200">{cred.key_id}</span>
                              <span className={`px-2 py-0.5 text-[10px] font-semibold rounded ${cred.status === 'ACTIVE' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-slate-800 text-slate-500'}`}>
                                {cred.status}
                              </span>
                            </div>
                            <div className="font-mono text-slate-400 text-xs mt-1">
                              Key Prefix: <strong className="text-slate-300">{cred.key_prefix}</strong>
                            </div>
                            <div className="text-[11px] text-slate-500 mt-1">
                              Created: {new Date(cred.created_at).toLocaleString()}
                              {cred.last_used_at && ` | Last Used: ${new Date(cred.last_used_at).toLocaleString()}`}
                              {cred.revoked_at && ` | Revoked: ${new Date(cred.revoked_at).toLocaleString()} (${cred.revocation_reason})`}
                            </div>
                          </div>

                          {cred.status === 'ACTIVE' && (
                            <button
                              onClick={() => handleRevokeCredential(cred.key_id)}
                              className="px-2.5 py-1 text-xs text-rose-300 hover:bg-rose-950/40 border border-rose-800/60 rounded transition"
                            >
                              Revoke Key
                            </button>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* 4. CONFIGURATION TAB */}
                {activeTab === 'configurations' && (
                  <div className="space-y-4 max-w-4xl">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-sm font-semibold text-white">Versioned Configuration History</h3>
                        <p className="text-xs text-slate-400">Declarative approved configuration versions with rollback support.</p>
                      </div>
                      <button
                        onClick={() => setShowConfigModal(true)}
                        className="px-3 py-1.5 text-xs font-medium bg-cyan-600 hover:bg-cyan-500 text-white rounded-md flex items-center gap-1 transition"
                      >
                        <Sliders className="w-3.5 h-3.5" />
                        Commit New Configuration
                      </button>
                    </div>

                    {selectedSensor.current_configuration && (
                      <div className="bg-slate-900 border border-cyan-500/30 rounded-lg p-4 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-xs font-bold text-cyan-300">
                            Current Active: v{selectedSensor.current_configuration.version}
                          </span>
                          <span className="text-[11px] text-slate-400">
                            By {selectedSensor.current_configuration.updated_by} on {new Date(selectedSensor.current_configuration.created_at).toLocaleString()}
                          </span>
                        </div>
                        <p className="text-xs text-slate-300">{selectedSensor.current_configuration.change_reason}</p>
                        <pre className="p-3 bg-slate-950 rounded border border-slate-800 text-[11px] text-slate-300 font-mono overflow-x-auto">
                          {JSON.stringify(selectedSensor.current_configuration.config_payload, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                )}

                {/* 5. OPERATIONAL ALERTS TAB */}
                {activeTab === 'alerts' && (
                  <div className="space-y-4 max-w-4xl">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-sm font-semibold text-white">Sensor Operational Alerts</h3>
                        <p className="text-xs text-slate-400">Health and delivery anomalies segregated from attacker detections.</p>
                      </div>
                    </div>

                    {selectedSensor.open_operational_alerts.length > 0 ? (
                      <div className="space-y-3">
                        {selectedSensor.open_operational_alerts.map((alert) => (
                          <div key={alert.id} className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-2 text-xs">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <span className="font-mono font-bold text-white">{alert.alert_category}</span>
                                {getSeverityBadge(alert.severity)}
                              </div>
                              <span className={`px-2 py-0.5 text-[10px] font-semibold rounded ${alert.status === 'OPEN' ? 'bg-rose-500/20 text-rose-300' : 'bg-amber-500/20 text-amber-300'}`}>
                                {alert.status}
                              </span>
                            </div>

                            <p className="text-slate-300"><strong className="text-slate-400">Action: </strong>{alert.recommended_action}</p>

                            <pre className="p-2 bg-slate-950 rounded border border-slate-800 text-[11px] text-slate-300 overflow-x-auto">
                              {JSON.stringify(alert.evidence_payload, null, 2)}
                            </pre>

                            <div className="flex items-center justify-between pt-2 border-t border-slate-800/80 text-[11px] text-slate-500">
                              <span>Observed: {new Date(alert.last_observed_at).toLocaleString()}</span>
                              <div className="flex items-center gap-2">
                                {alert.status === 'OPEN' && (
                                  <button
                                    onClick={() => handleAcknowledgeAlert(alert.alert_id)}
                                    className="px-2.5 py-1 text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 transition"
                                  >
                                    Acknowledge
                                  </button>
                                )}
                                <button
                                  onClick={() => {
                                    setSelectedAlertToResolve(alert.alert_id);
                                    setShowResolveAlertModal(true);
                                  }}
                                  className="px-2.5 py-1 text-xs bg-emerald-600 hover:bg-emerald-500 text-white rounded transition"
                                >
                                  Resolve Alert
                                </button>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="bg-slate-900 border border-slate-800 rounded-lg p-8 text-center text-xs text-slate-500">
                        No active operational alerts for this sensor.
                      </div>
                    )}
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center p-8 text-center text-slate-500">
              <Server className="w-12 h-12 text-slate-700 mb-3" />
              <h3 className="text-base font-semibold text-slate-300">No Sensor Selected</h3>
              <p className="text-xs text-slate-500 max-w-sm mt-1">
                Select a honeypot sensor from the left inventory panel to inspect vitals, heartbeats, and credentials.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* MODAL: Register Sensor */}
      {showRegisterModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 w-full max-w-lg shadow-xl">
            <h3 className="text-base font-bold text-white mb-4">Register New Honeypot Sensor</h3>
            <form onSubmit={handleRegister} className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Sensor ID *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. SENSOR-WEB-002"
                    value={registerForm.sensor_id}
                    onChange={(e) => setRegisterForm({ ...registerForm, sensor_id: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Display Name *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. ApexCore SSO Portal Decoy #2"
                    value={registerForm.name}
                    onChange={(e) => setRegisterForm({ ...registerForm, name: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Archetype</label>
                  <select
                    value={registerForm.sensor_type}
                    onChange={(e) => setRegisterForm({ ...registerForm, sensor_type: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none"
                  >
                    <option value="WEB_LOGIN_DECOY">Web Login Decoy</option>
                    <option value="COWRIE_SSH">Cowrie SSH Decoy</option>
                    <option value="GENERIC_COLLECTOR">Telemetry Collector Forwarder</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Environment</label>
                  <select
                    value={registerForm.deployment_environment}
                    onChange={(e) => setRegisterForm({ ...registerForm, deployment_environment: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none"
                  >
                    <option value="isolated_lab">Isolated Lab</option>
                    <option value="dmz_canary">DMZ Canary</option>
                    <option value="staging">Staging</option>
                    <option value="production">Production</option>
                  </select>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Lab / Network Zone</label>
                  <input
                    type="text"
                    value={registerForm.lab_zone}
                    onChange={(e) => setRegisterForm({ ...registerForm, lab_zone: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Heartbeat Interval (sec)</label>
                  <input
                    type="number"
                    min="10"
                    max="3600"
                    value={registerForm.heartbeat_interval_seconds}
                    onChange={(e) => setRegisterForm({ ...registerForm, heartbeat_interval_seconds: parseInt(e.target.value) || 60 })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none"
                  />
                </div>
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Administrative Notes</label>
                <textarea
                  rows={2}
                  placeholder="Operational purpose or sensor deployment location..."
                  value={registerForm.admin_notes}
                  onChange={(e) => setRegisterForm({ ...registerForm, admin_notes: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none"
                />
              </div>
              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowRegisterModal(false)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded font-medium"
                >
                  Complete Registration
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL: One-Time Key Reveal */}
      {showKeyRevealModal && revealedKey && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-amber-500/40 rounded-xl p-6 w-full max-w-md shadow-2xl">
            <div className="flex items-center gap-2 mb-3">
              <Key className="w-5 h-5 text-amber-400" />
              <h3 className="text-base font-bold text-white">Sensor API Credential Issued</h3>
            </div>
            <p className="text-xs text-amber-300/90 leading-relaxed mb-4">
              Copy this API secret immediately. It is stored as a cryptographic SHA-256 hash in SnareSight and <strong className="text-white">will never be displayed again</strong>.
            </p>
            <div className="relative mb-4">
              <input
                type="text"
                readOnly
                value={revealedKey}
                className="w-full bg-slate-950 border border-slate-800 rounded p-2.5 font-mono text-xs text-cyan-300 select-all pr-10"
              />
              <button
                onClick={() => {
                  navigator.clipboard.writeText(revealedKey);
                  setCopiedKey(true);
                  setTimeout(() => setCopiedKey(false), 2000);
                }}
                className="absolute right-2 top-2 p-1 text-slate-400 hover:text-white rounded"
              >
                {copiedKey ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>
            <div className="flex justify-end">
              <button
                onClick={() => {
                  setShowKeyRevealModal(false);
                  setRevealedKey(null);
                }}
                className="px-4 py-1.5 bg-amber-600 hover:bg-amber-500 text-white rounded font-medium text-xs"
              >
                I Have Saved The Secret
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: Change Status */}
      {showStatusModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 w-full max-w-md shadow-xl">
            <h3 className="text-base font-bold text-white mb-4">Change Sensor Operational Status</h3>
            <form onSubmit={handleStatusUpdate} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Operational State</label>
                <select
                  value={statusForm.operational_status}
                  onChange={(e) => setStatusForm({ ...statusForm, operational_status: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none"
                >
                  <option value="ACTIVE">ACTIVE (Accepting telemetry)</option>
                  <option value="DISABLED">DISABLED (Temporarily halted)</option>
                  <option value="RETIRED">RETIRED (Permanently decommissioned)</option>
                </select>
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Reason / Justification *</label>
                <textarea
                  required
                  rows={2}
                  placeholder="Administrative justification for status change..."
                  value={statusForm.reason}
                  onChange={(e) => setStatusForm({ ...statusForm, reason: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none"
                />
              </div>
              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowStatusModal(false)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded font-medium"
                >
                  Apply Status
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL: Maintenance Mode */}
      {showMaintenanceModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 w-full max-w-md shadow-xl">
            <h3 className="text-base font-bold text-white mb-4">Toggle Sensor Maintenance Mode</h3>
            <form onSubmit={handleMaintenanceToggle} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Action</label>
                <div className="p-2 bg-slate-950 rounded border border-slate-800 font-semibold text-slate-200">
                  {maintenanceForm.enabled ? 'ENTER Maintenance Mode' : 'EXIT Maintenance Mode'}
                </div>
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Reason *</label>
                <textarea
                  required
                  rows={2}
                  placeholder="e.g. Host operating system patching, honeynet container redeployment..."
                  value={maintenanceForm.reason}
                  onChange={(e) => setMaintenanceForm({ ...maintenanceForm, reason: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none"
                />
              </div>
              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowMaintenanceModal(false)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-orange-600 hover:bg-orange-500 text-white rounded font-medium"
                >
                  Confirm Toggle
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL: Commit Configuration */}
      {showConfigModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 w-full max-w-lg shadow-xl">
            <h3 className="text-base font-bold text-white mb-4">Commit Versioned Sensor Configuration</h3>
            <form onSubmit={handleCommitConfig} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">New Version *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 1.1.0"
                  value={configForm.version}
                  onChange={(e) => setConfigForm({ ...configForm, version: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Change Reason *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Elevate deception latency to 500ms for crawler exhaustion"
                  value={configForm.change_reason}
                  onChange={(e) => setConfigForm({ ...configForm, change_reason: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Approved Configuration Payload (JSON) *</label>
                <textarea
                  required
                  rows={6}
                  value={configForm.config_json}
                  onChange={(e) => setConfigForm({ ...configForm, config_json: e.target.value })}
                  className="w-full font-mono bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowConfigModal(false)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded font-medium"
                >
                  Commit Configuration
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL: Resolve Operational Alert */}
      {showResolveAlertModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 w-full max-w-md shadow-xl">
            <h3 className="text-base font-bold text-white mb-4">Resolve Operational Alert</h3>
            <form onSubmit={handleResolveAlertSubmit} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Resolution Justification & Actions Taken *</label>
                <textarea
                  required
                  rows={3}
                  placeholder="Explain remediation actions taken (e.g. restarted forwarder daemon, cleared network buffer)..."
                  value={resolveNotes}
                  onChange={(e) => setResolveNotes(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowResolveAlertModal(false)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded font-medium"
                >
                  Mark Resolved
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default SensorOperationsPage;

