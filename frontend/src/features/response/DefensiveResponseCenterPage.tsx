import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  FileCheck2,
  Lock,
  Play,
  RotateCcw,
  CheckCircle2,
  XCircle,
  Clock,
  Search,
  Filter,
  Plus,
  ArrowRight,
  Hash,
  AlertTriangle,
  FolderLock,
  UserCheck,
  Send,
  Link as LinkIcon,
  HelpCircle,
  FileText,
  Activity,
  Layers,
  Info,
} from 'lucide-react';
import {
  ResponseCase,
  ResponseDashboardSummary,
  CaseStatus,
  CasePriority,
  ResponseRecommendation,
  PlaybookDefinition,
  PlaybookExecution,
  ResponseApproval,
  ResponseAction,
  EvidencePreservationHold,
  CaseNote,
} from '../../types/response';
import { responseApi } from '../../services/responseApi';
import { formatPercent, formatDateTime } from '../../utils/format';

export const DefensiveResponseCenterPage: React.FC = () => {
  // Summary & list state
  const [summary, setSummary] = useState<ResponseDashboardSummary | null>(null);
  const [cases, setCases] = useState<ResponseCase[]>([]);
  const [totalCases, setTotalCases] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [priorityFilter, setPriorityFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [page, setPage] = useState(1);

  // Active selected case & sub-tab
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [selectedCase, setSelectedCase] = useState<ResponseCase | null>(null);
  const [activeTab, setActiveTab] = useState<
    'overview' | 'recommendations' | 'playbooks' | 'approvals' | 'actions' | 'holds' | 'notes'
  >('overview');

  // Playbook definitions catalog
  const [playbookCatalog, setPlaybookCatalog] = useState<PlaybookDefinition[]>([]);

  // Modals state
  const [showNewCaseModal, setShowNewCaseModal] = useState(false);
  const [showStatusModal, setShowStatusModal] = useState(false);
  const [showLinkModal, setShowLinkModal] = useState(false);
  const [showApprovalModal, setShowApprovalModal] = useState(false);
  const [showHoldModal, setShowHoldModal] = useState(false);
  const [showPlaybookModal, setShowPlaybookModal] = useState(false);

  // Form states for modals
  const [newCaseForm, setNewCaseForm] = useState({
    title: '',
    description: '',
    priority: 'P3_MEDIUM',
    severity: 'MEDIUM',
    assigned_analyst: '',
    primary_alert_id: '',
    primary_cluster_id: '',
    initial_note: '',
  });

  const [statusForm, setStatusForm] = useState({
    new_status: 'UNDER_REVIEW',
    reason: '',
    resolution_category: 'FALSE_POSITIVE',
  });

  const [linkForm, setLinkForm] = useState({
    related_entity_type: 'ALERT',
    related_entity_id: '',
    relationship_reason: '',
    confidence_score: 0.9,
  });

  const [approvalForm, setApprovalForm] = useState({
    action_type: 'HONEYPOT_SENSITIVITY_BOOST',
    justification: '',
    recommendation_id: '',
  });

  const [holdForm, setHoldForm] = useState({
    evidence_type: 'ALERT',
    evidence_identifier: '',
    hold_reason: '',
  });

  const [selectedPlaybookId, setSelectedPlaybookId] = useState('');

  // Note composer state
  const [newNoteContent, setNewNoteContent] = useState('');
  const [newNoteType, setNewNoteType] = useState('ANALYST_NOTE');
  const [submittingNote, setSubmittingNote] = useState(false);

  // Load initial data
  const loadDashboard = async () => {
    try {
      setLoading(true);
      setError(null);
      const [sum, caseList, pbs] = await Promise.all([
        responseApi.getSummary(),
        responseApi.listCases({
          status: statusFilter,
          priority: priorityFilter,
          search: searchQuery,
          page,
          limit: 20,
        }),
        responseApi.listPlaybooks(),
      ]);
      setSummary(sum);
      setCases(caseList.items);
      setTotalCases(caseList.total);
      setPlaybookCatalog(pbs);

      if (caseList.items.length > 0) {
        if (!selectedCaseId || !caseList.items.some((c) => c.case_id === selectedCaseId)) {
          setSelectedCaseId(caseList.items[0].case_id);
        }
      } else {
        setSelectedCaseId(null);
        setSelectedCase(null);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load response data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboard();
  }, [statusFilter, priorityFilter, page]);

  // Load single case details when selected
  const loadCaseDetail = async (caseId: string) => {
    try {
      const detail = await responseApi.getCase(caseId);
      setSelectedCase(detail);
    } catch (err: any) {
      console.error('Failed to load case detail:', err);
    }
  };

  useEffect(() => {
    if (selectedCaseId) {
      loadCaseDetail(selectedCaseId);
    }
  }, [selectedCaseId]);

  // Action Handlers
  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const created = await responseApi.createCase(newCaseForm);
      setShowNewCaseModal(false);
      setNewCaseForm({
        title: '',
        description: '',
        priority: 'P3_MEDIUM',
        severity: 'MEDIUM',
        assigned_analyst: '',
        primary_alert_id: '',
        primary_cluster_id: '',
        initial_note: '',
      });
      await loadDashboard();
      setSelectedCaseId(created.case_id);
    } catch (err: any) {
      alert(`Error creating case: ${err.message}`);
    }
  };

  const handleStatusTransition = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCase) return;
    try {
      const updated = await responseApi.transitionStatus(selectedCase.case_id, statusForm);
      setShowStatusModal(false);
      setSelectedCase(updated);
      await loadDashboard();
    } catch (err: any) {
      alert(`Error changing status: ${err.message}`);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCase || !newNoteContent.trim()) return;
    try {
      setSubmittingNote(true);
      await responseApi.addNote(selectedCase.case_id, {
        note_type: newNoteType,
        content: newNoteContent.trim(),
      });
      setNewNoteContent('');
      await loadCaseDetail(selectedCase.case_id);
    } catch (err: any) {
      alert(`Error adding note: ${err.message}`);
    } finally {
      setSubmittingNote(false);
    }
  };

  const handleLinkEntity = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCase) return;
    try {
      await responseApi.linkEntity(selectedCase.case_id, linkForm);
      setShowLinkModal(false);
      setLinkForm({
        related_entity_type: 'ALERT',
        related_entity_id: '',
        relationship_reason: '',
        confidence_score: 0.9,
      });
      await loadCaseDetail(selectedCase.case_id);
    } catch (err: any) {
      alert(`Error linking entity: ${err.message}`);
    }
  };

  const handleGenerateRecommendations = async () => {
    if (!selectedCase) return;
    try {
      await responseApi.generateRecommendations(selectedCase.case_id);
      await loadCaseDetail(selectedCase.case_id);
    } catch (err: any) {
      alert(`Error generating recommendations: ${err.message}`);
    }
  };

  const handleRecommendationDecision = async (
    recId: string,
    decision: 'ACCEPT' | 'REJECT'
  ) => {
    if (!selectedCase) return;
    const reason = window.prompt(`Enter justification to ${decision.toLowerCase()} recommendation:`);
    if (reason === null) return;
    try {
      await responseApi.decideRecommendation(selectedCase.case_id, recId, {
        decision,
        reason: reason || `Analyst chose to ${decision.toLowerCase()}`,
      });
      await loadCaseDetail(selectedCase.case_id);
    } catch (err: any) {
      alert(`Error updating recommendation: ${err.message}`);
    }
  };

  const handleStartPlaybook = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCase || !selectedPlaybookId) return;
    try {
      await responseApi.startPlaybook(selectedCase.case_id, {
        playbook_id: selectedPlaybookId,
        inputs: {},
      });
      setShowPlaybookModal(false);
      await loadCaseDetail(selectedCase.case_id);
    } catch (err: any) {
      alert(`Error starting playbook: ${err.message}`);
    }
  };

  const handleAdvancePlaybook = async (executionId: string) => {
    if (!selectedCase) return;
    const notes = window.prompt('Enter execution notes for this step (optional):') || 'Step completed';
    try {
      await responseApi.advancePlaybook(selectedCase.case_id, executionId, {
        step_status: 'SUCCESS',
        step_notes: notes,
      });
      await loadCaseDetail(selectedCase.case_id);
    } catch (err: any) {
      alert(`Error advancing playbook: ${err.message}`);
    }
  };

  const handleRequestApproval = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCase) return;
    try {
      await responseApi.requestApproval(selectedCase.case_id, {
        action_type: approvalForm.action_type,
        justification: approvalForm.justification,
        recommendation_id: approvalForm.recommendation_id || undefined,
      });
      setShowApprovalModal(false);
      setApprovalForm({ action_type: 'HONEYPOT_SENSITIVITY_BOOST', justification: '', recommendation_id: '' });
      await loadCaseDetail(selectedCase.case_id);
      await loadDashboard();
    } catch (err: any) {
      alert(`Error requesting approval: ${err.message}`);
    }
  };

  const handleApprovalDecision = async (approvalId: string, decision: 'APPROVE' | 'REJECT') => {
    if (!selectedCase) return;
    const reason = window.prompt(`Enter reason for ${decision.toLowerCase()}:`) || `Decision: ${decision}`;
    try {
      await responseApi.decideApproval(selectedCase.case_id, approvalId, {
        decision,
        reason,
      });
      await loadCaseDetail(selectedCase.case_id);
      await loadDashboard();
    } catch (err: any) {
      alert(`Error recording approval decision: ${err.message}`);
    }
  };

  const handleCreateHold = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCase) return;
    try {
      await responseApi.createHold(selectedCase.case_id, holdForm);
      setShowHoldModal(false);
      setHoldForm({ evidence_type: 'ALERT', evidence_identifier: '', hold_reason: '' });
      await loadCaseDetail(selectedCase.case_id);
      await loadDashboard();
    } catch (err: any) {
      alert(`Error applying evidence hold: ${err.message}`);
    }
  };

  const handleReleaseHold = async (holdId: string) => {
    if (!selectedCase) return;
    const justification = window.prompt('Enter justification for releasing evidence hold:') || 'Investigation complete';
    try {
      await responseApi.releaseHold(selectedCase.case_id, holdId, { justification });
      await loadCaseDetail(selectedCase.case_id);
      await loadDashboard();
    } catch (err: any) {
      alert(`Error releasing hold: ${err.message}`);
    }
  };

  // Status badge helper
  const getStatusBadge = (status: CaseStatus) => {
    switch (status) {
      case 'OPEN':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-blue-500/20 text-blue-400 border border-blue-500/30">OPEN</span>;
      case 'INVESTIGATING':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-purple-500/20 text-purple-400 border border-purple-500/30">INVESTIGATING</span>;
      case 'AWAITING_APPROVAL':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/30">AWAITING APPROVAL</span>;
      case 'APPROVED':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">APPROVED</span>;
      case 'RESOLVED':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-slate-500/20 text-slate-300 border border-slate-500/30">RESOLVED</span>;
      case 'CLOSED':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-slate-800 text-slate-400 border border-slate-700">CLOSED</span>;
      case 'ACTION_IN_PROGRESS':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">ACTION IN PROGRESS</span>;
      default:
        return <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-slate-700 text-slate-300">{status}</span>;
    }
  };

  const getPriorityBadge = (priority: CasePriority) => {
    switch (priority) {
      case 'P1_CRITICAL':
        return <span className="px-2 py-0.5 text-xs font-bold rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/30">P1 CRITICAL</span>;
      case 'P2_HIGH':
        return <span className="px-2 py-0.5 text-xs font-bold rounded-full bg-orange-500/20 text-orange-400 border border-orange-500/30">P2 HIGH</span>;
      case 'P3_MEDIUM':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/30">P3 MEDIUM</span>;
      case 'P4_LOW':
        return <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-slate-700 text-slate-300">P4 LOW</span>;
      default:
        return <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-slate-800 text-slate-400">P5 INFO</span>;
    }
  };

  return (
    <div className="flex flex-col h-full bg-slate-950 text-slate-100">
      {/* 1. Header & SOC Metrics */}
      <div className="border-b border-slate-800 bg-slate-900/60 px-6 py-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
          <div>
            <div className="flex items-center gap-3">
              <ShieldAlert className="w-6 h-6 text-indigo-400" />
              <h1 className="text-xl font-bold tracking-tight text-white">Defensive Response Center</h1>
              <span className="px-2 py-0.5 text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-full">
                Incident Handling Active
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Analyst-guided threat mitigation, explainable recommendations, controlled playbooks, and evidence preservation.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => loadDashboard()}
              className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg flex items-center gap-1.5 transition"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Refresh
            </button>
            <button
              onClick={() => setShowNewCaseModal(true)}
              className="px-3 py-1.5 text-xs font-medium bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg flex items-center gap-1.5 shadow-sm transition"
            >
              <Plus className="w-3.5 h-3.5" />
              New Response Case
            </button>
          </div>
        </div>

        {/* Metric Cards */}
        {summary && (
          <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-3">
              <span className="text-xs font-medium text-slate-400">Active Cases</span>
              <div className="text-xl font-bold text-slate-100 mt-1">{summary.total_active_cases}</div>
            </div>
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-3">
              <span className="text-xs font-medium text-slate-400">Open Cases</span>
              <div className="text-xl font-bold text-blue-400 mt-1">{summary.open_cases}</div>
            </div>
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-3">
              <span className="text-xs font-medium text-slate-400">Under Investigation</span>
              <div className="text-xl font-bold text-purple-400 mt-1">{summary.investigating_cases}</div>
            </div>
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-3">
              <span className="text-xs font-medium text-slate-400">Critical Priority</span>
              <div className="text-xl font-bold text-rose-400 mt-1">{summary.critical_cases_count}</div>
            </div>
            <div className="bg-slate-900 border border-amber-500/30 rounded-lg p-3 bg-amber-500/5">
              <span className="text-xs font-medium text-amber-300 flex items-center gap-1">
                <AlertTriangle className="w-3 h-3 text-amber-400" />
                Awaiting Approval
              </span>
              <div className="text-xl font-bold text-amber-400 mt-1">{summary.awaiting_approval_count}</div>
            </div>
            <div className="bg-slate-900 border border-cyan-500/30 rounded-lg p-3 bg-cyan-500/5">
              <span className="text-xs font-medium text-cyan-300 flex items-center gap-1">
                <FolderLock className="w-3 h-3 text-cyan-400" />
                Active Holds
              </span>
              <div className="text-xl font-bold text-cyan-400 mt-1">{summary.active_evidence_holds_count}</div>
            </div>
          </div>
        )}

        {/* Error Alert */}
        {error && (
          <div className="mt-3 p-3 bg-red-950/40 border border-red-500/30 rounded-lg flex items-center justify-between text-xs text-red-200">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{error}</span>
            </div>
            <button
              onClick={() => {
                setError(null);
                loadDashboard();
              }}
              className="px-2.5 py-1 bg-red-900/60 hover:bg-red-800 text-red-200 rounded border border-red-700 text-xs transition"
            >
              Retry
            </button>
          </div>
        )}
      </div>

      {/* 2. Main Content Split View */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Column: Response Case Queue */}
        <div className="w-80 md:w-96 border-r border-slate-800 flex flex-col bg-slate-900/40 shrink-0">
          {/* Search & Filters */}
          <div className="p-3 border-b border-slate-800 space-y-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
              <input
                type="text"
                placeholder="Search cases..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && loadDashboard()}
                className="w-full pl-8 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-md text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
              />
            </div>
            <div className="flex items-center gap-2">
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="flex-1 text-xs bg-slate-950 border border-slate-800 rounded-md px-2 py-1 text-slate-300 focus:outline-none"
              >
                <option value="ALL">All Statuses</option>
                <option value="OPEN">Open</option>
                <option value="INVESTIGATING">Investigating</option>
                <option value="RESPONSE_RECOMMENDED">Recommended</option>
                <option value="AWAITING_APPROVAL">Awaiting Approval</option>
                <option value="ACTION_IN_PROGRESS">Action In Progress</option>
                <option value="RESOLVED">Resolved</option>
                <option value="CLOSED">Closed</option>
              </select>
              <select
                value={priorityFilter}
                onChange={(e) => setPriorityFilter(e.target.value)}
                className="flex-1 text-xs bg-slate-950 border border-slate-800 rounded-md px-2 py-1 text-slate-300 focus:outline-none"
              >
                <option value="ALL">All Priorities</option>
                <option value="P1_CRITICAL">P1 Critical</option>
                <option value="P2_HIGH">P2 High</option>
                <option value="P3_MEDIUM">P3 Medium</option>
                <option value="P4_LOW">P4 Low</option>
              </select>
            </div>
          </div>

          {/* Cases List */}
          <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60">
            {loading && cases.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500">Loading cases...</div>
            ) : cases.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500 space-y-2">
                <p>No response cases match selected criteria.</p>
                {(statusFilter !== 'ALL' || priorityFilter !== 'ALL' || searchQuery) && (
                  <button
                    onClick={() => {
                      setStatusFilter('ALL');
                      setPriorityFilter('ALL');
                      setSearchQuery('');
                    }}
                    className="text-xs text-indigo-400 hover:text-indigo-300 underline font-medium"
                  >
                    Reset all filters
                  </button>
                )}
              </div>
            ) : (
              cases.map((c) => {
                const isSelected = selectedCaseId === c.case_id;
                return (
                  <div
                    key={c.case_id}
                    onClick={() => setSelectedCaseId(c.case_id)}
                    className={`p-3.5 cursor-pointer transition border-l-2 ${
                      isSelected
                        ? 'bg-slate-800/80 border-indigo-500'
                        : 'hover:bg-slate-800/40 border-transparent'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <span className="font-mono text-xs font-semibold text-slate-300">{c.case_id}</span>
                      <div className="flex items-center gap-1">
                        {getPriorityBadge(c.priority)}
                      </div>
                    </div>
                    <h4 className="text-xs font-medium text-slate-100 line-clamp-1">{c.title}</h4>
                    <div className="flex items-center justify-between text-[11px] text-slate-400 mt-2">
                      <div className="flex items-center gap-1.5">
                        {getStatusBadge(c.status)}
                      </div>
                      <div className="flex items-center gap-1">
                        <Clock className="w-3 h-3 text-slate-500" />
                        <span>{new Date(c.created_at).toLocaleDateString()}</span>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Case Workspace */}
        <div className="flex-1 flex flex-col bg-slate-950 overflow-hidden">
          {selectedCase ? (
            <>
              {/* Workspace Header */}
              <div className="p-5 border-b border-slate-800 bg-slate-900/30">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-mono text-xs text-indigo-400 font-semibold">{selectedCase.case_id}</span>
                      {getStatusBadge(selectedCase.status)}
                      {getPriorityBadge(selectedCase.priority)}
                      <span className="text-xs text-slate-500">
                        Severity: <strong className="text-slate-300">{selectedCase.severity}</strong>
                      </span>
                    </div>
                    <h2 className="text-lg font-bold text-white">{selectedCase.title}</h2>
                    <p className="text-xs text-slate-400 mt-1 max-w-2xl">{selectedCase.description}</p>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => {
                        setStatusForm({
                          new_status: selectedCase.status,
                          reason: '',
                          resolution_category: 'FALSE_POSITIVE',
                        });
                        setShowStatusModal(true);
                      }}
                      className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg flex items-center gap-1 transition"
                    >
                      <Activity className="w-3.5 h-3.5 text-indigo-400" />
                      Change Status
                    </button>
                    <button
                      onClick={() => setShowHoldModal(true)}
                      className="px-3 py-1.5 text-xs font-medium bg-cyan-950/60 hover:bg-cyan-900/60 text-cyan-300 border border-cyan-800/80 rounded-lg flex items-center gap-1 transition"
                    >
                      <FolderLock className="w-3.5 h-3.5 text-cyan-400" />
                      Apply Hold
                    </button>
                    <button
                      onClick={() => setShowLinkModal(true)}
                      className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg flex items-center gap-1 transition"
                    >
                      <LinkIcon className="w-3.5 h-3.5" />
                      Link Entity
                    </button>
                  </div>
                </div>

                {/* Workspace Navigation Tabs */}
                <div className="flex items-center gap-4 mt-5 border-b border-slate-800/80 -mb-5 text-xs font-medium text-slate-400">
                  <button
                    onClick={() => setActiveTab('overview')}
                    className={`pb-3 px-1 border-b-2 transition ${
                      activeTab === 'overview'
                        ? 'border-indigo-500 text-indigo-400 font-semibold'
                        : 'border-transparent hover:text-slate-200'
                    }`}
                  >
                    Overview & Links
                  </button>
                  <button
                    onClick={() => setActiveTab('recommendations')}
                    className={`pb-3 px-1 border-b-2 transition flex items-center gap-1.5 ${
                      activeTab === 'recommendations'
                        ? 'border-indigo-500 text-indigo-400 font-semibold'
                        : 'border-transparent hover:text-slate-200'
                    }`}
                  >
                    Recommendations
                    {selectedCase.recommendations && selectedCase.recommendations.length > 0 && (
                      <span className="px-1.5 py-0.2 rounded-full bg-indigo-500/20 text-indigo-300 text-[10px]">
                        {selectedCase.recommendations.length}
                      </span>
                    )}
                  </button>
                  <button
                    onClick={() => setActiveTab('playbooks')}
                    className={`pb-3 px-1 border-b-2 transition flex items-center gap-1.5 ${
                      activeTab === 'playbooks'
                        ? 'border-indigo-500 text-indigo-400 font-semibold'
                        : 'border-transparent hover:text-slate-200'
                    }`}
                  >
                    Playbooks
                    {selectedCase.executions && selectedCase.executions.length > 0 && (
                      <span className="px-1.5 py-0.2 rounded-full bg-slate-800 text-slate-300 text-[10px]">
                        {selectedCase.executions.length}
                      </span>
                    )}
                  </button>
                  <button
                    onClick={() => setActiveTab('approvals')}
                    className={`pb-3 px-1 border-b-2 transition flex items-center gap-1.5 ${
                      activeTab === 'approvals'
                        ? 'border-indigo-500 text-indigo-400 font-semibold'
                        : 'border-transparent hover:text-slate-200'
                    }`}
                  >
                    Approvals
                    {selectedCase.approvals && selectedCase.approvals.filter((a) => a.status === 'PENDING').length > 0 && (
                      <span className="px-1.5 py-0.2 rounded-full bg-amber-500/20 text-amber-300 text-[10px]">
                        {selectedCase.approvals.filter((a) => a.status === 'PENDING').length}
                      </span>
                    )}
                  </button>
                  <button
                    onClick={() => setActiveTab('actions')}
                    className={`pb-3 px-1 border-b-2 transition flex items-center gap-1.5 ${
                      activeTab === 'actions'
                        ? 'border-indigo-500 text-indigo-400 font-semibold'
                        : 'border-transparent hover:text-slate-200'
                    }`}
                  >
                    Defensive Actions
                  </button>
                  <button
                    onClick={() => setActiveTab('holds')}
                    className={`pb-3 px-1 border-b-2 transition flex items-center gap-1.5 ${
                      activeTab === 'holds'
                        ? 'border-indigo-500 text-indigo-400 font-semibold'
                        : 'border-transparent hover:text-slate-200'
                    }`}
                  >
                    Evidence Holds
                    {selectedCase.preservation_holds && selectedCase.preservation_holds.filter((h) => h.retention_hold_status === 'ACTIVE').length > 0 && (
                      <span className="px-1.5 py-0.2 rounded-full bg-cyan-500/20 text-cyan-300 text-[10px]">
                        {selectedCase.preservation_holds.filter((h) => h.retention_hold_status === 'ACTIVE').length}
                      </span>
                    )}
                  </button>
                  <button
                    onClick={() => setActiveTab('notes')}
                    className={`pb-3 px-1 border-b-2 transition flex items-center gap-1.5 ${
                      activeTab === 'notes'
                        ? 'border-indigo-500 text-indigo-400 font-semibold'
                        : 'border-transparent hover:text-slate-200'
                    }`}
                  >
                    Notes & Timeline
                  </button>
                </div>
              </div>

              {/* Workspace Tab Content */}
              <div className="flex-1 overflow-y-auto p-6">
                {/* 1. OVERVIEW & LINKS TAB */}
                {activeTab === 'overview' && (
                  <div className="space-y-6 max-w-4xl">
                    <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
                      <h3 className="text-sm font-semibold text-white mb-3">Case Metadata</h3>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                        <div>
                          <span className="text-slate-500">Assigned Analyst:</span>
                          <div className="font-medium text-slate-200 mt-0.5">
                            {selectedCase.assigned_analyst || 'Unassigned'}
                          </div>
                        </div>
                        <div>
                          <span className="text-slate-500">Created By:</span>
                          <div className="font-medium text-slate-200 mt-0.5">{selectedCase.created_by}</div>
                        </div>
                        <div>
                          <span className="text-slate-500">Primary Alert ID:</span>
                          <div className="font-mono text-slate-200 mt-0.5">
                            {selectedCase.primary_alert_id || 'None'}
                          </div>
                        </div>
                        <div>
                          <span className="text-slate-500">Primary Cluster ID:</span>
                          <div className="font-mono text-slate-200 mt-0.5">
                            {selectedCase.primary_cluster_id || 'None'}
                          </div>
                        </div>
                      </div>

                      {selectedCase.resolution_summary && (
                        <div className="mt-4 pt-4 border-t border-slate-800">
                          <span className="text-xs font-semibold text-emerald-400">Resolution Summary:</span>
                          <p className="text-xs text-slate-300 mt-1">{selectedCase.resolution_summary}</p>
                          {selectedCase.resolution_category && (
                            <span className="inline-block mt-2 px-2 py-0.5 text-[11px] font-semibold bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 rounded">
                              Category: {selectedCase.resolution_category}
                            </span>
                          )}
                        </div>
                      )}
                    </div>

                    {/* Linked Entities Table */}
                    <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
                      <div className="flex items-center justify-between mb-3">
                        <h3 className="text-sm font-semibold text-white">Linked Investigation Entities</h3>
                        <button
                          onClick={() => setShowLinkModal(true)}
                          className="px-2.5 py-1 text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 rounded border border-slate-700 transition"
                        >
                          + Link Another Entity
                        </button>
                      </div>

                      {selectedCase.relationships && selectedCase.relationships.length > 0 ? (
                        <div className="divide-y divide-slate-800/80">
                          {selectedCase.relationships.map((rel) => (
                            <div key={rel.id} className="py-2.5 flex items-center justify-between text-xs">
                              <div>
                                <span className="px-2 py-0.5 font-mono text-[10px] bg-slate-800 text-slate-300 rounded border border-slate-700 mr-2">
                                  {rel.related_entity_type}
                                </span>
                                <span className="font-mono font-medium text-slate-200">{rel.related_entity_id}</span>
                                <p className="text-slate-400 text-[11px] mt-0.5">{rel.relationship_reason}</p>
                              </div>
                              <div className="text-right">
                                <span className="text-[11px] text-slate-400">
                                  Confidence: {formatPercent(rel.confidence_score, 0, 'N/A', 100)}
                                </span>
                                <div className="text-[10px] text-slate-500 mt-0.5">By {rel.created_by}</div>
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="text-xs text-slate-500 py-4 text-center">
                          No related entities explicitly linked to this case yet.
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* 2. RECOMMENDATIONS TAB */}
                {activeTab === 'recommendations' && (
                  <div className="space-y-4 max-w-4xl">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-sm font-semibold text-white">Rule-Based Recommendations</h3>
                        <p className="text-xs text-slate-400">
                          Explainable mitigation proposals backed by concrete telemetry and evidence citations.
                        </p>
                      </div>
                      <button
                        onClick={handleGenerateRecommendations}
                        className="px-3 py-1.5 text-xs font-medium bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg flex items-center gap-1.5 shadow-sm transition"
                      >
                        <ShieldAlert className="w-3.5 h-3.5" />
                        Run Recommendation Engine
                      </button>
                    </div>

                    {selectedCase.recommendations && selectedCase.recommendations.length > 0 ? (
                      <div className="space-y-4 mt-3">
                        {selectedCase.recommendations.map((rec) => (
                          <div
                            key={rec.id}
                            className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-3"
                          >
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <span className="font-mono text-xs px-2 py-0.5 bg-indigo-950/60 border border-indigo-800 text-indigo-300 rounded">
                                  {rec.rule_id} v{rec.rule_version}
                                </span>
                                <h4 className="text-sm font-semibold text-white">{rec.title}</h4>
                              </div>
                              <span
                                className={`px-2 py-0.5 text-xs font-semibold rounded ${
                                  rec.status === 'ACCEPTED'
                                    ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                                    : rec.status === 'REJECTED'
                                    ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                                    : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                                }`}
                              >
                                {rec.status}
                              </span>
                            </div>

                            <p className="text-xs text-slate-300 leading-relaxed">{rec.explanation}</p>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs bg-slate-950 p-3 rounded border border-slate-800/80">
                              <div>
                                <span className="text-slate-500">Potential Impact:</span>
                                <p className="text-slate-300 mt-0.5">{rec.potential_impact}</p>
                              </div>
                              <div>
                                <span className="text-slate-500">Reversal Guidance:</span>
                                <p className="text-slate-300 mt-0.5">{rec.reversal_guidance}</p>
                              </div>
                            </div>

                            {/* Triggering evidence */}
                            {rec.triggering_evidence && Object.keys(rec.triggering_evidence).length > 0 && (
                              <div className="text-xs">
                                <span className="text-slate-500 font-medium">Supporting Evidence:</span>
                                <pre className="mt-1 p-2 bg-slate-950 rounded border border-slate-800 text-[11px] text-slate-300 overflow-x-auto">
                                  {JSON.stringify(rec.triggering_evidence, null, 2)}
                                </pre>
                              </div>
                            )}

                            {/* Action Buttons */}
                            {rec.status === 'PENDING' && (
                              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                                <button
                                  onClick={() => handleRecommendationDecision(rec.recommendation_id, 'REJECT')}
                                  className="px-3 py-1.5 text-xs font-medium text-rose-300 hover:bg-rose-950/40 border border-rose-800/60 rounded-md transition"
                                >
                                  Reject Proposal
                                </button>
                                <button
                                  onClick={() => handleRecommendationDecision(rec.recommendation_id, 'ACCEPT')}
                                  className="px-3 py-1.5 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-md transition shadow-sm"
                                >
                                  Accept & Proceed
                                </button>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="bg-slate-900 border border-slate-800 rounded-lg p-8 text-center text-xs text-slate-500">
                        No recommendations generated for this case yet. Click "Run Recommendation Engine" above to analyze telemetry.
                      </div>
                    )}
                  </div>
                )}

                {/* 3. PLAYBOOKS TAB */}
                {activeTab === 'playbooks' && (
                  <div className="space-y-6 max-w-4xl">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-sm font-semibold text-white">Safe Response Playbooks</h3>
                        <p className="text-xs text-slate-400">
                          Structured, non-destructive step-by-step procedures for incident handling.
                        </p>
                      </div>
                      <button
                        onClick={() => setShowPlaybookModal(true)}
                        className="px-3 py-1.5 text-xs font-medium bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg flex items-center gap-1.5 shadow-sm transition"
                      >
                        <Play className="w-3.5 h-3.5" />
                        Execute Playbook
                      </button>
                    </div>

                    {/* Active Playbook Executions */}
                    {selectedCase.executions && selectedCase.executions.length > 0 ? (
                      <div className="space-y-4">
                        {selectedCase.executions.map((exec) => (
                          <div
                            key={exec.id}
                            className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4"
                          >
                            <div className="flex items-center justify-between">
                              <div>
                                <span className="font-mono text-xs px-2 py-0.5 bg-slate-800 border border-slate-700 text-slate-300 rounded mr-2">
                                  {exec.playbook_id}
                                </span>
                                <span className="text-xs font-semibold text-slate-200">Execution {exec.execution_id}</span>
                              </div>
                              <span
                                className={`px-2 py-0.5 text-xs font-semibold rounded ${
                                  exec.status === 'COMPLETED'
                                    ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                                    : 'bg-indigo-500/20 text-indigo-400 border border-indigo-500/30'
                                }`}
                              >
                                {exec.status}
                              </span>
                            </div>

                            {/* Stepper info */}
                            <div className="text-xs bg-slate-950 p-3 rounded border border-slate-800">
                              <span className="text-slate-400">
                                Current Step: <strong className="text-white">Step {exec.current_step_index + 1}</strong>
                              </span>
                              {exec.outcome_summary && (
                                <p className="text-slate-300 mt-1">{exec.outcome_summary}</p>
                              )}
                            </div>

                            {exec.status === 'IN_PROGRESS' && (
                              <div className="flex justify-end gap-2 pt-2">
                                <button
                                  onClick={() => handleAdvancePlaybook(exec.execution_id)}
                                  className="px-3 py-1.5 text-xs font-medium bg-indigo-600 hover:bg-indigo-500 text-white rounded-md transition flex items-center gap-1"
                                >
                                  Complete Current Step & Advance
                                  <ArrowRight className="w-3 h-3" />
                                </button>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="bg-slate-900 border border-slate-800 rounded-lg p-8 text-center text-xs text-slate-500">
                        No playbooks currently executed on this case.
                      </div>
                    )}
                  </div>
                )}

                {/* 4. APPROVALS TAB */}
                {activeTab === 'approvals' && (
                  <div className="space-y-4 max-w-4xl">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-sm font-semibold text-white">Separation of Duties & Approval Gates</h3>
                        <p className="text-xs text-slate-400">
                          Pre-execution authorization required for controlled application-level defensive actions.
                        </p>
                      </div>
                      <button
                        onClick={() => setShowApprovalModal(true)}
                        className="px-3 py-1.5 text-xs font-medium bg-amber-600 hover:bg-amber-500 text-white rounded-lg flex items-center gap-1.5 shadow-sm transition"
                      >
                        <UserCheck className="w-3.5 h-3.5" />
                        Request Approval
                      </button>
                    </div>

                    {selectedCase.approvals && selectedCase.approvals.length > 0 ? (
                      <div className="space-y-3">
                        {selectedCase.approvals.map((appr) => (
                          <div
                            key={appr.id}
                            className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-2"
                          >
                            <div className="flex items-center justify-between">
                              <span className="font-mono text-xs font-bold text-slate-200">
                                {appr.action_type}
                              </span>
                              <span
                                className={`px-2 py-0.5 text-xs font-semibold rounded ${
                                  appr.status === 'APPROVED'
                                    ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                                    : appr.status === 'REJECTED'
                                    ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                                    : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                                }`}
                              >
                                {appr.status}
                              </span>
                            </div>

                            <p className="text-xs text-slate-300">
                              <strong className="text-slate-400">Justification: </strong>
                              {appr.justification}
                            </p>

                            <div className="text-[11px] text-slate-500 flex items-center gap-4 pt-1">
                              <span>Requested by: <strong className="text-slate-400">{appr.requested_by}</strong></span>
                              {appr.approved_by && (
                                <span>Decided by: <strong className="text-slate-400">{appr.approved_by}</strong></span>
                              )}
                            </div>

                            {appr.status === 'PENDING' && (
                              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                                <button
                                  onClick={() => handleApprovalDecision(appr.approval_id, 'REJECT')}
                                  className="px-3 py-1.5 text-xs font-medium text-rose-300 hover:bg-rose-950/40 border border-rose-800/60 rounded-md transition"
                                >
                                  Reject Request
                                </button>
                                <button
                                  onClick={() => handleApprovalDecision(appr.approval_id, 'APPROVE')}
                                  className="px-3 py-1.5 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-md transition shadow-sm"
                                >
                                  Authorize Execution
                                </button>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="bg-slate-900 border border-slate-800 rounded-lg p-8 text-center text-xs text-slate-500">
                        No approval requests logged for this case.
                      </div>
                    )}
                  </div>
                )}

                {/* 5. DEFENSIVE ACTIONS TAB */}
                {activeTab === 'actions' && (
                  <div className="space-y-4 max-w-4xl">
                    <div className="bg-slate-900/40 border border-slate-800 rounded-lg p-4 flex items-center gap-3">
                      <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />
                      <div className="text-xs text-slate-400">
                        <strong className="text-slate-200">Safe Defensive Boundaries Enforced: </strong>
                        Actions are strictly scoped to internal honeypot telemetry, session isolation, and canary rotation. Offensive exploits, firewall alterations, and shell execution are disallowed by policy.
                      </div>
                    </div>

                    {selectedCase.actions && selectedCase.actions.length > 0 ? (
                      <div className="space-y-3">
                        {selectedCase.actions.map((act) => (
                          <div
                            key={act.id}
                            className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-2 text-xs"
                          >
                            <div className="flex items-center justify-between">
                              <span className="font-mono font-bold text-slate-200">{act.action_type}</span>
                              <span className="px-2 py-0.5 text-[10px] font-semibold bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 rounded">
                                {act.execution_status}
                              </span>
                            </div>
                            <div className="text-slate-400">
                              Executed by: <strong className="text-slate-300">{act.executed_by}</strong> on {formatDateTime(act.executed_at)}
                            </div>
                            <pre className="p-2 bg-slate-950 rounded border border-slate-800 text-[11px] text-slate-300 overflow-x-auto">
                              {JSON.stringify(act.result_details, null, 2)}
                            </pre>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="bg-slate-900 border border-slate-800 rounded-lg p-8 text-center text-xs text-slate-500">
                        No defensive actions executed for this case yet.
                      </div>
                    )}
                  </div>
                )}

                {/* 6. EVIDENCE HOLDS TAB */}
                {activeTab === 'holds' && (
                  <div className="space-y-4 max-w-4xl">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-sm font-semibold text-white">Evidence Preservation & Chain of Custody</h3>
                        <p className="text-xs text-slate-400">
                          Cryptographic retention holds preventing automated deletion during legal or incident review.
                        </p>
                      </div>
                      <button
                        onClick={() => setShowHoldModal(true)}
                        className="px-3 py-1.5 text-xs font-medium bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg flex items-center gap-1.5 shadow-sm transition"
                      >
                        <FolderLock className="w-3.5 h-3.5" />
                        Apply Preservation Hold
                      </button>
                    </div>

                    {selectedCase.preservation_holds && selectedCase.preservation_holds.length > 0 ? (
                      <div className="space-y-3">
                        {selectedCase.preservation_holds.map((hold) => (
                          <div
                            key={hold.id}
                            className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-2 text-xs"
                          >
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <span className="font-mono px-2 py-0.5 bg-slate-800 text-slate-300 rounded border border-slate-700">
                                  {hold.evidence_type}
                                </span>
                                <span className="font-mono font-semibold text-white">{hold.evidence_identifier}</span>
                              </div>
                              <span
                                className={`px-2 py-0.5 text-[10px] font-semibold rounded ${
                                  hold.retention_hold_status === 'ACTIVE'
                                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                                    : 'bg-slate-800 text-slate-400'
                                }`}
                              >
                                {hold.retention_hold_status}
                              </span>
                            </div>

                            <p className="text-slate-300">{hold.hold_reason}</p>

                            {hold.integrity_hash_sha256 && (
                              <div className="flex items-center gap-2 bg-slate-950 p-2 rounded border border-slate-800/80">
                                <Hash className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                                <span className="font-mono text-[10px] text-emerald-400 truncate">
                                  SHA-256: {hold.integrity_hash_sha256}
                                </span>
                              </div>
                            )}

                            <div className="flex items-center justify-between pt-1 text-[11px] text-slate-500">
                              <span>Applied by: {hold.applied_by} on {formatDateTime(hold.applied_at)}</span>
                              {hold.retention_hold_status === 'ACTIVE' && (
                                <button
                                  onClick={() => handleReleaseHold(hold.hold_id)}
                                  className="px-2.5 py-1 text-xs text-rose-300 hover:bg-rose-950/40 border border-rose-800/60 rounded transition"
                                >
                                  Release Hold
                                </button>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="bg-slate-900 border border-slate-800 rounded-lg p-8 text-center text-xs text-slate-500">
                        No active preservation holds on this case.
                      </div>
                    )}
                  </div>
                )}

                {/* 7. NOTES & TIMELINE TAB */}
                {activeTab === 'notes' && (
                  <div className="space-y-6 max-w-4xl">
                    {/* Note Composer */}
                    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
                      <h4 className="text-xs font-semibold text-white mb-2">Add Analyst Observation</h4>
                      <form onSubmit={handleAddNote} className="space-y-3">
                        <div className="flex items-center gap-3">
                          <select
                            value={newNoteType}
                            onChange={(e) => setNewNoteType(e.target.value)}
                            className="text-xs bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-200 focus:outline-none"
                          >
                            <option value="ANALYST_NOTE">Analyst Note</option>
                            <option value="FINDING">Key Finding</option>
                            <option value="ACTION_LOG">Action Summary</option>
                            <option value="EXTERNAL_LIAISON">External Liaison</option>
                          </select>
                        </div>
                        <textarea
                          rows={3}
                          placeholder="Record investigation findings, attribution insights, or defensive recommendations..."
                          value={newNoteContent}
                          onChange={(e) => setNewNoteContent(e.target.value)}
                          className="w-full text-xs bg-slate-950 border border-slate-800 rounded-md p-3 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                        />
                        <div className="flex justify-end">
                          <button
                            type="submit"
                            disabled={submittingNote || !newNoteContent.trim()}
                            className="px-3.5 py-1.5 text-xs font-medium bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded-md flex items-center gap-1.5 transition"
                          >
                            <Send className="w-3.5 h-3.5" />
                            Post Note
                          </button>
                        </div>
                      </form>
                    </div>

                    {/* Notes List */}
                    {selectedCase.notes && selectedCase.notes.length > 0 ? (
                      <div className="space-y-3">
                        {selectedCase.notes.map((note) => (
                          <div
                            key={note.id}
                            className="bg-slate-900/60 border border-slate-800 rounded-lg p-4 space-y-1.5"
                          >
                            <div className="flex items-center justify-between text-xs">
                              <div className="flex items-center gap-2">
                                <span className="font-semibold text-slate-200">{note.author_username}</span>
                                <span className="px-1.5 py-0.2 bg-slate-800 text-[10px] text-slate-400 rounded">
                                  {note.note_type}
                                </span>
                              </div>
                              <span className="text-[11px] text-slate-500">
                                {formatDateTime(note.created_at)}
                              </span>
                            </div>
                            <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap">
                              {note.content}
                            </p>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-xs text-slate-500 py-4 text-center">No notes recorded yet.</div>
                    )}
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center p-8 text-center text-slate-500">
              <ShieldAlert className="w-12 h-12 text-slate-700 mb-3" />
              <h3 className="text-base font-semibold text-slate-300">No Response Case Selected</h3>
              <p className="text-xs text-slate-500 max-w-sm mt-1">
                Select an existing case from the left panel or create a new case to initiate defensive handling.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* MODAL: New Response Case */}
      {showNewCaseModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 w-full max-w-lg shadow-xl">
            <h3 className="text-base font-bold text-white mb-4">Create New Response Case</h3>
            <form onSubmit={handleCreateCase} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Case Title *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Credential Stuffing Campaign on Sensor-01"
                  value={newCaseForm.title}
                  onChange={(e) => setNewCaseForm({ ...newCaseForm, title: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-indigo-500"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Description *</label>
                <textarea
                  required
                  rows={3}
                  placeholder="Summarize the threat trigger, affected assets, and recommended containment steps..."
                  value={newCaseForm.description}
                  onChange={(e) => setNewCaseForm({ ...newCaseForm, description: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-indigo-500"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Priority</label>
                  <select
                    value={newCaseForm.priority}
                    onChange={(e) => setNewCaseForm({ ...newCaseForm, priority: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none"
                  >
                    <option value="P1_CRITICAL">P1 Critical</option>
                    <option value="P2_HIGH">P2 High</option>
                    <option value="P3_MEDIUM">P3 Medium</option>
                    <option value="P4_LOW">P4 Low</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Severity</label>
                  <select
                    value={newCaseForm.severity}
                    onChange={(e) => setNewCaseForm({ ...newCaseForm, severity: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Primary Alert ID (Optional)</label>
                  <input
                    type="text"
                    placeholder="e.g. ALT-20261031-..."
                    value={newCaseForm.primary_alert_id}
                    onChange={(e) => setNewCaseForm({ ...newCaseForm, primary_alert_id: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Cluster ID (Optional)</label>
                  <input
                    type="text"
                    placeholder="e.g. CLUSTER-..."
                    value={newCaseForm.primary_cluster_id}
                    onChange={(e) => setNewCaseForm({ ...newCaseForm, primary_cluster_id: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none"
                  />
                </div>
              </div>
              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowNewCaseModal(false)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded font-medium"
                >
                  Create Case
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL: Status Transition */}
      {showStatusModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 w-full max-w-md shadow-xl">
            <h3 className="text-base font-bold text-white mb-4">Transition Case Lifecycle Status</h3>
            <form onSubmit={handleStatusTransition} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Target Status</label>
                <select
                  value={statusForm.new_status}
                  onChange={(e) => setStatusForm({ ...statusForm, new_status: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none"
                >
                  <option value="UNDER_REVIEW">UNDER_REVIEW</option>
                  <option value="INVESTIGATING">INVESTIGATING</option>
                  <option value="RESPONSE_RECOMMENDED">RESPONSE_RECOMMENDED</option>
                  <option value="AWAITING_APPROVAL">AWAITING_APPROVAL</option>
                  <option value="APPROVED">APPROVED</option>
                  <option value="ACTION_IN_PROGRESS">ACTION_IN_PROGRESS</option>
                  <option value="MONITORING">MONITORING</option>
                  <option value="RESOLVED">RESOLVED</option>
                  <option value="CLOSED">CLOSED</option>
                  <option value="REOPENED">REOPENED</option>
                </select>
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Reason / Justification *</label>
                <textarea
                  required
                  rows={2}
                  placeholder="Explain reason for state transition..."
                  value={statusForm.reason}
                  onChange={(e) => setStatusForm({ ...statusForm, reason: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none"
                />
              </div>
              {statusForm.new_status === 'RESOLVED' && (
                <div>
                  <label className="block text-slate-400 mb-1">Resolution Category</label>
                  <select
                    value={statusForm.resolution_category}
                    onChange={(e) => setStatusForm({ ...statusForm, resolution_category: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none"
                  >
                    <option value="TRUE_POSITIVE_MITIGATED">True Positive Mitigated</option>
                    <option value="FALSE_POSITIVE">False Positive</option>
                    <option value="BENIGN_ACTIVITY">Benign Scanner / Activity</option>
                    <option value="POLICY_EXCEPTION">Policy Exception</option>
                  </select>
                </div>
              )}
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
                  className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded font-medium"
                >
                  Update Status
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL: Link Entity */}
      {showLinkModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 w-full max-w-md shadow-xl">
            <h3 className="text-base font-bold text-white mb-4">Link Security Entity to Case</h3>
            <form onSubmit={handleLinkEntity} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Entity Type</label>
                <select
                  value={linkForm.related_entity_type}
                  onChange={(e) => setLinkForm({ ...linkForm, related_entity_type: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none"
                >
                  <option value="ALERT">Alert</option>
                  <option value="EVENT">Security Event</option>
                  <option value="SESSION">Honeypot Session</option>
                  <option value="SOURCE_PROFILE">Source Profile</option>
                  <option value="CAMPAIGN_CLUSTER">Campaign Cluster</option>
                </select>
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Entity Identifier *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. ALT-..., EVT-..., or UUID"
                  value={linkForm.related_entity_id}
                  onChange={(e) => setLinkForm({ ...linkForm, related_entity_id: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Relationship Reason</label>
                <input
                  type="text"
                  placeholder="e.g. Correlated IP address exhibiting identical attack chain"
                  value={linkForm.relationship_reason}
                  onChange={(e) => setLinkForm({ ...linkForm, relationship_reason: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none"
                />
              </div>
              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowLinkModal(false)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded font-medium"
                >
                  Link Entity
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL: Request Approval */}
      {showApprovalModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 w-full max-w-md shadow-xl">
            <h3 className="text-base font-bold text-white mb-4">Request Action Authorization</h3>
            <form onSubmit={handleRequestApproval} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Defensive Action Type</label>
                <select
                  value={approvalForm.action_type}
                  onChange={(e) => setApprovalForm({ ...approvalForm, action_type: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none"
                >
                  <option value="HONEYPOT_SENSITIVITY_BOOST">Boost Honeypot Sensitivity</option>
                  <option value="CREDENTIAL_CANARY_ROTATION">Rotate Credential Canaries</option>
                  <option value="SESSION_ISOLATION">Isolate Honeypot Session</option>
                  <option value="TELEMETRY_SAMPLE_RATE_MAX">Maximize Telemetry Sampling</option>
                </select>
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Justification *</label>
                <textarea
                  required
                  rows={3}
                  placeholder="Provide operational justification why this action is necessary..."
                  value={approvalForm.justification}
                  onChange={(e) => setApprovalForm({ ...approvalForm, justification: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none"
                />
              </div>
              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowApprovalModal(false)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-amber-600 hover:bg-amber-500 text-white rounded font-medium"
                >
                  Submit for Approval
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL: Apply Preservation Hold */}
      {showHoldModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 w-full max-w-md shadow-xl">
            <h3 className="text-base font-bold text-white mb-4">Apply Evidence Retention Hold</h3>
            <form onSubmit={handleCreateHold} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Evidence Type</label>
                <select
                  value={holdForm.evidence_type}
                  onChange={(e) => setHoldForm({ ...holdForm, evidence_type: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none"
                >
                  <option value="ALERT">Alert</option>
                  <option value="EVENT">Security Event</option>
                  <option value="SESSION">Honeypot Session</option>
                  <option value="PAYLOAD">Payload Capture</option>
                  <option value="TRACE">Correlation Trace</option>
                </select>
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Evidence Identifier *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. ALT-..., EVT-..., or Session ID"
                  value={holdForm.evidence_identifier}
                  onChange={(e) => setHoldForm({ ...holdForm, evidence_identifier: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Hold Justification *</label>
                <textarea
                  required
                  rows={2}
                  placeholder="Reason this evidence must be exempted from lifecycle pruning..."
                  value={holdForm.hold_reason}
                  onChange={(e) => setHoldForm({ ...holdForm, hold_reason: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none"
                />
              </div>
              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowHoldModal(false)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded font-medium"
                >
                  Lock Evidence
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL: Execute Playbook */}
      {showPlaybookModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 w-full max-w-lg shadow-xl">
            <h3 className="text-base font-bold text-white mb-4">Execute Defensive Playbook</h3>
            <form onSubmit={handleStartPlaybook} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Select Playbook Definition</label>
                <select
                  value={selectedPlaybookId}
                  onChange={(e) => setSelectedPlaybookId(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none"
                  required
                >
                  <option value="">-- Choose a standard procedure --</option>
                  {playbookCatalog.map((pb) => (
                    <option key={pb.playbook_id} value={pb.playbook_id}>
                      {pb.playbook_id} — {pb.title}
                    </option>
                  ))}
                </select>
              </div>

              {selectedPlaybookId && (
                <div className="bg-slate-950 p-3 rounded border border-slate-800 text-slate-300 space-y-2">
                  {(() => {
                    const pb = playbookCatalog.find((p) => p.playbook_id === selectedPlaybookId);
                    if (!pb) return null;
                    return (
                      <>
                        <p className="text-xs text-slate-300">{pb.description}</p>
                        <div className="text-[11px] text-slate-400 font-semibold mt-2">
                          Steps in Workflow ({pb.workflow_steps.length}):
                        </div>
                        <ul className="list-decimal list-inside space-y-1 text-[11px] text-slate-400">
                          {pb.workflow_steps.map((s, idx) => (
                            <li key={idx}>
                              <strong className="text-slate-200">{s.step_name}:</strong> {s.instruction}
                            </li>
                          ))}
                        </ul>
                      </>
                    );
                  })()}
                </div>
              )}

              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowPlaybookModal(false)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={!selectedPlaybookId}
                  className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded font-medium"
                >
                  Start Execution
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default DefensiveResponseCenterPage;

