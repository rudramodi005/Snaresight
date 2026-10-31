import React, { useEffect, useState } from 'react';
import {
  InvestigationCluster,
  ClusterSummary,
  ClusterDetail,
  ClusterTimelineResponse,
} from '../../types/campaign';
import {
  listInvestigations,
  getInvestigationSummary,
  getInvestigationClusterDetail,
  getClusterTimeline,
  addAnalystNote,
  transitionClusterLifecycle,
  submitMemberDecision,
  mergeClusters,
  splitCluster,
  closeInvestigation,
  triggerClustering,
} from '../../services/campaignApi';
import { CampaignRelationshipGraph } from '../../components/CampaignRelationshipGraph';

export const CampaignInvestigationsPage: React.FC = () => {
  const [clusters, setClusters] = useState<InvestigationCluster[]>([]);
  const [summary, setSummary] = useState<ClusterSummary | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters & Pagination
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [priorityFilter, setPriorityFilter] = useState<string>('');
  const [page, setPage] = useState<number>(1);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [isClustering, setIsClustering] = useState<boolean>(false);

  // Detail Drawer State
  const [selectedClusterId, setSelectedClusterId] = useState<string | null>(null);
  const [clusterDetail, setClusterDetail] = useState<ClusterDetail | null>(null);
  const [timelineData, setTimelineData] = useState<ClusterTimelineResponse | null>(null);
  const [detailTab, setDetailTab] = useState<'overview' | 'members' | 'timeline' | 'attack' | 'topology' | 'analyst'>('overview');
  const [detailLoading, setDetailLoading] = useState<boolean>(false);

  // Analyst Forms State
  const [analystId, setAnalystId] = useState<string>('SOC-LEAD');
  const [newNote, setNewNote] = useState<string>('');
  const [submittingNote, setSubmittingNote] = useState<boolean>(false);
  const [targetStatus, setTargetStatus] = useState<string>('UNDER_REVIEW');
  const [transitionReason, setTransitionReason] = useState<string>('');
  const [submittingTransition, setSubmittingTransition] = useState<boolean>(false);

  // Merge Dialog State
  const [showMergeModal, setShowMergeModal] = useState<boolean>(false);
  const [sourceMergeId, setSourceMergeId] = useState<string>('');
  const [mergeReason, setMergeReason] = useState<string>('');
  const [submittingMerge, setSubmittingMerge] = useState<boolean>(false);

  // Split Dialog State
  const [showSplitModal, setShowSplitModal] = useState<boolean>(false);
  const [splitMemberIds, setSplitMemberIds] = useState<string[]>([]);
  const [splitTitle, setSplitTitle] = useState<string>('');
  const [splitDesc, setSplitDesc] = useState<string>('');
  const [splitReason, setSplitReason] = useState<string>('');
  const [submittingSplit, setSubmittingSplit] = useState<boolean>(false);

  // Close Dialog State
  const [showCloseModal, setShowCloseModal] = useState<boolean>(false);
  const [closeReason, setCloseReason] = useState<string>('');
  const [closeResolution, setCloseResolution] = useState<'RESOLVED' | 'FALSE_POSITIVE' | 'BENIGN_ACTIVITY'>('RESOLVED');
  const [submittingClose, setSubmittingClose] = useState<boolean>(false);

  useEffect(() => {
    loadData();
    loadSummary();
  }, [page, statusFilter, priorityFilter, searchTerm]);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await listInvestigations({
        page,
        page_size: 15,
        search: searchTerm || undefined,
        status: statusFilter || undefined,
        priority: priorityFilter || undefined,
      });
      setClusters(res.items);
      setTotalCount(res.total);
    } catch (err: any) {
      setError(err.message || 'Failed to load investigation clusters');
    } finally {
      setLoading(false);
    }
  };

  const loadSummary = async () => {
    try {
      const sum = await getInvestigationSummary();
      setSummary(sum);
    } catch (err: any) {
      console.error('Failed to load summary:', err);
    }
  };

  const handleSelectCluster = async (clusterId: string) => {
    setSelectedClusterId(clusterId);
    setDetailLoading(true);
    try {
      const [detail, tl] = await Promise.all([
        getInvestigationClusterDetail(clusterId),
        getClusterTimeline(clusterId, 100, 0, true),
      ]);
      setClusterDetail(detail);
      setTimelineData(tl);
    } catch (err: any) {
      console.error('Failed to load cluster details:', err);
    } finally {
      setDetailLoading(false);
    }
  };

  const handleTriggerClustering = async () => {
    try {
      setIsClustering(true);
      await triggerClustering({ force_all: true });
      await loadData();
      await loadSummary();
      if (selectedClusterId) {
        await handleSelectCluster(selectedClusterId);
      }
    } catch (err: any) {
      alert(`Clustering failed: ${err.message}`);
    } finally {
      setIsClustering(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedClusterId || !newNote.trim()) return;
    try {
      setSubmittingNote(true);
      await addAnalystNote(selectedClusterId, { analyst_id: analystId, notes: newNote.trim() });
      setNewNote('');
      const updatedDetail = await getInvestigationClusterDetail(selectedClusterId);
      setClusterDetail(updatedDetail);
    } catch (err: any) {
      alert(`Failed to add note: ${err.message}`);
    } finally {
      setSubmittingNote(false);
    }
  };

  const handleTransitionLifecycle = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedClusterId || !transitionReason.trim()) return;
    try {
      setSubmittingTransition(true);
      await transitionClusterLifecycle(selectedClusterId, {
        analyst_id: analystId,
        target_status: targetStatus as any,
        reason: transitionReason.trim(),
      });
      setTransitionReason('');
      const updatedDetail = await getInvestigationClusterDetail(selectedClusterId);
      setClusterDetail(updatedDetail);
      loadData();
      loadSummary();
    } catch (err: any) {
      alert(`Lifecycle transition failed: ${err.message}`);
    } finally {
      setSubmittingTransition(false);
    }
  };

  const handleMemberDecision = async (memberId: string, decision: 'ACCEPT' | 'REJECT') => {
    if (!selectedClusterId) return;
    try {
      await submitMemberDecision(selectedClusterId, memberId, {
        analyst_id: analystId,
        decision,
        reason: `Analyst decision: ${decision}`,
      });
      const updatedDetail = await getInvestigationClusterDetail(selectedClusterId);
      setClusterDetail(updatedDetail);
    } catch (err: any) {
      alert(`Member decision failed: ${err.message}`);
    }
  };

  const handleMergeSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedClusterId || !sourceMergeId.trim() || !mergeReason.trim()) return;
    try {
      setSubmittingMerge(true);
      await mergeClusters(selectedClusterId, {
        analyst_id: analystId,
        source_cluster_id: sourceMergeId.trim(),
        reason: mergeReason.trim(),
      });
      setShowMergeModal(false);
      setSourceMergeId('');
      setMergeReason('');
      await handleSelectCluster(selectedClusterId);
      loadData();
      loadSummary();
      alert('Clusters successfully merged.');
    } catch (err: any) {
      alert(`Merge failed: ${err.message}`);
    } finally {
      setSubmittingMerge(false);
    }
  };

  const handleSplitSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedClusterId || splitMemberIds.length === 0 || !splitTitle.trim() || !splitReason.trim()) return;
    try {
      setSubmittingSplit(true);
      const newCluster = await splitCluster(selectedClusterId, {
        analyst_id: analystId,
        member_ids: splitMemberIds,
        new_cluster_title: splitTitle.trim(),
        new_cluster_description: splitDesc.trim(),
        reason: splitReason.trim(),
      });
      setShowSplitModal(false);
      setSplitMemberIds([]);
      setSplitTitle('');
      setSplitDesc('');
      setSplitReason('');
      await handleSelectCluster(selectedClusterId);
      loadData();
      loadSummary();
      alert(`Cluster partitioned into new investigation '${newCluster.cluster_id}'.`);
    } catch (err: any) {
      alert(`Split failed: ${err.message}`);
    } finally {
      setSubmittingSplit(false);
    }
  };

  const handleCloseSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedClusterId || !closeReason.trim()) return;
    try {
      setSubmittingClose(true);
      await closeInvestigation(selectedClusterId, {
        analyst_id: analystId,
        closure_reason: closeReason.trim(),
        resolution_status: closeResolution,
      });
      setShowCloseModal(false);
      setCloseReason('');
      await handleSelectCluster(selectedClusterId);
      loadData();
      loadSummary();
      alert('Investigation cluster closed.');
    } catch (err: any) {
      alert(`Closure failed: ${err.message}`);
    } finally {
      setSubmittingClose(false);
    }
  };

  const getPriorityBadgeClass = (priority: string) => {
    switch (priority) {
      case 'CRITICAL':
        return 'bg-red-950 text-red-400 border border-red-800';
      case 'HIGH':
        return 'bg-orange-950 text-orange-400 border border-orange-800';
      case 'MEDIUM':
        return 'bg-yellow-950 text-yellow-400 border border-yellow-800';
      case 'LOW':
        return 'bg-blue-950 text-blue-400 border border-blue-800';
      default:
        return 'bg-gray-800 text-gray-400 border border-gray-700';
    }
  };

  const getLifecycleBadgeClass = (status: string) => {
    switch (status) {
      case 'ACTIVE':
        return 'bg-emerald-950 text-emerald-400 border border-emerald-800';
      case 'UNDER_REVIEW':
        return 'bg-cyan-950 text-cyan-400 border border-cyan-800';
      case 'CANDIDATE':
        return 'bg-indigo-950 text-indigo-400 border border-indigo-800';
      case 'MONITORING':
        return 'bg-purple-950 text-purple-400 border border-purple-800';
      case 'MERGED':
        return 'bg-slate-800 text-slate-400 border border-slate-700 line-through';
      case 'SPLIT':
        return 'bg-slate-800 text-slate-400 border border-slate-700';
      case 'CLOSED':
        return 'bg-slate-900 text-slate-500 border border-slate-800';
      default:
        return 'bg-gray-800 text-gray-400 border border-gray-700';
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight text-white">Campaign Investigations</h1>
            <span className="px-2.5 py-0.5 text-xs font-medium rounded-full bg-indigo-950 text-indigo-400 border border-indigo-800">
              Phase 5: Task P24
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Evidence-based investigation grouping, cross-sensor campaign clustering, and non-destructive triage.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleTriggerClustering}
            disabled={isClustering}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-900 text-white text-sm font-medium rounded-lg shadow transition"
          >
            {isClustering ? (
              <>
                <svg className="animate-spin h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                </svg>
                Clustering Observations...
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
                </svg>
                Run Investigation Clustering
              </>
            )}
          </button>
        </div>
      </div>

      {/* Attribution Policy Guardrail Disclaimer */}
      <div className="my-4 p-3 bg-slate-900/80 border border-slate-800 rounded-lg flex items-center justify-between text-xs text-slate-400">
        <div className="flex items-center gap-2">
          <svg className="w-4 h-4 text-indigo-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <span>
            <strong className="text-slate-300">Investigative Guardrail:</strong> An investigation cluster represents an <em>evidence-based activity grouping</em>. It organizes correlated honeypot telemetry and does NOT constitute proof of a real-world attacker, nation-state group, or singular human operator.
          </span>
        </div>
        <span className="font-mono text-slate-500">Evidence Preserved Non-Destructively</span>
      </div>

      {/* Overview Statistics Cards */}
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3 mb-6">
          <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
            <span className="text-[11px] text-slate-400 uppercase font-semibold">Total Clusters</span>
            <div className="text-xl font-bold text-slate-100 mt-1">{summary.total_clusters}</div>
          </div>
          <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
            <span className="text-[11px] text-slate-400 uppercase font-semibold">Active Investigations</span>
            <div className="text-xl font-bold text-emerald-400 mt-1">{summary.active_investigations}</div>
          </div>
          <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
            <span className="text-[11px] text-slate-400 uppercase font-semibold">Under Review</span>
            <div className="text-xl font-bold text-cyan-400 mt-1">{summary.under_review_count}</div>
          </div>
          <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
            <span className="text-[11px] text-slate-400 uppercase font-semibold">Candidate Groups</span>
            <div className="text-xl font-bold text-indigo-400 mt-1">{summary.candidate_clusters}</div>
          </div>
          <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
            <span className="text-[11px] text-slate-400 uppercase font-semibold">Critical Priority</span>
            <div className="text-xl font-bold text-red-400 mt-1">{summary.critical_priority_count}</div>
          </div>
          <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
            <span className="text-[11px] text-slate-400 uppercase font-semibold">High Priority</span>
            <div className="text-xl font-bold text-orange-400 mt-1">{summary.high_priority_count}</div>
          </div>
        </div>
      )}

      {/* Search and Filters */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="md:col-span-2">
          <input
            type="text"
            placeholder="Search by Cluster ID, Title, or Pattern..."
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value);
              setPage(1);
            }}
            className="w-full bg-slate-900 border border-slate-750 text-slate-200 text-sm rounded-lg px-3.5 py-2.5 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          />
        </div>

        <div>
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setPage(1);
            }}
            className="w-full bg-slate-900 border border-slate-750 text-slate-200 text-sm rounded-lg px-3 py-2.5 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          >
            <option value="">All Lifecycle Statuses</option>
            <option value="CANDIDATE">CANDIDATE</option>
            <option value="UNDER_REVIEW">UNDER_REVIEW</option>
            <option value="ACTIVE">ACTIVE</option>
            <option value="MONITORING">MONITORING</option>
            <option value="CLOSED">CLOSED</option>
            <option value="MERGED">MERGED</option>
            <option value="SPLIT">SPLIT</option>
          </select>
        </div>

        <div>
          <select
            value={priorityFilter}
            onChange={(e) => {
              setPriorityFilter(e.target.value);
              setPage(1);
            }}
            className="w-full bg-slate-900 border border-slate-750 text-slate-200 text-sm rounded-lg px-3 py-2.5 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          >
            <option value="">All Priorities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>
        </div>
      </div>

      {/* Main Workspace Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Side: Clusters Table */}
        <div className={`${selectedClusterId ? 'lg:col-span-6' : 'lg:col-span-12'} transition-all duration-300`}>
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow">
            <div className="p-4 border-b border-slate-800 flex justify-between items-center">
              <span className="text-sm font-semibold text-slate-300">
                Investigation Clusters ({totalCount})
              </span>
              {loading && <span className="text-xs text-indigo-400 animate-pulse">Loading clusters...</span>}
            </div>

            {error ? (
              <div className="p-6 text-center text-red-400 text-sm">{error}</div>
            ) : clusters.length === 0 && !loading ? (
              <div className="p-8 text-center text-slate-500 text-sm">
                No investigation clusters found matching criteria. Click "Run Investigation Clustering" to analyze telemetry.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm text-slate-300">
                  <thead className="bg-slate-950/60 text-xs uppercase tracking-wider text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="py-3 px-4">Status</th>
                      <th className="py-3 px-4">Investigation Group</th>
                      <th className="py-3 px-4">Priority</th>
                      <th className="py-3 px-4">Members</th>
                      <th className="py-3 px-4">Last Activity</th>
                      <th className="py-3 px-4 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {clusters.map((c) => {
                      const isSelected = selectedClusterId === c.cluster_id;
                      return (
                        <tr
                          key={c.cluster_id}
                          onClick={() => handleSelectCluster(c.cluster_id)}
                          className={`cursor-pointer transition hover:bg-slate-800/50 ${
                            isSelected ? 'bg-indigo-950/40 border-l-4 border-indigo-500' : ''
                          }`}
                        >
                          <td className="py-3 px-4">
                            <span className={`px-2 py-0.5 text-xs font-semibold rounded ${getLifecycleBadgeClass(c.lifecycle_status)}`}>
                              {c.lifecycle_status}
                            </span>
                          </td>
                          <td className="py-3 px-4">
                            <div className="font-semibold text-slate-100">{c.title}</div>
                            <div className="text-[11px] font-mono text-slate-400">{c.cluster_id}</div>
                          </td>
                          <td className="py-3 px-4">
                            <span className={`px-2 py-0.5 text-xs font-semibold rounded ${getPriorityBadgeClass(c.priority)}`}>
                              {c.priority}
                            </span>
                          </td>
                          <td className="py-3 px-4 text-xs text-slate-400">
                            <div>{c.session_count} session(s) • {c.alert_count} alert(s)</div>
                            <div>{c.source_profile_count} profile(s)</div>
                          </td>
                          <td className="py-3 px-4 text-xs text-slate-400 font-mono">
                            {new Date(c.last_observed_at).toLocaleString()}
                          </td>
                          <td className="py-3 px-4 text-right">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                handleSelectCluster(c.cluster_id);
                              }}
                              className="px-2.5 py-1 text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 rounded border border-slate-700 transition"
                            >
                              Inspect
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        {/* Right Side: Investigation Inspection Drawer */}
        {selectedClusterId && (
          <div className="lg:col-span-6 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow flex flex-col">
            {/* Header */}
            <div className="p-4 bg-slate-950/60 border-b border-slate-800 flex justify-between items-start">
              <div>
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 text-xs font-semibold rounded ${getLifecycleBadgeClass(clusterDetail?.cluster.lifecycle_status || '')}`}>
                    {clusterDetail?.cluster.lifecycle_status}
                  </span>
                  <span className={`px-2 py-0.5 text-xs font-semibold rounded ${getPriorityBadgeClass(clusterDetail?.cluster.priority || '')}`}>
                    {clusterDetail?.cluster.priority}
                  </span>
                  <span className="text-xs font-mono text-slate-400">{clusterDetail?.cluster.cluster_id}</span>
                </div>
                <h2 className="text-lg font-bold text-white mt-1">
                  {clusterDetail?.cluster.title}
                </h2>
                <div className="text-xs text-slate-400 mt-0.5">
                  Methodology Version: {clusterDetail?.cluster.cluster_methodology_version}
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => setShowMergeModal(true)}
                  className="px-2.5 py-1 text-xs bg-indigo-950 hover:bg-indigo-900 text-indigo-300 border border-indigo-800 rounded transition"
                >
                  Merge Into...
                </button>
                <button
                  onClick={() => setShowSplitModal(true)}
                  className="px-2.5 py-1 text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded transition"
                >
                  Split...
                </button>
                <button
                  onClick={() => setShowCloseModal(true)}
                  className="px-2.5 py-1 text-xs bg-red-950 hover:bg-red-900 text-red-300 border border-red-800 rounded transition"
                >
                  Close
                </button>
                <button
                  onClick={() => setSelectedClusterId(null)}
                  className="text-slate-400 hover:text-slate-200 text-sm p-1 rounded hover:bg-slate-800 ml-2"
                >
                  ✕
                </button>
              </div>
            </div>

            {/* Navigation Tabs */}
            <div className="flex border-b border-slate-800 text-xs font-medium bg-slate-950/40">
              {[
                { id: 'overview', label: `Summary & Evidence (${clusterDetail?.evidence.length || 0})` },
                { id: 'members', label: `Members (${clusterDetail?.members.length || 0})` },
                { id: 'timeline', label: `Timeline (${timelineData?.total_items || 0})` },
                { id: 'attack', label: `ATT&CK (${clusterDetail?.attack_techniques.length || 0})` },
                { id: 'topology', label: 'Topology' },
                { id: 'analyst', label: `Actions (${clusterDetail?.audit_logs.length || 0})` },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setDetailTab(tab.id as any)}
                  className={`px-3 py-2.5 transition border-b-2 ${
                    detailTab === tab.id
                      ? 'border-indigo-500 text-indigo-400 bg-slate-900'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Drawer Body Content */}
            <div className="p-4 overflow-y-auto flex-1 max-h-[700px] space-y-4">
              {detailLoading ? (
                <div className="p-8 text-center text-slate-400 text-sm animate-pulse">
                  Loading investigation cluster telemetry...
                </div>
              ) : (
                <>
                  {/* TAB 1: OVERVIEW & EVIDENCE */}
                  {detailTab === 'overview' && clusterDetail && (
                    <div className="space-y-4">
                      {/* Description Card */}
                      <div className="p-3.5 bg-slate-950/80 border border-slate-800 rounded-lg">
                        <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">
                          Investigative Rationale & Description
                        </span>
                        <p className="text-sm text-slate-200 mt-1">
                          {clusterDetail.cluster.description}
                        </p>
                      </div>

                      {/* Supporting Evidence Items */}
                      <div className="space-y-2">
                        <span className="text-xs uppercase tracking-wider font-semibold text-emerald-400 block">
                          Supporting Evidence Items ({clusterDetail.evidence.filter((e) => e.classification === 'SUPPORTING').length})
                        </span>
                        {clusterDetail.evidence
                          .filter((e) => e.classification === 'SUPPORTING')
                          .map((ev) => (
                            <div key={ev.evidence_id} className="p-3 bg-slate-950/60 border border-emerald-900/50 rounded-lg text-xs space-y-1">
                              <div className="flex justify-between items-center">
                                <span className="font-semibold text-emerald-400">{ev.evidence_type}</span>
                                <span className="font-mono text-slate-400">{ev.evidence_reference}</span>
                              </div>
                              <p className="text-slate-300">{ev.evidence_description}</p>
                            </div>
                          ))}
                      </div>

                      {/* Contradicting Evidence Items */}
                      <div className="space-y-2">
                        <span className="text-xs uppercase tracking-wider font-semibold text-red-400 block">
                          Contradicting / Divergent Evidence ({clusterDetail.evidence.filter((e) => e.classification === 'CONTRADICTING').length})
                        </span>
                        {clusterDetail.evidence.filter((e) => e.classification === 'CONTRADICTING').length === 0 ? (
                          <div className="text-xs text-slate-500 p-3 bg-slate-950/40 rounded border border-slate-800">
                            No contradicting evidence signals identified. Observations conform with grouping policy.
                          </div>
                        ) : (
                          clusterDetail.evidence
                            .filter((e) => e.classification === 'CONTRADICTING')
                            .map((ev) => (
                              <div key={ev.evidence_id} className="p-3 bg-slate-950/60 border border-red-900/50 rounded-lg text-xs space-y-1">
                                <div className="flex justify-between items-center">
                                  <span className="font-semibold text-red-400">{ev.evidence_type}</span>
                                  <span className="font-mono text-slate-400">{ev.evidence_reference}</span>
                                </div>
                                <p className="text-slate-300">{ev.evidence_description}</p>
                              </div>
                            ))
                        )}
                      </div>
                    </div>
                  )}

                  {/* TAB 2: MEMBERSHIPS */}
                  {detailTab === 'members' && clusterDetail && (
                    <div className="space-y-3">
                      <span className="text-xs uppercase tracking-wider font-semibold text-slate-400 block">
                        Correlated Members ({clusterDetail.members.length})
                      </span>
                      {clusterDetail.members.map((m) => (
                        <div key={m.id} className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg text-xs space-y-2">
                          <div className="flex justify-between items-center">
                            <div className="flex items-center gap-2">
                              <span className="px-1.5 py-0.5 rounded text-[10px] bg-indigo-950 text-indigo-300 border border-indigo-800 font-semibold">
                                {m.member_type}
                              </span>
                              <span className="font-mono font-semibold text-slate-200">{m.member_id}</span>
                            </div>
                            <span className="text-slate-400">{m.association_confidence}% Confidence</span>
                          </div>

                          <div className="flex justify-between items-center text-[11px] text-slate-400">
                            <span>Status: <strong className="text-slate-300">{m.membership_status}</strong> ({m.analyst_review_status})</span>
                            <div className="flex items-center gap-1.5">
                              {m.membership_status === 'PROPOSED' && (
                                <>
                                  <button
                                    onClick={() => handleMemberDecision(m.member_id, 'ACCEPT')}
                                    className="px-2 py-0.5 bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-800 rounded"
                                  >
                                    Accept
                                  </button>
                                  <button
                                    onClick={() => handleMemberDecision(m.member_id, 'REJECT')}
                                    className="px-2 py-0.5 bg-red-950 hover:bg-red-900 text-red-300 border border-red-800 rounded"
                                  >
                                    Reject
                                  </button>
                                </>
                              )}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* TAB 3: UNIFIED TIMELINE */}
                  {detailTab === 'timeline' && timelineData && (
                    <div className="space-y-3">
                      <span className="text-xs uppercase tracking-wider font-semibold text-slate-400 block">
                        Chronological Investigation Timeline ({timelineData.items.length})
                      </span>
                      {timelineData.items.map((item) => (
                        <div key={item.item_id} className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg text-xs space-y-1">
                          <div className="flex justify-between items-center">
                            <span className="font-semibold text-slate-200">{item.title}</span>
                            <span className="font-mono text-slate-400">{new Date(item.timestamp).toLocaleString()}</span>
                          </div>
                          <p className="text-slate-300">{item.summary}</p>
                          <div className="text-[11px] text-slate-500 font-mono">Ref: {item.reference_id}</div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* TAB 4: MITRE ATT&CK */}
                  {detailTab === 'attack' && clusterDetail && (
                    <div className="space-y-3">
                      <span className="text-xs uppercase tracking-wider font-semibold text-slate-400 block">
                        Evidence-Backed ATT&CK Techniques ({clusterDetail.attack_techniques.length})
                      </span>
                      {clusterDetail.attack_techniques.length === 0 ? (
                        <div className="text-xs text-slate-500 p-3 bg-slate-950/40 rounded border border-slate-800">
                          No MITRE ATT&CK mappings attached to member alerts yet.
                        </div>
                      ) : (
                        clusterDetail.attack_techniques.map((tech) => (
                          <div key={tech.technique_id} className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg text-xs space-y-1">
                            <div className="flex justify-between items-center">
                              <span className="font-semibold text-indigo-400">{tech.technique_id}: {tech.technique_name}</span>
                              <span className="text-slate-400">{tech.tactic}</span>
                            </div>
                            <div className="text-slate-400 text-[11px]">
                              Rules: {tech.supporting_rules.join(', ') || 'N/A'} (Confidence: {tech.mapping_confidence}%)
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  )}

                  {/* TAB 5: TOPOLOGY */}
                  {detailTab === 'topology' && clusterDetail && (
                    <CampaignRelationshipGraph
                      clusterId={clusterDetail.cluster.cluster_id}
                      clusterTitle={clusterDetail.cluster.title}
                      members={clusterDetail.members}
                      relationships={clusterDetail.relationships}
                    />
                  )}

                  {/* TAB 6: ANALYST ACTIONS & AUDIT */}
                  {detailTab === 'analyst' && clusterDetail && (
                    <div className="space-y-6">
                      {/* Record Note */}
                      <form onSubmit={handleAddNote} className="p-3.5 bg-slate-950/80 border border-slate-800 rounded-lg space-y-3">
                        <span className="text-xs uppercase tracking-wider font-semibold text-slate-400 block">
                          Record Investigation Note
                        </span>
                        <textarea
                          rows={3}
                          placeholder="Document hypothesis, cross-sensor telemetry analysis, or triage notes..."
                          value={newNote}
                          onChange={(e) => setNewNote(e.target.value)}
                          className="w-full bg-slate-900 border border-slate-750 text-slate-200 text-xs rounded px-2.5 py-1.5 focus:outline-none"
                        />
                        <button
                          type="submit"
                          disabled={submittingNote || !newNote.trim()}
                          className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-900 text-white text-xs font-medium rounded transition"
                        >
                          {submittingNote ? 'Saving Note...' : 'Add Note'}
                        </button>
                      </form>

                      {/* Transition Lifecycle */}
                      <form onSubmit={handleTransitionLifecycle} className="p-3.5 bg-slate-950/80 border border-slate-800 rounded-lg space-y-3">
                        <span className="text-xs uppercase tracking-wider font-semibold text-slate-400 block">
                          Update Lifecycle State
                        </span>
                        <div className="grid grid-cols-2 gap-3">
                          <div>
                            <label className="text-[11px] text-slate-400 block mb-1">Target Status</label>
                            <select
                              value={targetStatus}
                              onChange={(e) => setTargetStatus(e.target.value)}
                              className="w-full bg-slate-900 border border-slate-750 text-slate-200 text-xs rounded px-2 py-1.5"
                            >
                              <option value="UNDER_REVIEW">UNDER_REVIEW</option>
                              <option value="ACTIVE">ACTIVE</option>
                              <option value="MONITORING">MONITORING</option>
                              <option value="CLOSED">CLOSED</option>
                            </select>
                          </div>
                          <div>
                            <label className="text-[11px] text-slate-400 block mb-1">Reason</label>
                            <input
                              type="text"
                              placeholder="Transition rationale..."
                              value={transitionReason}
                              onChange={(e) => setTransitionReason(e.target.value)}
                              className="w-full bg-slate-900 border border-slate-750 text-slate-200 text-xs rounded px-2 py-1.5"
                            />
                          </div>
                        </div>
                        <button
                          type="submit"
                          disabled={submittingTransition || !transitionReason.trim()}
                          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded border border-slate-700 transition"
                        >
                          {submittingTransition ? 'Updating...' : 'Change Status'}
                        </button>
                      </form>

                      {/* Audit History */}
                      <div className="space-y-2">
                        <span className="text-xs uppercase tracking-wider font-semibold text-slate-400 block">
                          Audit Trail ({clusterDetail.audit_logs.length})
                        </span>
                        {clusterDetail.audit_logs.map((log) => (
                          <div key={log.id} className="p-2.5 bg-slate-950/40 border border-slate-800 rounded text-xs space-y-1">
                            <div className="flex justify-between items-center font-mono text-[11px] text-slate-400">
                              <span>{log.action} by {log.actor}</span>
                              <span>{new Date(log.timestamp).toLocaleString()}</span>
                            </div>
                            {log.reason && <div className="text-slate-300 italic">"{log.reason}"</div>}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        )}
      </div>

      {/* MERGE MODAL */}
      {showMergeModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center p-4 z-50">
          <form onSubmit={handleMergeSubmit} className="bg-slate-900 border border-slate-800 rounded-xl p-5 max-w-md w-full space-y-4">
            <h3 className="text-base font-bold text-white">Merge Clusters</h3>
            <p className="text-xs text-slate-400">
              Consolidate another cluster into this destination cluster. All members, evidence, and audit histories are preserved.
            </p>
            <div>
              <label className="text-xs text-slate-400 block mb-1">Source Cluster ID to Merge In</label>
              <input
                type="text"
                placeholder="CAMP-..."
                value={sourceMergeId}
                onChange={(e) => setSourceMergeId(e.target.value)}
                className="w-full bg-slate-950 border border-slate-750 text-slate-200 text-xs rounded p-2 focus:outline-none"
              />
            </div>
            <div>
              <label className="text-xs text-slate-400 block mb-1">Merge Reason / Rationale</label>
              <input
                type="text"
                placeholder="Confirmed identical behavioral progression..."
                value={mergeReason}
                onChange={(e) => setMergeReason(e.target.value)}
                className="w-full bg-slate-950 border border-slate-750 text-slate-200 text-xs rounded p-2 focus:outline-none"
              />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowMergeModal(false)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submittingMerge || !sourceMergeId.trim() || !mergeReason.trim()}
                className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold rounded"
              >
                {submittingMerge ? 'Merging...' : 'Confirm Merge'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* SPLIT MODAL */}
      {showSplitModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center p-4 z-50">
          <form onSubmit={handleSplitSubmit} className="bg-slate-900 border border-slate-800 rounded-xl p-5 max-w-md w-full space-y-4">
            <h3 className="text-base font-bold text-white">Split Cluster</h3>
            <p className="text-xs text-slate-400">
              Partition selected members out into a new distinct investigation group.
            </p>
            <div>
              <label className="text-xs text-slate-400 block mb-1">Select Members to Transfer</label>
              <div className="max-h-40 overflow-y-auto space-y-1 bg-slate-950 p-2 rounded border border-slate-800 text-xs">
                {(clusterDetail?.members || []).map((m) => (
                  <label key={m.id} className="flex items-center gap-2 text-slate-300">
                    <input
                      type="checkbox"
                      checked={splitMemberIds.includes(m.member_id)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSplitMemberIds([...splitMemberIds, m.member_id]);
                        } else {
                          setSplitMemberIds(splitMemberIds.filter((id) => id !== m.member_id));
                        }
                      }}
                      className="rounded bg-slate-900 border-slate-700"
                    />
                    <span>{m.member_type}: {m.member_id}</span>
                  </label>
                ))}
              </div>
            </div>
            <div>
              <label className="text-xs text-slate-400 block mb-1">New Cluster Title</label>
              <input
                type="text"
                placeholder="Partitioned Investigation Group..."
                value={splitTitle}
                onChange={(e) => setSplitTitle(e.target.value)}
                className="w-full bg-slate-950 border border-slate-750 text-slate-200 text-xs rounded p-2 focus:outline-none"
              />
            </div>
            <div>
              <label className="text-xs text-slate-400 block mb-1">Split Reason</label>
              <input
                type="text"
                placeholder="Divergent protocol and targeting characteristics..."
                value={splitReason}
                onChange={(e) => setSplitReason(e.target.value)}
                className="w-full bg-slate-950 border border-slate-750 text-slate-200 text-xs rounded p-2 focus:outline-none"
              />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowSplitModal(false)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submittingSplit || splitMemberIds.length === 0 || !splitTitle.trim() || !splitReason.trim()}
                className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold rounded"
              >
                {submittingSplit ? 'Splitting...' : 'Confirm Split'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* CLOSE MODAL */}
      {showCloseModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center p-4 z-50">
          <form onSubmit={handleCloseSubmit} className="bg-slate-900 border border-slate-800 rounded-xl p-5 max-w-md w-full space-y-4">
            <h3 className="text-base font-bold text-white">Close Investigation</h3>
            <p className="text-xs text-slate-400">
              Conclude this investigation group. Closed investigations remain preserved for audit and historical review.
            </p>
            <div>
              <label className="text-xs text-slate-400 block mb-1">Resolution Status</label>
              <select
                value={closeResolution}
                onChange={(e) => setCloseResolution(e.target.value as any)}
                className="w-full bg-slate-950 border border-slate-750 text-slate-200 text-xs rounded p-2"
              >
                <option value="RESOLVED">RESOLVED</option>
                <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
                <option value="BENIGN_ACTIVITY">BENIGN_ACTIVITY</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-slate-400 block mb-1">Closure Summary / Rationale</label>
              <textarea
                rows={2}
                placeholder="Findings summary and justification for concluding investigation..."
                value={closeReason}
                onChange={(e) => setCloseReason(e.target.value)}
                className="w-full bg-slate-950 border border-slate-750 text-slate-200 text-xs rounded p-2 focus:outline-none"
              />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowCloseModal(false)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submittingClose || !closeReason.trim()}
                className="px-3 py-1.5 bg-red-600 hover:bg-red-500 text-white text-xs font-semibold rounded"
              >
                {submittingClose ? 'Closing...' : 'Close Investigation'}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
export default CampaignInvestigationsPage;

