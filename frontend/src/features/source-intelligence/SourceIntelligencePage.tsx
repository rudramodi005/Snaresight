import React, { useEffect, useState } from 'react';
import {
  SourceProfile,
  ProfileBehaviorResponse,
  ProfileTrendsResponse,
  SimilarProfile,
} from '../../types/sourceProfile';
import {
  listSourceProfiles,
  getSourceProfile,
  getSourceProfileSessions,
  getSourceProfileBehavior,
  getSourceProfileTrends,
  getSimilarProfiles,
  addAnalystNote,
  updateProfileAssociation,
  triggerAggregation,
} from '../../services/sourceProfileApi';
import { formatPercent, formatDateTime } from '../../utils/format';

export const SourceIntelligencePage: React.FC = () => {
  const [profiles, setProfiles] = useState<SourceProfile[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters & Pagination
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [priorityFilter, setPriorityFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [page, setPage] = useState<number>(1);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [isAggregating, setIsAggregating] = useState<boolean>(false);

  // Detail Drawer State
  const [selectedProfileId, setSelectedProfileId] = useState<string | null>(null);
  const [profileDetail, setProfileDetail] = useState<SourceProfile | null>(null);
  const [behaviorData, setBehaviorData] = useState<ProfileBehaviorResponse | null>(null);
  const [trendsData, setTrendsData] = useState<ProfileTrendsResponse | null>(null);
  const [sessionsData, setSessionsData] = useState<any[]>([]);
  const [similarProfiles, setSimilarProfiles] = useState<SimilarProfile[]>([]);
  const [detailTab, setDetailTab] = useState<'overview' | 'trends' | 'sessions' | 'similarity' | 'recurrences' | 'analyst'>('overview');
  const [detailLoading, setDetailLoading] = useState<boolean>(false);

  // Analyst Action Form State
  const [analystId, setAnalystId] = useState<string>('SOC-ANALYST');
  const [newNote, setNewNote] = useState<string>('');
  const [submittingNote, setSubmittingNote] = useState<boolean>(false);
  const [reviewPriority, setReviewPriority] = useState<string>('');
  const [reviewStatus, setReviewStatus] = useState<string>('');
  const [isSharedInfra, setIsSharedInfra] = useState<boolean>(false);
  const [reviewNotes, setReviewNotes] = useState<string>('');
  const [submittingReview, setSubmittingReview] = useState<boolean>(false);

  useEffect(() => {
    loadProfiles();
  }, [page, priorityFilter, statusFilter, searchTerm]);

  const loadProfiles = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await listSourceProfiles({
        page,
        page_size: 15,
        search: searchTerm || undefined,
        priority: priorityFilter || undefined,
        status: statusFilter || undefined,
      });
      setProfiles(res.items);
      setTotalCount(res.total);
    } catch (err: any) {
      setError(err.message || 'Failed to load source profiles');
    } finally {
      setLoading(false);
    }
  };

  const handleSelectProfile = async (profileId: string) => {
    setSelectedProfileId(profileId);
    setDetailLoading(true);
    try {
      const [p, b, t, s, sim] = await Promise.all([
        getSourceProfile(profileId),
        getSourceProfileBehavior(profileId),
        getSourceProfileTrends(profileId),
        getSourceProfileSessions(profileId),
        getSimilarProfiles(profileId),
      ]);
      setProfileDetail(p);
      setBehaviorData(b);
      setTrendsData(t);
      setSessionsData(s);
      setSimilarProfiles(sim);
      setReviewPriority(p.profile_priority);
      setReviewStatus(p.profile_status);
      setIsSharedInfra(p.is_shared_infrastructure);
    } catch (err: any) {
      console.error('Failed to load profile details:', err);
    } finally {
      setDetailLoading(false);
    }
  };

  const handleTriggerAggregation = async () => {
    try {
      setIsAggregating(true);
      await triggerAggregation({ force_all: true });
      await loadProfiles();
      if (selectedProfileId) {
        await handleSelectProfile(selectedProfileId);
      }
    } catch (err: any) {
      alert(`Aggregation failed: ${err.message}`);
    } finally {
      setIsAggregating(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProfileId || !newNote.trim()) return;
    try {
      setSubmittingNote(true);
      await addAnalystNote(selectedProfileId, {
        analyst_id: analystId,
        notes: newNote.trim(),
      });
      setNewNote('');
      // Reload behavior & profile
      const [updatedP, updatedB] = await Promise.all([
        getSourceProfile(selectedProfileId),
        getSourceProfileBehavior(selectedProfileId),
      ]);
      setProfileDetail(updatedP);
      setBehaviorData(updatedB);
      loadProfiles();
    } catch (err: any) {
      alert(`Failed to add note: ${err.message}`);
    } finally {
      setSubmittingNote(false);
    }
  };

  const handleUpdateAssociation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProfileId) return;
    try {
      setSubmittingReview(true);
      const updated = await updateProfileAssociation(selectedProfileId, {
        analyst_id: analystId,
        is_shared_infrastructure: isSharedInfra,
        status: (reviewStatus as any) || undefined,
        priority: (reviewPriority as any) || undefined,
        notes: reviewNotes.trim() || undefined,
      });
      setProfileDetail(updated);
      setReviewNotes('');
      const updatedB = await getSourceProfileBehavior(selectedProfileId);
      setBehaviorData(updatedB);
      loadProfiles();
      alert('Profile association and priority updated successfully.');
    } catch (err: any) {
      alert(`Failed to update association: ${err.message}`);
    } finally {
      setSubmittingReview(false);
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

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight text-white">Source Intelligence & Profiling</h1>
            <span className="px-2.5 py-0.5 text-xs font-medium rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800">
              Phase 5: Task P23
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Persistent behavioral intelligence, multi-session activity baselines, and explainable source context.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleTriggerAggregation}
            disabled={isAggregating}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-900 text-white text-sm font-medium rounded-lg shadow transition"
          >
            {isAggregating ? (
              <>
                <svg className="animate-spin h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                </svg>
                Aggregating Profiles...
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.03 8.03 0 01-15.357-2m15.357 2H15" />
                </svg>
                Run On-Demand Aggregation
              </>
            )}
          </button>
        </div>
      </div>

      {/* Disclaimers & Terminology Guardrail Banner */}
      <div className="my-4 p-3 bg-slate-900/80 border border-slate-800 rounded-lg flex items-center justify-between text-xs text-slate-400">
        <div className="flex items-center gap-2">
          <svg className="w-4 h-4 text-cyan-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <span>
            <strong className="text-slate-300">Operational Notice:</strong> Profiles represent <em>Observed Network Artifacts</em> across deception decoys. They organize observable honeypot interactions and do not infer physical identity, geographic location, or confirmed threat actor attribution.
          </span>
        </div>
        <span className="font-mono text-slate-500">Zero Password Persistence Enforced</span>
      </div>

      {/* Filter and Search Bar */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="md:col-span-2">
          <input
            type="text"
            placeholder="Search by Source IP, Profile ID, or Label..."
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
            <option value="INSUFFICIENT_DATA">INSUFFICIENT_DATA</option>
          </select>
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
            <option value="">All Statuses</option>
            <option value="ACTIVE">ACTIVE</option>
            <option value="DORMANT">DORMANT</option>
            <option value="ARCHIVED">ARCHIVED</option>
          </select>
        </div>
      </div>

      {/* Main Workspace Layout: Table + Detail Slide-Over */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Side: Profile Table */}
        <div className={`${selectedProfileId ? 'lg:col-span-6' : 'lg:col-span-12'} transition-all duration-300`}>
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow">
            <div className="p-4 border-b border-slate-800 flex justify-between items-center">
              <span className="text-sm font-semibold text-slate-300">
                Observed Source Profiles ({totalCount})
              </span>
              {loading && <span className="text-xs text-indigo-400 animate-pulse">Loading profiles...</span>}
            </div>

            {error ? (
              <div className="p-6 text-center text-red-400 text-sm">{error}</div>
            ) : profiles.length === 0 && !loading ? (
              <div className="p-8 text-center text-slate-500 text-sm">
                No observed source profiles found matching criteria. Click "Run On-Demand Aggregation" to discover active honeypot traffic.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm text-slate-300">
                  <thead className="bg-slate-950/60 text-xs uppercase tracking-wider text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="py-3 px-4">Priority</th>
                      <th className="py-3 px-4">Observed Source</th>
                      <th className="py-3 px-4">Activity Volume</th>
                      <th className="py-3 px-4">Targets</th>
                      <th className="py-3 px-4">Last Observed</th>
                      <th className="py-3 px-4 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {profiles.map((p) => {
                      const isSelected = selectedProfileId === p.profile_id;
                      return (
                        <tr
                          key={p.profile_id}
                          onClick={() => handleSelectProfile(p.profile_id)}
                          className={`cursor-pointer transition hover:bg-slate-800/50 ${
                            isSelected ? 'bg-indigo-950/40 border-l-4 border-indigo-500' : ''
                          }`}
                        >
                          <td className="py-3 px-4">
                            <span className={`px-2 py-0.5 text-xs font-semibold rounded ${getPriorityBadgeClass(p.profile_priority)}`}>
                              {p.profile_priority}
                            </span>
                          </td>
                          <td className="py-3 px-4">
                            <div className="font-mono text-slate-100 font-medium">{p.source_ip}</div>
                            <div className="flex items-center gap-1.5 mt-0.5">
                              <span className="text-[10px] text-slate-400 font-mono">{p.ip_family}</span>
                              {p.is_shared_infrastructure && (
                                <span className="text-[10px] px-1 bg-amber-950 text-amber-400 border border-amber-800 rounded">
                                  Shared Infra
                                </span>
                              )}
                              {p.analyst_notes_count > 0 && (
                                <span className="text-[10px] text-indigo-400">
                                  📝 {p.analyst_notes_count}
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="py-3 px-4">
                            <div className="text-xs text-slate-300">
                              <span className="font-semibold text-slate-100">{p.total_sessions}</span> sessions
                            </div>
                            <div className="text-xs text-slate-400">
                              {p.total_events} events • {p.total_alerts} alerts
                            </div>
                          </td>
                          <td className="py-3 px-4">
                            <div className="text-xs text-slate-300">{p.distinct_honeypots} decoy(s)</div>
                            <div className="text-[11px] text-slate-400">
                              {Object.keys(p.protocol_distribution).join(', ') || 'N/A'}
                            </div>
                          </td>
                          <td className="py-3 px-4 text-xs text-slate-400 font-mono">
                            {formatDateTime(p.last_observed_at)}
                          </td>
                          <td className="py-3 px-4 text-right">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                handleSelectProfile(p.profile_id);
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

        {/* Right Side: Profile Inspection Drawer */}
        {selectedProfileId && (
          <div className="lg:col-span-6 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow flex flex-col">
            {/* Drawer Header */}
            <div className="p-4 bg-slate-950/60 border-b border-slate-800 flex justify-between items-start">
              <div>
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 text-xs font-semibold rounded ${getPriorityBadgeClass(profileDetail?.profile_priority || '')}`}>
                    {profileDetail?.profile_priority}
                  </span>
                  <span className="text-xs font-mono text-slate-400">{profileDetail?.profile_id}</span>
                </div>
                <h2 className="text-lg font-bold text-white mt-1">
                  {profileDetail?.display_label || `Observed Source Profile: ${profileDetail?.source_ip}`}
                </h2>
                <div className="text-xs text-slate-400 mt-0.5 flex items-center gap-2">
                  <span>Status: <strong className="text-slate-300">{profileDetail?.profile_status}</strong></span>
                  <span>•</span>
                  <span>Fingerprint: <span className="font-mono text-slate-400">{profileDetail?.fingerprint.substring(0, 12)}...</span></span>
                </div>
              </div>

              <button
                onClick={() => setSelectedProfileId(null)}
                className="text-slate-400 hover:text-slate-200 text-sm p-1 rounded hover:bg-slate-800"
              >
                ✕ Close
              </button>
            </div>

            {/* Navigation Tabs */}
            <div className="flex border-b border-slate-800 text-xs font-medium bg-slate-950/40">
              {[
                { id: 'overview', label: 'Overview & Baselines' },
                { id: 'trends', label: 'Trends' },
                { id: 'sessions', label: `Sessions (${sessionsData.length})` },
                { id: 'similarity', label: `Similar Sources (${similarProfiles.length})` },
                { id: 'recurrences', label: `Recurrences (${behaviorData?.recurrences.length || 0})` },
                { id: 'analyst', label: `Analyst Actions (${behaviorData?.history.length || 0})` },
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
                  Loading source intelligence profile telemetry...
                </div>
              ) : (
                <>
                  {/* TAB 1: OVERVIEW & BASELINES */}
                  {detailTab === 'overview' && behaviorData && (
                    <div className="space-y-4">
                      {/* Priority Rationale Card */}
                      <div className="p-3.5 bg-slate-950/80 border border-slate-800 rounded-lg">
                        <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">
                          Transparent Prioritization Rationale
                        </span>
                        <p className="text-sm text-slate-200 mt-1 font-medium">
                          {behaviorData.priority_rationale}
                        </p>
                      </div>

                      {/* Behavioral Metrics Grid */}
                      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                        <div className="p-3 bg-slate-950/50 border border-slate-800 rounded-lg">
                          <span className="text-[11px] text-slate-400 uppercase font-semibold">Interaction Tempo</span>
                          <div className="text-lg font-bold text-slate-100 mt-0.5">
                            {behaviorData.baseline_features.interaction_tempo} <span className="text-xs font-normal text-slate-400">ev/min</span>
                          </div>
                        </div>

                        <div className="p-3 bg-slate-950/50 border border-slate-800 rounded-lg">
                          <span className="text-[11px] text-slate-400 uppercase font-semibold">Burstiness Ratio</span>
                          <div className="text-lg font-bold text-slate-100 mt-0.5">
                            {behaviorData.baseline_features.burstiness_ratio}x
                          </div>
                        </div>

                        <div className="p-3 bg-slate-950/50 border border-slate-800 rounded-lg">
                          <span className="text-[11px] text-slate-400 uppercase font-semibold">Max Concurrency</span>
                          <div className="text-lg font-bold text-slate-100 mt-0.5">
                            {behaviorData.baseline_features.concurrency_level} <span className="text-xs font-normal text-slate-400">session(s)</span>
                          </div>
                        </div>

                        <div className="p-3 bg-slate-950/50 border border-slate-800 rounded-lg">
                          <span className="text-[11px] text-slate-400 uppercase font-semibold">Auth Failures</span>
                          <div className="text-lg font-bold text-orange-400 mt-0.5">
                            {behaviorData.baseline_features.auth_failure_count} / {behaviorData.baseline_features.auth_attempt_count}
                          </div>
                        </div>

                        <div className="p-3 bg-slate-950/50 border border-slate-800 rounded-lg">
                          <span className="text-[11px] text-slate-400 uppercase font-semibold">Distinct Users Tested</span>
                          <div className="text-lg font-bold text-slate-100 mt-0.5">
                            {behaviorData.baseline_features.distinct_usernames_count}
                          </div>
                        </div>

                        <div className="p-3 bg-slate-950/50 border border-slate-800 rounded-lg">
                          <span className="text-[11px] text-slate-400 uppercase font-semibold">Traversal Probes</span>
                          <div className="text-lg font-bold text-red-400 mt-0.5">
                            {behaviorData.baseline_features.path_traversal_probes}
                          </div>
                        </div>
                      </div>

                      {/* Honeypots & Protocol Distribution */}
                      <div className="p-3.5 bg-slate-950/50 border border-slate-800 rounded-lg">
                        <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">
                          Targeted Decoys & Honeypot Affinities
                        </span>
                        <div className="flex flex-wrap gap-2 mt-2">
                          {(profileDetail?.behavioral_summary.honeypots || []).map((h) => (
                            <span key={h} className="px-2 py-1 text-xs bg-indigo-950 text-indigo-300 border border-indigo-800 rounded">
                              🎯 {h}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* TAB 2: TRENDS */}
                  {detailTab === 'trends' && trendsData && (
                    <div className="space-y-4">
                      <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">
                        Multi-Window Feature Comparison
                      </span>
                      <div className="grid grid-cols-2 gap-3">
                        {Object.entries(trendsData.windows).map(([wName, wFeat]) => (
                          <div key={wName} className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
                            <span className="text-xs font-bold text-indigo-400">{wName} Window</span>
                            <div className="text-xs text-slate-300 mt-1 space-y-1">
                              <div>Tempo: {wFeat.interaction_tempo} ev/min</div>
                              <div>Auth Failures: {wFeat.auth_failure_count}</div>
                              <div>Traversal Probes: {wFeat.path_traversal_probes}</div>
                            </div>
                          </div>
                        ))}
                      </div>

                      <span className="text-xs uppercase tracking-wider font-semibold text-slate-400 block mt-4">
                        Activity Timeline Points ({trendsData.activity_timeline.length})
                      </span>
                      <div className="space-y-2">
                        {trendsData.activity_timeline.map((pt, idx) => (
                          <div key={idx} className="p-2.5 bg-slate-950/40 border border-slate-800/80 rounded flex justify-between text-xs">
                            <span className="font-mono text-slate-400">{pt.timestamp}</span>
                            <span className="text-slate-300">{pt.event_count} events ({pt.top_protocol})</span>
                            {pt.alert_count > 0 && <span className="text-amber-400">🚨 Alert Triggered</span>}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* TAB 3: SESSIONS */}
                  {detailTab === 'sessions' && (
                    <div className="space-y-3">
                      <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">
                        Correlated Activity Sessions ({sessionsData.length})
                      </span>
                      {sessionsData.map((s) => (
                        <div key={s.session_id} className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg text-xs space-y-1">
                          <div className="flex justify-between items-center">
                            <span className="font-mono font-semibold text-indigo-400">{s.session_id}</span>
                            <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300">
                              {s.session_status}
                            </span>
                          </div>
                          <div className="text-slate-300">
                            Target Decoy: <strong className="text-slate-100">{s.decoy_id}</strong> ({s.protocol})
                          </div>
                          <div className="text-slate-400">
                            {s.event_count} events • Observed: {formatDateTime(s.start_time)}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* TAB 4: SIMILARITY */}
                  {detailTab === 'similarity' && (
                    <div className="space-y-4">
                      <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">
                        Behaviorally Similar Observed Profiles ({similarProfiles.length})
                      </span>
                      {similarProfiles.length === 0 ? (
                        <div className="text-xs text-slate-500 p-4 bg-slate-950/40 rounded border border-slate-800">
                          No behaviorally similar profiles observed above the similarity threshold.
                        </div>
                      ) : (
                        similarProfiles.map((sim) => (
                          <div key={sim.target_profile_id} className="p-3.5 bg-slate-950/80 border border-slate-800 rounded-lg space-y-2">
                            <div className="flex justify-between items-center">
                              <div>
                                <span className="font-semibold text-slate-200">{sim.target_source_ip}</span>
                                <span className="text-xs text-slate-500 font-mono ml-2">({sim.target_profile_id})</span>
                              </div>
                              <span className="px-2 py-0.5 text-xs font-bold rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                                {sim.similarity_score}% Match
                              </span>
                            </div>

                            {/* Contributing Factors */}
                            <div className="text-xs text-slate-400 space-y-1 pt-1 border-t border-slate-800/80">
                              {sim.contributing_factors.map((f, i) => (
                                <div key={i} className="flex justify-between">
                                  <span>{f.dimension}: <span className="text-slate-300">{f.rationale}</span></span>
                                  <span className="font-mono text-cyan-400">{formatPercent(f.similarity, 0, 'N/A', 100)}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  )}

                  {/* TAB 5: RECURRENCES */}
                  {detailTab === 'recurrences' && (
                    <div className="space-y-3">
                      <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">
                        Observed Pattern Recurrences After Dormancy
                      </span>
                      {(behaviorData?.recurrences || []).length === 0 ? (
                        <div className="text-xs text-slate-500 p-4 bg-slate-950/40 rounded border border-slate-800">
                          No dormancy reactivations detected for this profile.
                        </div>
                      ) : (
                        (behaviorData?.recurrences || []).map((r) => (
                          <div key={r.id} className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg text-xs space-y-1">
                            <div className="flex justify-between items-center">
                              <span className="font-semibold text-amber-400">
                                Reactivated after {r.dormant_interval_display}
                              </span>
                              <span className="font-mono text-slate-400">
                                {formatDateTime(r.reactivation_at)}
                              </span>
                            </div>
                            <p className="text-slate-300">{r.summary}</p>
                          </div>
                        ))
                      )}
                    </div>
                  )}

                  {/* TAB 6: ANALYST ACTIONS & AUDIT */}
                  {detailTab === 'analyst' && (
                    <div className="space-y-6">
                      {/* Add Note Form */}
                      <form onSubmit={handleAddNote} className="p-3.5 bg-slate-950/80 border border-slate-800 rounded-lg space-y-3">
                        <span className="text-xs uppercase tracking-wider font-semibold text-slate-400 block">
                          Record Analyst Investigation Note
                        </span>
                        <div>
                          <label className="text-[11px] text-slate-400 block mb-1">Analyst ID</label>
                          <input
                            type="text"
                            value={analystId}
                            onChange={(e) => setAnalystId(e.target.value)}
                            className="w-full bg-slate-900 border border-slate-750 text-slate-200 text-xs rounded px-2.5 py-1.5 focus:outline-none"
                          />
                        </div>
                        <div>
                          <label className="text-[11px] text-slate-400 block mb-1">Observation Notes</label>
                          <textarea
                            rows={3}
                            placeholder="Enter findings, behavioral context, or IOC correlation notes..."
                            value={newNote}
                            onChange={(e) => setNewNote(e.target.value)}
                            className="w-full bg-slate-900 border border-slate-750 text-slate-200 text-xs rounded px-2.5 py-1.5 focus:outline-none"
                          />
                        </div>
                        <button
                          type="submit"
                          disabled={submittingNote || !newNote.trim()}
                          className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-900 text-white text-xs font-medium rounded transition"
                        >
                          {submittingNote ? 'Saving Note...' : 'Add Note'}
                        </button>
                      </form>

                      {/* Association & Infrastructure Review Form */}
                      <form onSubmit={handleUpdateAssociation} className="p-3.5 bg-slate-950/80 border border-slate-800 rounded-lg space-y-3">
                        <span className="text-xs uppercase tracking-wider font-semibold text-slate-400 block">
                          Association & Priority Review
                        </span>
                        <div className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            id="sharedInfraCheck"
                            checked={isSharedInfra}
                            onChange={(e) => setIsSharedInfra(e.target.checked)}
                            className="rounded bg-slate-900 border-slate-700 text-indigo-600 focus:ring-0"
                          />
                          <label htmlFor="sharedInfraCheck" className="text-xs text-slate-300">
                            Flag as Shared Infrastructure (NAT / VPN / Public Cloud Gateway)
                          </label>
                        </div>
                        <div className="grid grid-cols-2 gap-3">
                          <div>
                            <label className="text-[11px] text-slate-400 block mb-1">Priority Override</label>
                            <select
                              value={reviewPriority}
                              onChange={(e) => setReviewPriority(e.target.value)}
                              className="w-full bg-slate-900 border border-slate-750 text-slate-200 text-xs rounded px-2 py-1.5"
                            >
                              <option value="CRITICAL">CRITICAL</option>
                              <option value="HIGH">HIGH</option>
                              <option value="MEDIUM">MEDIUM</option>
                              <option value="LOW">LOW</option>
                              <option value="INSUFFICIENT_DATA">INSUFFICIENT_DATA</option>
                            </select>
                          </div>
                          <div>
                            <label className="text-[11px] text-slate-400 block mb-1">Status Override</label>
                            <select
                              value={reviewStatus}
                              onChange={(e) => setReviewStatus(e.target.value)}
                              className="w-full bg-slate-900 border border-slate-750 text-slate-200 text-xs rounded px-2 py-1.5"
                            >
                              <option value="ACTIVE">ACTIVE</option>
                              <option value="DORMANT">DORMANT</option>
                              <option value="ARCHIVED">ARCHIVED</option>
                            </select>
                          </div>
                        </div>
                        <div>
                          <label className="text-[11px] text-slate-400 block mb-1">Rationale / Audit Comment</label>
                          <input
                            type="text"
                            placeholder="Reason for adjustment..."
                            value={reviewNotes}
                            onChange={(e) => setReviewNotes(e.target.value)}
                            className="w-full bg-slate-900 border border-slate-750 text-slate-200 text-xs rounded px-2.5 py-1.5 focus:outline-none"
                          />
                        </div>
                        <button
                          type="submit"
                          disabled={submittingReview}
                          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded border border-slate-700 transition"
                        >
                          {submittingReview ? 'Updating...' : 'Save Review'}
                        </button>
                      </form>

                      {/* Audit History Log */}
                      <div>
                        <span className="text-xs uppercase tracking-wider font-semibold text-slate-400 block mb-2">
                          Audit History ({behaviorData?.history.length || 0})
                        </span>
                        <div className="space-y-2">
                          {(behaviorData?.history || []).map((h) => (
                            <div key={h.id} className="p-2.5 bg-slate-950/40 border border-slate-800 rounded text-xs space-y-1">
                              <div className="flex justify-between items-center text-slate-400 font-mono text-[11px]">
                                <span>{h.action} by {h.analyst_id || 'System'}</span>
                                <span>{formatDateTime(h.created_at)}</span>
                              </div>
                              {h.notes && <div className="text-slate-300 italic">"{h.notes}"</div>}
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
export default SourceIntelligencePage;

