import React, { useEffect, useState } from 'react';
import {
  BehavioralSequence,
  BehavioralSequenceDetail,
  SequenceStatistics,
  SequenceTimelineResponse,
} from '../../types/sequence';
import {
  listSequences,
  getSequence,
  getSequenceTimeline,
  recordAssessment,
  getSequenceStatistics,
} from '../../services/sequenceApi';
import { SequenceTimeline } from '../../components/SequenceTimeline';
import { SequenceRelationshipGraph } from '../../components/SequenceRelationshipGraph';

export const SequenceInvestigationPage: React.FC = () => {
  const [sequences, setSequences] = useState<BehavioralSequence[]>([]);
  const [stats, setStats] = useState<SequenceStatistics | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [patternFilter, setPatternFilter] = useState<string>('');
  const [searchIp, setSearchIp] = useState<string>('');
  const [page, setPage] = useState<number>(1);
  const [totalCount, setTotalCount] = useState<number>(0);

  // Detail View State
  const [selectedSequenceId, setSelectedSequenceId] = useState<string | null>(null);
  const [sequenceDetail, setSequenceDetail] = useState<BehavioralSequenceDetail | null>(null);
  const [timelineData, setTimelineData] = useState<SequenceTimelineResponse | null>(null);
  const [detailTab, setDetailTab] = useState<'timeline' | 'graph' | 'evidence' | 'history'>('timeline');
  const [detailLoading, setDetailLoading] = useState<boolean>(false);

  // Review Modal State
  const [showReviewModal, setShowReviewModal] = useState<boolean>(false);
  const [assessmentAction, setAssessmentAction] = useState<'CONFIRM' | 'DISMISS' | 'INCONCLUSIVE'>('CONFIRM');
  const [reviewNotes, setReviewNotes] = useState<string>('');
  const [submittingReview, setSubmittingReview] = useState<boolean>(false);

  useEffect(() => {
    loadData();
    loadStats();
  }, [page, statusFilter, patternFilter, searchIp]);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await listSequences({
        page,
        page_size: 15,
        status: statusFilter || undefined,
        pattern: patternFilter || undefined,
        source_address: searchIp || undefined,
      });
      setSequences(res.items);
      setTotalCount(res.total);
    } catch (err: any) {
      setError(err.message || 'Failed to load sequences');
    } finally {
      setLoading(false);
    }
  };

  const loadStats = async () => {
    try {
      const data = await getSequenceStatistics();
      setStats(data);
    } catch (e) {
      console.error('Failed to load stats', e);
    }
  };

  const handleSelectSequence = async (id: string) => {
    setSelectedSequenceId(id);
    setDetailLoading(true);
    try {
      const [detail, tl] = await Promise.all([
        getSequence(id),
        getSequenceTimeline(id),
      ]);
      setSequenceDetail(detail);
      setTimelineData(tl);
    } catch (err: any) {
      console.error(err);
    } finally {
      setDetailLoading(false);
    }
  };

  const handleAssessmentSubmit = async () => {
    if (!selectedSequenceId || reviewNotes.trim().length < 5) return;
    try {
      setSubmittingReview(true);
      await recordAssessment(selectedSequenceId, {
        assessment_action: assessmentAction,
        review_notes: reviewNotes,
      });
      setShowReviewModal(false);
      setReviewNotes('');
      // Reload current sequence detail and list
      await handleSelectSequence(selectedSequenceId);
      loadData();
      loadStats();
    } catch (err: any) {
      alert(`Error submitting review: ${err.message}`);
    } finally {
      setSubmittingReview(false);
    }
  };

  const getStatusBadge = (status: string) => {
    const map: Record<string, string> = {
      NEW: 'bg-cyan-950 text-cyan-300 border-cyan-800',
      OBSERVING: 'bg-blue-950 text-blue-300 border-blue-800',
      UNDER_REVIEW: 'bg-amber-950 text-amber-300 border-amber-800',
      REVIEWED: 'bg-emerald-950 text-emerald-300 border-emerald-800',
      DISMISSED: 'bg-slate-800 text-slate-400 border-slate-700',
      CLOSED: 'bg-slate-900 text-slate-500 border-slate-800',
    };
    return (
      <span className={`px-2 py-0.5 text-xs font-semibold rounded border ${map[status] || 'bg-slate-800 text-slate-300 border-slate-700'}`}>
        {status}
      </span>
    );
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 space-y-6">
      {/* Workspace Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse" />
            Multi-Session Attack-Chain & Behavioral Sequences
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Correlates discrete honeypot interaction sessions into explainable behavioral progression candidates (Task P22).
          </p>
        </div>
        <button
          onClick={() => { loadData(); loadStats(); }}
          className="px-3 py-1.5 text-xs bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded font-medium transition-colors"
        >
          Refresh Queue
        </button>
      </div>

      {/* KPI Summary Cards */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-lg">
            <span className="text-xs text-slate-400 font-medium">Total Sequences</span>
            <div className="text-2xl font-bold text-white mt-1">{stats.total_sequences}</div>
            <span className="text-xs text-slate-500 font-mono mt-1 block">Avg {stats.average_sessions_per_sequence} sess/seq</span>
          </div>
          <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-lg">
            <span className="text-xs text-blue-400 font-medium">Observing / New</span>
            <div className="text-2xl font-bold text-blue-300 mt-1">{stats.new_sequences + stats.observing_sequences}</div>
            <span className="text-xs text-slate-500 font-mono mt-1 block">Active correlation windows</span>
          </div>
          <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-lg">
            <span className="text-xs text-amber-400 font-medium">Under Investigation</span>
            <div className="text-2xl font-bold text-amber-300 mt-1">{stats.under_review_sequences}</div>
            <span className="text-xs text-slate-500 font-mono mt-1 block">Assigned to analysts</span>
          </div>
          <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-lg">
            <span className="text-xs text-emerald-400 font-medium">Confirmed Attack Chains</span>
            <div className="text-2xl font-bold text-emerald-300 mt-1">{stats.reviewed_sequences}</div>
            <span className="text-xs text-slate-500 font-mono mt-1 block">Evidence-validated progression</span>
          </div>
        </div>
      )}

      {/* Filter Toolbar */}
      <div className="flex flex-wrap items-center gap-3 bg-slate-900/40 p-3 rounded-lg border border-slate-800">
        <input
          type="text"
          placeholder="Filter by Source IP..."
          value={searchIp}
          onChange={(e) => setSearchIp(e.target.value)}
          className="px-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded text-slate-200 placeholder-slate-500 w-48 focus:outline-none focus:border-cyan-500"
        />
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-cyan-500"
        >
          <option value="">All Statuses</option>
          <option value="NEW">NEW</option>
          <option value="OBSERVING">OBSERVING</option>
          <option value="UNDER_REVIEW">UNDER_REVIEW</option>
          <option value="REVIEWED">REVIEWED</option>
          <option value="DISMISSED">DISMISSED</option>
          <option value="CLOSED">CLOSED</option>
        </select>
        <select
          value={patternFilter}
          onChange={(e) => setPatternFilter(e.target.value)}
          className="px-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-cyan-500"
        >
          <option value="">All Behavioral Patterns</option>
          <option value="REPEATED_AUTHENTICATION">Repeated Authentication</option>
          <option value="AUTH_THEN_ENUMERATION">Auth Then Enumeration</option>
          <option value="ENUMERATION_THEN_EXPLOIT">Enumeration Then Exploit</option>
          <option value="MULTI_TECHNIQUE_PROGRESSION">Multi-Technique Progression</option>
          <option value="RECURRING_HONEYPOT_TARGET">Recurring Decoy Target</option>
          <option value="CROSS_PROTOCOL_INTERACTION">Cross-Protocol Activity</option>
        </select>
        {(statusFilter || patternFilter || searchIp) && (
          <button
            onClick={() => { setStatusFilter(''); setPatternFilter(''); setSearchIp(''); }}
            className="text-xs text-slate-400 hover:text-slate-200 underline"
          >
            Clear Filters
          </button>
        )}
      </div>

      {/* Main Split Grid: Left Table, Right Detail */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Sequences Table (Left Pane) */}
        <div className={`space-y-4 ${selectedSequenceId ? 'lg:col-span-5' : 'lg:col-span-12'}`}>
          <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
            <div className="p-3 border-b border-slate-800 flex items-center justify-between text-xs text-slate-400">
              <span>Behavioral Sequence Candidates ({totalCount})</span>
              <span>Page {page}</span>
            </div>

            {loading ? (
              <div className="p-8 text-center text-xs text-slate-500">Loading sequence records...</div>
            ) : error ? (
              <div className="p-8 text-center text-xs text-rose-400">{error}</div>
            ) : sequences.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500">No behavioral sequences match active criteria.</div>
            ) : (
              <div className="divide-y divide-slate-800">
                {sequences.map((s) => {
                  const isSelected = selectedSequenceId === s.sequence_id;
                  return (
                    <div
                      key={s.sequence_id}
                      onClick={() => handleSelectSequence(s.sequence_id)}
                      className={`p-4 transition-all cursor-pointer ${
                        isSelected
                          ? 'bg-slate-800/80 border-l-4 border-cyan-400'
                          : 'hover:bg-slate-800/40'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-xs font-semibold text-cyan-400 truncate">
                          {s.sequence_id}
                        </span>
                        {getStatusBadge(s.lifecycle_status)}
                      </div>

                      <h3 className="text-sm font-medium text-slate-200 mt-1 line-clamp-1">
                        {s.title}
                      </h3>

                      <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-slate-400">
                        <span>Pattern: <strong className="text-slate-300 font-mono">{s.sequence_pattern}</strong></span>
                        <span>Sessions: <strong className="text-white">{s.session_count}</strong></span>
                        <span>Detections: <strong className="text-rose-400">{s.detection_count}</strong></span>
                        <span>Confidence: <strong className="text-amber-400">{s.correlation_confidence}%</strong></span>
                      </div>

                      <div className="mt-2 text-xs text-slate-500 font-mono">
                        Source: {s.primary_source_address || 'N/A'} | Target: {s.primary_decoy_id || 'N/A'}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* Sequence Detail Drawer (Right Pane) */}
        {selectedSequenceId && (
          <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
            {detailLoading ? (
              <div className="p-12 text-center text-xs text-slate-500">Loading sequence details & graph...</div>
            ) : sequenceDetail ? (
              <>
                {/* Detail Header */}
                <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-800 pb-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs text-cyan-400">{sequenceDetail.sequence_id}</span>
                      {getStatusBadge(sequenceDetail.lifecycle_status)}
                      <span className="px-2 py-0.5 text-xs font-bold rounded bg-amber-950 text-amber-300 border border-amber-800 font-mono">
                        {sequenceDetail.analyst_review_status}
                      </span>
                    </div>
                    <h2 className="text-lg font-bold text-white mt-1">{sequenceDetail.title}</h2>
                    <p className="text-xs text-slate-400 mt-1">{sequenceDetail.description}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setShowReviewModal(true)}
                      className="px-3 py-1.5 text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white rounded transition-colors"
                    >
                      Analyst Review
                    </button>
                    <button
                      onClick={() => setSelectedSequenceId(null)}
                      className="text-xs text-slate-500 hover:text-slate-300 px-2 py-1"
                    >
                      &times; Close
                    </button>
                  </div>
                </div>

                {/* Scope Warning Banner */}
                <div className="p-3 bg-amber-950/20 border border-amber-800/40 rounded text-xs text-amber-200/90 leading-relaxed">
                  <strong className="text-amber-300 font-semibold">Cautionary Investigation Boundary:</strong> A behavioral sequence is an analytical hypothesis. It does not establish common human identity, prove malicious intent, or confirm compromise without independent forensic validation.
                </div>

                {/* Tab Navigation */}
                <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
                  {[
                    { id: 'timeline', label: 'Multi-Session Timeline' },
                    { id: 'graph', label: 'Topology & Edges' },
                    { id: 'evidence', label: `Evidence (${sequenceDetail.evidence_items.length})` },
                    { id: 'history', label: `Audit Log (${sequenceDetail.history_records.length})` },
                  ].map((tab) => (
                    <button
                      key={tab.id}
                      onClick={() => setDetailTab(tab.id as any)}
                      className={`px-3 py-1.5 text-xs font-medium rounded transition-colors ${
                        detailTab === tab.id
                          ? 'bg-slate-800 text-cyan-400 font-semibold'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {tab.label}
                    </button>
                  ))}
                </div>

                {/* Tab Content */}
                {detailTab === 'timeline' && timelineData && (
                  <SequenceTimeline entries={timelineData.entries} sequenceId={sequenceDetail.sequence_id} />
                )}

                {detailTab === 'graph' && (
                  <SequenceRelationshipGraph
                    members={sequenceDetail.members}
                    relationships={sequenceDetail.relationships}
                    sequenceId={sequenceDetail.sequence_id}
                  />
                )}

                {detailTab === 'evidence' && (
                  <div className="space-y-3">
                    <div className="text-xs text-slate-400 font-medium">Field-Level Supporting Evidence Traces:</div>
                    {sequenceDetail.evidence_items.length === 0 ? (
                      <div className="p-4 text-xs text-slate-500 italic bg-slate-950 rounded">No field evidence stored.</div>
                    ) : (
                      sequenceDetail.evidence_items.map((ev) => (
                        <div key={ev.id} className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs space-y-1">
                          <div className="flex items-center justify-between text-slate-400">
                            <span className="font-mono font-semibold text-cyan-400">{ev.evidence_record_type} &bull; {ev.field_name}</span>
                            <span className="font-mono text-slate-500">{ev.observed_at}</span>
                          </div>
                          <div className="text-slate-200 font-mono bg-slate-900 p-1.5 rounded">{ev.field_value}</div>
                          {ev.evidence_provenance && Object.keys(ev.evidence_provenance).length > 0 && (
                            <div className="text-slate-500 text-xs">Provenance: {JSON.stringify(ev.evidence_provenance)}</div>
                          )}
                        </div>
                      ))
                    )}
                  </div>
                )}

                {detailTab === 'history' && (
                  <div className="space-y-3">
                    <div className="text-xs text-slate-400 font-medium">Assessment & Lifecycle History:</div>
                    {sequenceDetail.history_records.map((h) => (
                      <div key={h.id} className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs space-y-1">
                        <div className="flex items-center justify-between text-slate-400">
                          <span className="font-bold text-amber-300">{h.assessment_action}</span>
                          <span className="font-mono text-slate-500">{h.timestamp}</span>
                        </div>
                        <div className="text-slate-300">Actor: <span className="font-mono text-cyan-400">{h.assessed_by}</span> | Status: <span className="font-mono">{h.new_status}</span></div>
                        {h.assessment_notes && <p className="text-slate-400 italic mt-1">{h.assessment_notes}</p>}
                      </div>
                    ))}
                  </div>
                )}
              </>
            ) : null}
          </div>
        )}
      </div>

      {/* Analyst Assessment Modal */}
      {showReviewModal && sequenceDetail && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-white">Record Analyst Assessment</h3>
            <p className="text-xs text-slate-400">
              Document your investigation conclusion for sequence <code className="text-cyan-400 font-bold">{sequenceDetail.sequence_id}</code>.
            </p>

            <div className="space-y-2">
              <label className="text-xs font-semibold text-slate-300">Investigation Conclusion:</label>
              <div className="grid grid-cols-3 gap-2">
                {[
                  { id: 'CONFIRM', label: 'Confirm Attack Chain' },
                  { id: 'DISMISS', label: 'Dismiss Coincidence' },
                  { id: 'INCONCLUSIVE', label: 'Inconclusive' },
                ].map((act) => (
                  <button
                    key={act.id}
                    type="button"
                    onClick={() => setAssessmentAction(act.id as any)}
                    className={`py-2 text-xs font-medium rounded border transition-colors ${
                      assessmentAction === act.id
                        ? 'bg-cyan-600 text-white border-cyan-500 font-bold'
                        : 'bg-slate-950 text-slate-300 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    {act.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-xs font-semibold text-slate-300">
                Documented Justification (Required, min 5 chars):
              </label>
              <textarea
                rows={4}
                value={reviewNotes}
                onChange={(e) => setReviewNotes(e.target.value)}
                placeholder="Detail technical rationale, observed evidence, and verification notes..."
                className="w-full p-2.5 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setShowReviewModal(false)}
                className="px-4 py-2 text-xs text-slate-400 hover:text-slate-200"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={submittingReview || reviewNotes.trim().length < 5}
                onClick={handleAssessmentSubmit}
                className="px-4 py-2 text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded"
              >
                {submittingReview ? 'Recording...' : 'Commit Assessment'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

