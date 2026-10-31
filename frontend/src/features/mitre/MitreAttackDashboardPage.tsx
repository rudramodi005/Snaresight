import React, { useState, useEffect, useCallback } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  AttackCatalogueMetadata,
  AttackSummaryResponse,
  AttackTacticOverviewItem,
  AttackMatrixResponse,
  AttackMatrixColumn,
  AttackMatrixCell,
  AttackTechniqueExplorerItem,
  AttackTechniqueExplorerResponse,
  AttackTechniqueDetailResponse,
  AttackCoverageAnalyticsResponse,
  AttackTraceabilityItem,
  AttackTraceabilityResponse,
  AttackVisualState,
} from '../../types/mitre';
import { mitreApi } from '../../services/mitreApi';

export const MitreAttackDashboardPage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();

  // Active view tab
  const [activeTab, setActiveTab] = useState<'matrix' | 'tactics' | 'explorer' | 'coverage' | 'traceability' | 'reviews'>(
    (searchParams.get('tab') as any) || 'matrix'
  );

  // High-level metadata & summary
  const [metadata, setMetadata] = useState<AttackCatalogueMetadata | null>(null);
  const [summary, setSummary] = useState<AttackSummaryResponse | null>(null);
  const [loadingSummary, setLoadingSummary] = useState(true);

  // Tactics Overview
  const [tacticsOverview, setTacticsOverview] = useState<AttackTacticOverviewItem[]>([]);
  const [loadingTactics, setLoadingTactics] = useState(false);

  // Matrix View State
  const [matrixData, setMatrixData] = useState<AttackMatrixResponse | null>(null);
  const [matrixFilterStatus, setMatrixFilterStatus] = useState<string>('ALL');
  const [matrixFilterTactic, setMatrixFilterTactic] = useState<string>('');
  const [matrixSearch, setMatrixSearch] = useState<string>('');
  const [loadingMatrix, setLoadingMatrix] = useState(false);

  // Explorer View State
  const [explorerData, setExplorerData] = useState<AttackTechniqueExplorerResponse | null>(null);
  const [explorerSearch, setExplorerSearch] = useState<string>('');
  const [explorerTactic, setExplorerTactic] = useState<string>('');
  const [explorerStatus, setExplorerStatus] = useState<string>('ALL');
  const [explorerPage, setExplorerPage] = useState<number>(1);
  const [loadingExplorer, setLoadingExplorer] = useState(false);

  // Coverage Analytics
  const [coverageData, setCoverageData] = useState<AttackCoverageAnalyticsResponse | null>(null);
  const [loadingCoverage, setLoadingCoverage] = useState(false);

  // Traceability
  const [traceabilityData, setTraceabilityData] = useState<AttackTraceabilityResponse | null>(null);
  const [traceabilityRuleFilter, setTraceabilityRuleFilter] = useState<string>('');
  const [loadingTraceability, setLoadingTraceability] = useState(false);

  // Detail Modal / Drawer
  const [selectedTechniqueId, setSelectedTechniqueId] = useState<string | null>(searchParams.get('technique_id'));
  const [techniqueDetail, setTechniqueDetail] = useState<AttackTechniqueDetailResponse | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  // Review Modal State
  const [reviewModalOpen, setReviewModalOpen] = useState(false);
  const [reviewMappingId, setReviewMappingId] = useState<string | null>(null);
  const [reviewAction, setReviewAction] = useState<'APPROVE' | 'REJECT' | 'REQUEST_REVIEW'>('APPROVE');
  const [reviewComment, setReviewComment] = useState('');
  const [reviewAnalystId, setReviewAnalystId] = useState('analyst_soc_lead');
  const [submittingReview, setSubmittingReview] = useState(false);

  // Global Error / Notification
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [notification, setNotification] = useState<string | null>(null);

  // Load Metadata & Summary on Mount
  const loadSummaryData = useCallback(async () => {
    setLoadingSummary(true);
    try {
      const [meta, sum] = await Promise.all([
        mitreApi.getCatalogueMetadata(),
        mitreApi.getAttackSummary(),
      ]);
      setMetadata(meta);
      setSummary(sum);
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to load MITRE ATT&CK summary metadata.');
    } finally {
      setLoadingSummary(false);
    }
  }, []);

  useEffect(() => {
    loadSummaryData();
  }, [loadSummaryData]);

  // Load Tab Specific Data
  useEffect(() => {
    if (activeTab === 'matrix') {
      loadMatrixData();
    } else if (activeTab === 'tactics') {
      loadTacticsData();
    } else if (activeTab === 'explorer') {
      loadExplorerData();
    } else if (activeTab === 'coverage') {
      loadCoverageData();
    } else if (activeTab === 'traceability') {
      loadTraceabilityData();
    }
  }, [activeTab]);

  // Handle URL technique_id param
  useEffect(() => {
    const tid = searchParams.get('technique_id');
    if (tid && tid !== selectedTechniqueId) {
      setSelectedTechniqueId(tid);
    }
  }, [searchParams]);

  useEffect(() => {
    if (selectedTechniqueId) {
      loadTechniqueDetail(selectedTechniqueId);
    } else {
      setTechniqueDetail(null);
    }
  }, [selectedTechniqueId]);

  const loadMatrixData = async () => {
    setLoadingMatrix(true);
    try {
      const data = await mitreApi.getAttackMatrix({
        tactic: matrixFilterTactic || undefined,
        statusFilter: matrixFilterStatus !== 'ALL' ? matrixFilterStatus : undefined,
        search: matrixSearch || undefined,
      });
      setMatrixData(data);
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to load MITRE matrix.');
    } finally {
      setLoadingMatrix(false);
    }
  };

  const loadTacticsData = async () => {
    setLoadingTactics(true);
    try {
      const data = await mitreApi.getTacticsOverview();
      setTacticsOverview(data);
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to load tactics overview.');
    } finally {
      setLoadingTactics(false);
    }
  };

  const loadExplorerData = async () => {
    setLoadingExplorer(true);
    try {
      const data = await mitreApi.getTechniquesExplorer({
        search: explorerSearch || undefined,
        tactic: explorerTactic || undefined,
        statusFilter: explorerStatus !== 'ALL' ? explorerStatus : undefined,
        page: explorerPage,
        pageSize: 20,
      });
      setExplorerData(data);
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to load techniques explorer.');
    } finally {
      setLoadingExplorer(false);
    }
  };

  const loadCoverageData = async () => {
    setLoadingCoverage(true);
    try {
      const data = await mitreApi.getCoverageAnalytics();
      setCoverageData(data);
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to load coverage analytics.');
    } finally {
      setLoadingCoverage(false);
    }
  };

  const loadTraceabilityData = async () => {
    setLoadingTraceability(true);
    try {
      const data = await mitreApi.getTraceability({
        ruleId: traceabilityRuleFilter || undefined,
      });
      setTraceabilityData(data);
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to load traceability data.');
    } finally {
      setLoadingTraceability(false);
    }
  };

  const loadTechniqueDetail = async (techniqueId: string) => {
    setLoadingDetail(true);
    try {
      const detail = await mitreApi.getTechniqueDetail(techniqueId);
      setTechniqueDetail(detail);
    } catch (err: any) {
      setErrorMessage(err?.message || `Failed to load details for ${techniqueId}`);
    } finally {
      setLoadingDetail(false);
    }
  };

  const openTechnique = (techniqueId: string) => {
    setSelectedTechniqueId(techniqueId);
    const newParams = new URLSearchParams(searchParams);
    newParams.set('technique_id', techniqueId);
    setSearchParams(newParams);
  };

  const closeTechnique = () => {
    setSelectedTechniqueId(null);
    setTechniqueDetail(null);
    const newParams = new URLSearchParams(searchParams);
    newParams.delete('technique_id');
    setSearchParams(newParams);
  };

  const switchTab = (tab: typeof activeTab) => {
    setActiveTab(tab);
    const newParams = new URLSearchParams(searchParams);
    newParams.set('tab', tab);
    setSearchParams(newParams);
  };

  const openReviewModal = (mappingId: string, defaultAction: 'APPROVE' | 'REJECT' | 'REQUEST_REVIEW' = 'APPROVE') => {
    setReviewMappingId(mappingId);
    setReviewAction(defaultAction);
    setReviewComment('');
    setReviewModalOpen(true);
  };

  const submitReviewAction = async () => {
    if (!reviewMappingId) return;
    setSubmittingReview(true);
    try {
      if (reviewAction === 'APPROVE') {
        await mitreApi.approveAttackMapping(reviewMappingId, reviewComment || 'Approved in SOC triage', reviewAnalystId);
      } else if (reviewAction === 'REJECT') {
        await mitreApi.rejectAttackMapping(reviewMappingId, reviewComment || 'Rejected by analyst', reviewAnalystId);
      } else {
        await mitreApi.requestAttackMappingReview(reviewMappingId, reviewComment || 'Requested additional evidence', reviewAnalystId);
      }
      setNotification(`Review recorded: ${reviewAction} on mapping ${reviewMappingId.slice(0, 8)}...`);
      setReviewModalOpen(false);
      // Reload current views
      loadSummaryData();
      if (selectedTechniqueId) loadTechniqueDetail(selectedTechniqueId);
      if (activeTab === 'matrix') loadMatrixData();
      if (activeTab === 'explorer') loadExplorerData();
      if (activeTab === 'traceability') loadTraceabilityData();
    } catch (err: any) {
      setErrorMessage(err?.message || 'Review action failed.');
    } finally {
      setSubmittingReview(false);
    }
  };

  // State Badge Helpers
  const renderVisualStateBadge = (state: AttackVisualState) => {
    switch (state) {
      case 'ALERT_EVIDENCE':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase bg-emerald-950/80 text-emerald-400 border border-emerald-500/40 animate-pulse">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
            Alert Evidence
          </span>
        );
      case 'RULE_MAPPED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase bg-blue-950/80 text-blue-400 border border-blue-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-400"></span>
            Rule Mapped
          </span>
        );
      case 'REVIEW_REQUIRED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase bg-amber-950/80 text-amber-400 border border-amber-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
            Review Needed
          </span>
        );
      case 'UNMAPPED':
      default:
        return (
          <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-normal text-slate-500 bg-slate-900 border border-slate-800">
            Unmapped
          </span>
        );
    }
  };

  return (
    <div className="p-6 max-w-[1720px] mx-auto space-y-6 text-slate-100 font-sans">
      {/* 1. Header Banner */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-3">
            <span className="text-3xl">🗺️</span>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-slate-100">
                MITRE ATT&CK Threat Intelligence & Mapping
              </h1>
              <p className="text-xs text-slate-400 mt-0.5">
                Enterprise Deception Mapping, Technique Coverage & Behavioral Tradecraft Analytics
              </p>
            </div>
          </div>
        </div>

        {/* Catalogue & Registry Metadata Badges */}
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center gap-2">
            <span className="text-slate-500 uppercase font-mono text-[10px]">Domain:</span>
            <span className="font-semibold text-slate-200">
              {metadata?.domain || 'enterprise-attack'}
            </span>
          </div>
          <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center gap-2">
            <span className="text-slate-500 uppercase font-mono text-[10px]">Release:</span>
            <span className="font-semibold text-emerald-400">
              {metadata?.version || summary?.catalogue_version || 'v14.1'}
            </span>
          </div>
          <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center gap-2">
            <span className="text-slate-500 uppercase font-mono text-[10px]">Registry:</span>
            <span className="font-semibold text-blue-400">
              {summary?.mapping_registry_version || 'v1.0'}
            </span>
          </div>
          <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center gap-2">
            <span className="text-slate-500 uppercase font-mono text-[10px]">Refreshed:</span>
            <span className="text-slate-300 font-mono text-[11px]">
              {summary?.last_refreshed_at ? new Date(summary.last_refreshed_at).toLocaleTimeString() : 'Live'}
            </span>
          </div>
          <button
            onClick={() => {
              loadSummaryData();
              if (activeTab === 'matrix') loadMatrixData();
              if (activeTab === 'explorer') loadExplorerData();
              if (activeTab === 'coverage') loadCoverageData();
              if (activeTab === 'traceability') loadTraceabilityData();
            }}
            className="px-3 py-1.5 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 text-xs font-medium transition-colors"
          >
            ↻ Refresh
          </button>
        </div>
      </div>

      {/* 2. Non-Attribution Caveat Banner */}
      <div className="p-3.5 rounded-lg bg-amber-950/20 border border-amber-500/30 text-amber-200/90 text-xs flex items-start gap-3">
        <span className="text-base shrink-0">⚠️</span>
        <div className="leading-relaxed">
          <strong className="font-semibold text-amber-300 uppercase tracking-wide mr-1">
            Non-Attribution Notice:
          </strong>
          SnareSight deception telemetry reflects adversary reconnaissance and interaction against isolated decoy assets.
          ATT&CK classifications document observed tradecraft, tactics, and procedural patterns. They do not assert confirmed human actor identity, state sponsorship, or compromise of internal production assets.
        </div>
      </div>

      {/* Notifications / Errors */}
      {errorMessage && (
        <div className="p-3 bg-rose-950/40 border border-rose-500/40 rounded-lg text-rose-300 text-xs flex items-center justify-between">
          <span>{errorMessage}</span>
          <button onClick={() => setErrorMessage(null)} className="text-rose-400 hover:text-rose-200">✕</button>
        </div>
      )}
      {notification && (
        <div className="p-3 bg-emerald-950/40 border border-emerald-500/40 rounded-lg text-emerald-300 text-xs flex items-center justify-between">
          <span>{notification}</span>
          <button onClick={() => setNotification(null)} className="text-emerald-400 hover:text-emerald-200">✕</button>
        </div>
      )}

      {/* 3. Executive KPI Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-between">
          <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">Catalogue Techniques</div>
          <div className="mt-2 text-2xl font-bold font-mono text-slate-100">
            {summary?.total_catalogue_techniques ?? '...'}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">
            + {summary?.total_catalogue_subtechniques ?? 0} sub-techniques
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-between">
          <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">Rule-Mapped Techniques</div>
          <div className="mt-2 text-2xl font-bold font-mono text-blue-400">
            {summary?.mapped_techniques_count ?? '...'}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">
            Configured in detection registry
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-between">
          <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">Alert Evidence Supported</div>
          <div className="mt-2 text-2xl font-bold font-mono text-emerald-400">
            {summary?.supported_by_alerts_count ?? '...'}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">
            Live observed honeypot alerts
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-between">
          <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">Pending Analyst Review</div>
          <div className="mt-2 text-2xl font-bold font-mono text-amber-400">
            {summary?.pending_analyst_review_count ?? '0'}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">
            Requires analyst triage
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-between">
          <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">Detection Rules Mapped</div>
          <div className="mt-2 text-2xl font-bold font-mono text-indigo-400">
            {summary?.active_detection_rules_mapped ?? '...'}
            <span className="text-sm font-normal text-slate-500 ml-1">
              / {summary?.total_active_detection_rules ?? '...'}
            </span>
          </div>
          <div className="text-[10px] text-slate-500 mt-1">
            {summary?.unmapped_detection_rules_count ?? 0} unmapped rules
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-between">
          <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">Catalogue Coverage</div>
          <div className="mt-2 text-2xl font-bold font-mono text-teal-400">
            {summary ? `${summary.coverage_percentage.toFixed(1)}%` : '...'}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">
            Enterprise techniques covered
          </div>
        </div>
      </div>

      {/* 4. Tab Navigation */}
      <div className="flex border-b border-slate-800 gap-2">
        <button
          onClick={() => switchTab('matrix')}
          className={`pb-3 px-4 text-xs font-semibold uppercase tracking-wider border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === 'matrix'
              ? 'border-emerald-500 text-emerald-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <span>🎯</span> ATT&CK Matrix
        </button>

        <button
          onClick={() => switchTab('tactics')}
          className={`pb-3 px-4 text-xs font-semibold uppercase tracking-wider border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === 'tactics'
              ? 'border-emerald-500 text-emerald-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <span>📑</span> Canonical Tactics
        </button>

        <button
          onClick={() => switchTab('explorer')}
          className={`pb-3 px-4 text-xs font-semibold uppercase tracking-wider border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === 'explorer'
              ? 'border-emerald-500 text-emerald-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <span>🔍</span> Technique Explorer
        </button>

        <button
          onClick={() => switchTab('coverage')}
          className={`pb-3 px-4 text-xs font-semibold uppercase tracking-wider border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === 'coverage'
              ? 'border-emerald-500 text-emerald-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <span>📊</span> Coverage Analytics
        </button>

        <button
          onClick={() => switchTab('traceability')}
          className={`pb-3 px-4 text-xs font-semibold uppercase tracking-wider border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === 'traceability'
              ? 'border-emerald-500 text-emerald-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <span>🔗</span> Detection Traceability
        </button>
      </div>

      {/* ==================================================================== */}
      {/* TAB 1: ATT&CK MATRIX VIEW */}
      {/* ==================================================================== */}
      {activeTab === 'matrix' && (
        <div className="space-y-4">
          {/* Matrix Filter Bar & Legend */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
            {/* Filters */}
            <div className="flex flex-wrap items-center gap-3">
              <input
                type="text"
                placeholder="Search technique ID or name..."
                value={matrixSearch}
                onChange={(e) => setMatrixSearch(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && loadMatrixData()}
                className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-slate-700 w-64"
              />

              <select
                value={matrixFilterStatus}
                onChange={(e) => {
                  setMatrixFilterStatus(e.target.value);
                  setTimeout(loadMatrixData, 10);
                }}
                className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-slate-700"
              >
                <option value="ALL">All Mapping States</option>
                <option value="ALERT_EVIDENCE">Alert Evidence Observed</option>
                <option value="RULE_MAPPED">Rule Mapped (No Alerts)</option>
                <option value="REVIEW_REQUIRED">Review Required</option>
                <option value="UNMAPPED">Unmapped Only</option>
              </select>

              <button
                onClick={loadMatrixData}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 transition-colors"
              >
                Apply Filters
              </button>
            </div>

            {/* Visual State Legend */}
            <div className="flex items-center gap-3 text-xs">
              <span className="text-slate-500 font-mono text-[10px] uppercase">Legend:</span>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
                <span className="text-emerald-300 text-[11px]">Alert Evidence</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-blue-400"></span>
                <span className="text-blue-300 text-[11px]">Rule Mapped</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-400"></span>
                <span className="text-amber-300 text-[11px]">Review Needed</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-slate-600"></span>
                <span className="text-slate-400 text-[11px]">Unmapped</span>
              </div>
            </div>
          </div>

          {/* Matrix Columns Container */}
          {loadingMatrix ? (
            <div className="p-12 text-center text-slate-500 text-xs">Loading ATT&CK Matrix...</div>
          ) : !matrixData || matrixData.columns.length === 0 ? (
            <div className="p-12 text-center text-slate-500 text-xs">No techniques matched the filters.</div>
          ) : (
            <div className="overflow-x-auto pb-4">
              <div className="flex gap-3 min-w-[2800px]">
                {matrixData.columns.map((col) => (
                  <div
                    key={col.tactic_id}
                    className="w-[200px] shrink-0 flex flex-col rounded-xl bg-slate-900 border border-slate-800 overflow-hidden"
                  >
                    {/* Column Header */}
                    <div className="p-3 bg-slate-950/80 border-b border-slate-800">
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-[10px] text-slate-500">{col.tactic_id}</span>
                        <span className="text-[10px] font-bold text-slate-400 bg-slate-900 px-1.5 py-0.5 rounded">
                          {col.mapped_techniques_count}/{col.total_techniques}
                        </span>
                      </div>
                      <div className="font-bold text-xs text-slate-200 mt-1 truncate" title={col.tactic_name}>
                        {col.tactic_name}
                      </div>
                    </div>

                    {/* Technique Cells List */}
                    <div className="p-2 space-y-2 max-h-[700px] overflow-y-auto">
                      {col.techniques.map((tech) => {
                        let borderClass = 'border-slate-800/80 hover:border-slate-700 bg-slate-950/40';
                        if (tech.visual_state === 'ALERT_EVIDENCE') {
                          borderClass = 'border-emerald-500/50 hover:border-emerald-400 bg-emerald-950/30';
                        } else if (tech.visual_state === 'RULE_MAPPED') {
                          borderClass = 'border-blue-500/40 hover:border-blue-400 bg-blue-950/30';
                        } else if (tech.visual_state === 'REVIEW_REQUIRED') {
                          borderClass = 'border-amber-500/40 hover:border-amber-400 bg-amber-950/30';
                        }

                        return (
                          <div
                            key={tech.technique_id}
                            onClick={() => openTechnique(tech.technique_id)}
                            className={`p-2.5 rounded-lg border text-xs cursor-pointer transition-all ${borderClass}`}
                          >
                            <div className="flex items-center justify-between gap-1">
                              <span className="font-mono text-[11px] font-semibold text-slate-300">
                                {tech.technique_id}
                              </span>
                              {tech.alert_evidence_count > 0 && (
                                <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-emerald-500 text-slate-950">
                                  {tech.alert_evidence_count}
                                </span>
                              )}
                            </div>
                            <div className="text-[11px] font-medium text-slate-300 mt-1 line-clamp-2 leading-tight">
                              {tech.technique_name}
                            </div>
                            <div className="mt-2 flex items-center justify-between text-[10px] text-slate-500">
                              <span>
                                {tech.subtechnique_count > 0 ? `${tech.subtechnique_count} subs` : ''}
                              </span>
                              <span>{renderVisualStateBadge(tech.visual_state)}</span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 2: CANONICAL TACTICS OVERVIEW */}
      {/* ==================================================================== */}
      {activeTab === 'tactics' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
              Enterprise ATT&CK Canonical Tactics (14 Phases)
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Ordered according to the official MITRE Enterprise ATT&CK matrix progression from Reconnaissance to Impact.
            </p>
          </div>

          <div className="overflow-x-auto rounded-xl bg-slate-900 border border-slate-800">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 font-mono text-[11px] uppercase">
                <tr>
                  <th className="py-3 px-4">Order</th>
                  <th className="py-3 px-4">Tactic ID</th>
                  <th className="py-3 px-4">Tactic Name</th>
                  <th className="py-3 px-4">Short Name</th>
                  <th className="py-3 px-4 text-right">Total Techniques</th>
                  <th className="py-3 px-4 text-right">Mapped Techniques</th>
                  <th className="py-3 px-4 text-right">Supporting Rules</th>
                  <th className="py-3 px-4 text-right">Live Alerts</th>
                  <th className="py-3 px-4 text-right">Coverage %</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-300">
                {tacticsOverview.map((tac) => (
                  <tr key={tac.tactic_id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-4 font-mono text-slate-500">{tac.display_order}</td>
                    <td className="py-3 px-4 font-mono font-semibold text-emerald-400">{tac.tactic_id}</td>
                    <td className="py-3 px-4 font-medium text-slate-100">{tac.tactic_name}</td>
                    <td className="py-3 px-4 font-mono text-slate-400">{tac.short_name}</td>
                    <td className="py-3 px-4 text-right font-mono text-slate-300">{tac.total_techniques}</td>
                    <td className="py-3 px-4 text-right font-mono font-semibold text-blue-400">
                      {tac.mapped_techniques_count}
                    </td>
                    <td className="py-3 px-4 text-right font-mono text-indigo-400">
                      {tac.supporting_rules_count}
                    </td>
                    <td className="py-3 px-4 text-right font-mono">
                      {tac.active_alerts_count > 0 ? (
                        <span className="px-2 py-0.5 rounded bg-emerald-950 border border-emerald-500/40 text-emerald-400 font-bold">
                          {tac.active_alerts_count}
                        </span>
                      ) : (
                        <span className="text-slate-600">0</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right font-mono">
                      <span className={tac.coverage_percentage > 0 ? 'text-teal-400 font-semibold' : 'text-slate-600'}>
                        {tac.coverage_percentage.toFixed(1)}%
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 3: TECHNIQUE EXPLORER */}
      {/* ==================================================================== */}
      {activeTab === 'explorer' && (
        <div className="space-y-4">
          {/* Search & Filter Header */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-3">
              <input
                type="text"
                placeholder="Search technique ID, name, description..."
                value={explorerSearch}
                onChange={(e) => setExplorerSearch(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    setExplorerPage(1);
                    loadExplorerData();
                  }
                }}
                className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-slate-700 w-80"
              />

              <select
                value={explorerStatus}
                onChange={(e) => {
                  setExplorerStatus(e.target.value);
                  setExplorerPage(1);
                  setTimeout(loadExplorerData, 10);
                }}
                className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none"
              >
                <option value="ALL">All Mapping States</option>
                <option value="ALERT_EVIDENCE">Alert Evidence Observed</option>
                <option value="RULE_MAPPED">Rule Mapped (No Alerts)</option>
                <option value="REVIEW_REQUIRED">Review Required</option>
                <option value="UNMAPPED">Unmapped Only</option>
              </select>

              <button
                onClick={() => {
                  setExplorerPage(1);
                  loadExplorerData();
                }}
                className="px-3.5 py-1.5 rounded-lg bg-emerald-600/30 text-emerald-300 border border-emerald-500/40 text-xs font-semibold hover:bg-emerald-600/40"
              >
                Search
              </button>
            </div>

            <div className="text-xs text-slate-400 font-mono">
              Total Techniques: <span className="font-semibold text-slate-200">{explorerData?.total ?? 0}</span>
            </div>
          </div>

          {/* Explorer Table */}
          <div className="overflow-x-auto rounded-xl bg-slate-900 border border-slate-800">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 font-mono text-[11px] uppercase">
                <tr>
                  <th className="py-3 px-4">Technique ID</th>
                  <th className="py-3 px-4">Name</th>
                  <th className="py-3 px-4">Primary Tactic</th>
                  <th className="py-3 px-4">Platforms</th>
                  <th className="py-3 px-4">Visual State</th>
                  <th className="py-3 px-4 text-right">Rules</th>
                  <th className="py-3 px-4 text-right">Alerts</th>
                  <th className="py-3 px-4 text-center">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-300">
                {loadingExplorer ? (
                  <tr>
                    <td colSpan={8} className="py-12 text-center text-slate-500">
                      Loading techniques...
                    </td>
                  </tr>
                ) : !explorerData || explorerData.items.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="py-12 text-center text-slate-500">
                      No techniques found matching query.
                    </td>
                  </tr>
                ) : (
                  explorerData.items.map((tech) => (
                    <tr key={tech.technique_id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4 font-mono font-semibold text-emerald-400">
                        {tech.technique_id}
                        {tech.is_subtechnique && (
                          <span className="ml-1 text-[9px] uppercase px-1 py-0.2 rounded bg-slate-800 text-slate-400">
                            sub
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 font-medium text-slate-200 max-w-xs truncate" title={tech.technique_name}>
                        {tech.technique_name}
                      </td>
                      <td className="py-3 px-4 text-slate-400">
                        <span className="font-mono text-[11px] text-slate-500 mr-1">{tech.primary_tactic_id}</span>
                        {tech.primary_tactic_name}
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px]">
                        {tech.platforms.slice(0, 3).join(', ')}
                        {tech.platforms.length > 3 ? ` +${tech.platforms.length - 3}` : ''}
                      </td>
                      <td className="py-3 px-4">{renderVisualStateBadge(tech.visual_state)}</td>
                      <td className="py-3 px-4 text-right font-mono text-blue-400">
                        {tech.mapped_rules_count}
                      </td>
                      <td className="py-3 px-4 text-right font-mono">
                        {tech.supporting_alerts_count > 0 ? (
                          <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-500/40 font-bold">
                            {tech.supporting_alerts_count}
                          </span>
                        ) : (
                          <span className="text-slate-600">0</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-center">
                        <button
                          onClick={() => openTechnique(tech.technique_id)}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-medium"
                        >
                          View Details
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination Controls */}
          {explorerData && explorerData.pages > 1 && (
            <div className="flex items-center justify-between px-4 py-3 bg-slate-900 border border-slate-800 rounded-xl text-xs">
              <span className="text-slate-400">
                Page <strong className="text-slate-200">{explorerData.page}</strong> of{' '}
                <strong className="text-slate-200">{explorerData.pages}</strong>
              </span>
              <div className="flex items-center gap-2">
                <button
                  disabled={explorerPage <= 1}
                  onClick={() => {
                    setExplorerPage((p) => Math.max(1, p - 1));
                    setTimeout(loadExplorerData, 10);
                  }}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-40"
                >
                  Previous
                </button>
                <button
                  disabled={explorerPage >= explorerData.pages}
                  onClick={() => {
                    setExplorerPage((p) => p + 1);
                    setTimeout(loadExplorerData, 10);
                  }}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-40"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 4: COVERAGE ANALYTICS */}
      {/* ==================================================================== */}
      {activeTab === 'coverage' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Rule-Based Catalogue Coverage
              </h3>
              <div className="flex items-baseline justify-between">
                <span className="text-3xl font-bold font-mono text-blue-400">
                  {coverageData?.overall_rule_coverage_pct.toFixed(2) ?? '...'}%
                </span>
                <span className="text-xs text-slate-400 font-mono">
                  {coverageData?.techniques_with_rule_coverage ?? 0} / {coverageData?.total_catalogue_techniques ?? 0} techniques
                </span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-blue-500 rounded-full"
                  style={{ width: `${coverageData?.overall_rule_coverage_pct ?? 0}%` }}
                />
              </div>
              <p className="text-[11px] text-slate-500">
                Proportion of Enterprise ATT&CK techniques with at least one active SnareSight detection rule mapping.
              </p>
            </div>

            <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Alert Evidence-Supported Coverage
              </h3>
              <div className="flex items-baseline justify-between">
                <span className="text-3xl font-bold font-mono text-emerald-400">
                  {coverageData?.overall_alert_coverage_pct.toFixed(2) ?? '...'}%
                </span>
                <span className="text-xs text-slate-400 font-mono">
                  {coverageData?.techniques_with_alert_evidence ?? 0} / {coverageData?.total_catalogue_techniques ?? 0} techniques
                </span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-emerald-500 rounded-full"
                  style={{ width: `${coverageData?.overall_alert_coverage_pct ?? 0}%` }}
                />
              </div>
              <p className="text-[11px] text-slate-500">
                Proportion of Enterprise ATT&CK techniques validated by at least one live honeypot alert observation.
              </p>
            </div>
          </div>

          {/* Tactic-by-Tactic Breakdown Table */}
          <div className="overflow-x-auto rounded-xl bg-slate-900 border border-slate-800">
            <div className="p-4 border-b border-slate-800">
              <h3 className="text-sm font-semibold text-slate-200">Coverage Breakdown by Enterprise Tactic</h3>
            </div>
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 font-mono text-[11px] uppercase">
                <tr>
                  <th className="py-3 px-4">Tactic ID</th>
                  <th className="py-3 px-4">Tactic Name</th>
                  <th className="py-3 px-4 text-right">Total Techniques</th>
                  <th className="py-3 px-4 text-right">Rule Mapped</th>
                  <th className="py-3 px-4 text-right">Alert Evidence</th>
                  <th className="py-3 px-4 text-right">Rule Coverage %</th>
                  <th className="py-3 px-4 text-right">Alert Coverage %</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-300">
                {coverageData?.tactic_coverage.map((tac) => (
                  <tr key={tac.tactic_id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-4 font-mono font-semibold text-emerald-400">{tac.tactic_id}</td>
                    <td className="py-3 px-4 font-medium text-slate-100">{tac.tactic_name}</td>
                    <td className="py-3 px-4 text-right font-mono text-slate-400">{tac.total_techniques}</td>
                    <td className="py-3 px-4 text-right font-mono text-blue-400 font-semibold">
                      {tac.rule_mapped_techniques}
                    </td>
                    <td className="py-3 px-4 text-right font-mono text-emerald-400 font-semibold">
                      {tac.alert_supported_techniques}
                    </td>
                    <td className="py-3 px-4 text-right font-mono">
                      <span className={tac.rule_coverage_pct > 0 ? 'text-blue-400 font-bold' : 'text-slate-600'}>
                        {tac.rule_coverage_pct.toFixed(1)}%
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right font-mono">
                      <span className={tac.alert_coverage_pct > 0 ? 'text-emerald-400 font-bold' : 'text-slate-600'}>
                        {tac.alert_coverage_pct.toFixed(1)}%
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 5: DETECTION RULE TRACEABILITY */}
      {/* ==================================================================== */}
      {activeTab === 'traceability' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
                End-to-End Detection Rule Traceability
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Full audit ladder: Technique → Mapping Definition → Detection Rule → Live Alert Evidence → Session Navigation.
              </p>
            </div>
            <div className="text-xs font-mono text-slate-400">
              Total Chains: <strong className="text-slate-200">{traceabilityData?.total_traces ?? 0}</strong>
            </div>
          </div>

          <div className="overflow-x-auto rounded-xl bg-slate-900 border border-slate-800">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 font-mono text-[11px] uppercase">
                <tr>
                  <th className="py-3 px-4">Technique</th>
                  <th className="py-3 px-4">Category</th>
                  <th className="py-3 px-4">Detection Rule</th>
                  <th className="py-3 px-4">Rule Version</th>
                  <th className="py-3 px-4">Supporting Alert</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Observed Event / Session</th>
                  <th className="py-3 px-4 text-center">Investigation Link</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-300">
                {loadingTraceability ? (
                  <tr>
                    <td colSpan={8} className="py-12 text-center text-slate-500">
                      Loading traceability traces...
                    </td>
                  </tr>
                ) : !traceabilityData || traceabilityData.traces.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="py-12 text-center text-slate-500">
                      No active traceability traces found.
                    </td>
                  </tr>
                ) : (
                  traceabilityData.traces.map((trace, idx) => (
                    <tr key={`${trace.mapping_id}-${idx}`} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4">
                        <span
                          onClick={() => openTechnique(trace.technique_id)}
                          className="font-mono font-semibold text-emerald-400 cursor-pointer hover:underline"
                        >
                          {trace.technique_id}
                        </span>
                        <div className="text-[11px] text-slate-400 truncate max-w-[180px]">
                          {trace.technique_name}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded text-[10px] uppercase font-mono bg-slate-800 text-slate-300">
                          {trace.mapping_category.replace(/_/g, ' ')}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono font-semibold text-blue-300">
                        {trace.rule_id}
                        <div className="text-[11px] font-normal text-slate-400 font-sans">
                          {trace.rule_name}
                        </div>
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-400">{trace.rule_version}</td>
                      <td className="py-3 px-4">
                        {trace.alert_id ? (
                          <div>
                            <span className="font-mono text-amber-400 text-[11px]">
                              {trace.alert_id.slice(0, 8)}...
                            </span>
                            <div className="text-[11px] text-slate-400 truncate max-w-[160px]">
                              {trace.alert_title}
                            </div>
                          </div>
                        ) : (
                          <span className="text-slate-600 text-[11px] italic">No active alert</span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        {trace.severity ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-950/80 text-rose-400 border border-rose-500/30">
                            {trace.severity}
                          </span>
                        ) : (
                          <span className="text-slate-600">-</span>
                        )}
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-slate-400">
                        {trace.session_id ? (
                          <div>
                            <span>Session: {trace.session_id.slice(0, 8)}...</span>
                            {trace.event_id && <div className="text-[10px] text-slate-500">Event: {trace.event_id.slice(0, 8)}...</div>}
                          </div>
                        ) : (
                          <span className="text-slate-600">-</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-center">
                        <button
                          onClick={() => navigate(trace.navigation_url)}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-medium"
                        >
                          Navigate ↗
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* TECHNIQUE DETAIL DRAWER / MODAL */}
      {/* ==================================================================== */}
      {selectedTechniqueId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="w-full max-w-4xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
            {/* Modal Header */}
            <div className="p-5 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-base font-bold text-emerald-400">
                    {techniqueDetail?.technique_id || selectedTechniqueId}
                  </span>
                  {techniqueDetail?.is_subtechnique && (
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-slate-300">
                      Sub-technique of {techniqueDetail.parent_technique_id}
                    </span>
                  )}
                </div>
                <h2 className="text-lg font-bold text-slate-100 mt-1">
                  {techniqueDetail?.technique_name || 'Loading technique details...'}
                </h2>
              </div>
              <button
                onClick={closeTechnique}
                className="w-8 h-8 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 flex items-center justify-center text-sm"
              >
                ✕
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-6 space-y-6 overflow-y-auto">
              {loadingDetail ? (
                <div className="py-12 text-center text-slate-500 text-xs">Loading detail records...</div>
              ) : techniqueDetail ? (
                <>
                  {/* ATT&CK Taxonomy Attributes */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
                      <div className="text-[10px] font-mono uppercase text-slate-500">Tactics</div>
                      <div className="mt-1 flex flex-wrap gap-1">
                        {techniqueDetail.tactics.map((t) => (
                          <span
                            key={t.tactic_id}
                            className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-xs font-mono"
                          >
                            {t.tactic_id}: {t.tactic_name}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
                      <div className="text-[10px] font-mono uppercase text-slate-500">Platforms</div>
                      <div className="mt-1 text-xs text-slate-300 font-mono">
                        {techniqueDetail.platforms.join(', ') || 'N/A'}
                      </div>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
                      <div className="text-[10px] font-mono uppercase text-slate-500">Data Sources</div>
                      <div className="mt-1 text-xs text-slate-300 font-mono truncate">
                        {techniqueDetail.data_sources.slice(0, 3).join(', ') || 'N/A'}
                      </div>
                    </div>
                  </div>

                  {/* Description */}
                  <div>
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Description</h4>
                    <p className="mt-1.5 text-xs text-slate-300 leading-relaxed max-h-36 overflow-y-auto p-3 bg-slate-950/40 rounded-lg border border-slate-800">
                      {techniqueDetail.description || 'No description provided in catalogue.'}
                    </p>
                  </div>

                  {/* Subtechniques */}
                  {techniqueDetail.subtechniques.length > 0 && (
                    <div>
                      <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                        Sub-techniques ({techniqueDetail.subtechniques.length})
                      </h4>
                      <div className="mt-2 flex flex-wrap gap-2">
                        {techniqueDetail.subtechniques.map((sub) => (
                          <button
                            key={sub.subtechnique_id}
                            onClick={() => openTechnique(sub.subtechnique_id)}
                            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono flex items-center gap-1.5"
                          >
                            <span className="text-emerald-400">{sub.subtechnique_id}</span>
                            <span>{sub.subtechnique_name}</span>
                          </button>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* SnareSight Configured Detection Mappings */}
                  <div>
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-blue-400 flex items-center justify-between">
                      <span>SnareSight Detection Mappings ({techniqueDetail.configured_mappings.length})</span>
                      <span className="text-[10px] font-mono text-slate-500">Detection Registry v1.0</span>
                    </h4>
                    {techniqueDetail.configured_mappings.length === 0 ? (
                      <p className="mt-2 text-xs text-slate-500 italic p-3 bg-slate-950/30 rounded-lg border border-slate-800">
                        No SnareSight detection rules are currently configured for this technique.
                      </p>
                    ) : (
                      <div className="mt-2 space-y-2">
                        {techniqueDetail.configured_mappings.map((m) => (
                          <div
                            key={m.mapping_definition_id}
                            className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between"
                          >
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="font-mono text-xs font-bold text-blue-300">{m.rule_id}</span>
                                <span className="text-xs text-slate-200 font-semibold">{m.rule_name}</span>
                                <span className="text-[10px] font-mono text-slate-500">({m.rule_version})</span>
                              </div>
                              <p className="text-xs text-slate-400 mt-1">{m.mapping_rationale}</p>
                            </div>
                            <div className="flex items-center gap-3 shrink-0 ml-4">
                              <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-slate-800 text-slate-300">
                                {m.mapping_category}
                              </span>
                              <span className="font-mono text-xs font-bold text-emerald-400">
                                {m.default_confidence}% Conf
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Live Supporting Alert Evidence */}
                  <div>
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-emerald-400">
                      Live Supporting Alert & Event Evidence ({techniqueDetail.live_evidence.length})
                    </h4>
                    {techniqueDetail.live_evidence.length === 0 ? (
                      <p className="mt-2 text-xs text-slate-500 italic p-3 bg-slate-950/30 rounded-lg border border-slate-800">
                        No live honeypot alerts have currently mapped to this technique.
                      </p>
                    ) : (
                      <div className="mt-2 space-y-2">
                        {techniqueDetail.live_evidence.map((ev) => (
                          <div
                            key={ev.mapping_id}
                            className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3"
                          >
                            <div className="space-y-1">
                              <div className="flex items-center gap-2">
                                <span className="font-mono text-xs font-bold text-amber-400">
                                  {ev.alert_id ? `Alert: ${ev.alert_id.slice(0, 8)}...` : 'Alert Evidence'}
                                </span>
                                <span className="font-mono text-xs text-blue-400">{ev.detection_rule_id}</span>
                                <span className="px-1.5 py-0.2 rounded text-[10px] uppercase font-mono bg-slate-800 text-slate-300">
                                  {ev.review_status}
                                </span>
                              </div>
                              <p className="text-xs text-slate-300">{ev.evidence_summary}</p>
                              <div className="flex items-center gap-3 text-[11px] font-mono text-slate-500">
                                {ev.session_id && <span>Session: {ev.session_id.slice(0, 8)}...</span>}
                                {ev.event_id && <span>Event: {ev.event_id.slice(0, 8)}...</span>}
                                <span>{new Date(ev.recorded_at).toLocaleString()}</span>
                              </div>
                            </div>

                            <div className="flex items-center gap-2 shrink-0">
                              {ev.alert_navigation_url && (
                                <button
                                  onClick={() => navigate(ev.alert_navigation_url!)}
                                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium"
                                >
                                  View Alert ↗
                                </button>
                              )}
                              <button
                                onClick={() => openReviewModal(ev.mapping_id, 'APPROVE')}
                                className="px-2.5 py-1 rounded bg-emerald-600/30 hover:bg-emerald-600/40 text-emerald-300 border border-emerald-500/30 text-xs font-medium"
                              >
                                Triage Review
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Caveat Footer */}
                  <div className="p-3 rounded-lg bg-slate-950 text-[11px] text-slate-400 border border-slate-800 leading-relaxed">
                    <strong className="text-slate-300">Analysis Caveat: </strong>
                    {techniqueDetail.non_attribution_caveat}
                  </div>
                </>
              ) : null}
            </div>

            {/* Modal Footer */}
            <div className="p-4 bg-slate-950 border-t border-slate-800 flex justify-end">
              <button
                onClick={closeTechnique}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold"
              >
                Close Drawer
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* ANALYST REVIEW MODAL */}
      {/* ==================================================================== */}
      {reviewModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6 space-y-4">
            <div>
              <h3 className="text-base font-bold text-slate-100">Analyst Mapping Review</h3>
              <p className="text-xs text-slate-400 mt-1">
                Record a verified review decision into the mapping audit history log.
              </p>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 font-mono text-[10px] uppercase mb-1">Decision Action</label>
                <div className="grid grid-cols-3 gap-2">
                  <button
                    type="button"
                    onClick={() => setReviewAction('APPROVE')}
                    className={`py-1.5 rounded-lg font-semibold border ${
                      reviewAction === 'APPROVE'
                        ? 'bg-emerald-950 text-emerald-400 border-emerald-500'
                        : 'bg-slate-950 text-slate-400 border-slate-800'
                    }`}
                  >
                    Approve
                  </button>
                  <button
                    type="button"
                    onClick={() => setReviewAction('REJECT')}
                    className={`py-1.5 rounded-lg font-semibold border ${
                      reviewAction === 'REJECT'
                        ? 'bg-rose-950 text-rose-400 border-rose-500'
                        : 'bg-slate-950 text-slate-400 border-slate-800'
                    }`}
                  >
                    Reject
                  </button>
                  <button
                    type="button"
                    onClick={() => setReviewAction('REQUEST_REVIEW')}
                    className={`py-1.5 rounded-lg font-semibold border ${
                      reviewAction === 'REQUEST_REVIEW'
                        ? 'bg-amber-950 text-amber-400 border-amber-500'
                        : 'bg-slate-950 text-slate-400 border-slate-800'
                    }`}
                  >
                    Need Evidence
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-slate-400 font-mono text-[10px] uppercase mb-1">Analyst ID</label>
                <input
                  type="text"
                  value={reviewAnalystId}
                  onChange={(e) => setReviewAnalystId(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200"
                />
              </div>

              <div>
                <label className="block text-slate-400 font-mono text-[10px] uppercase mb-1">Review Comments</label>
                <textarea
                  rows={3}
                  value={reviewComment}
                  onChange={(e) => setReviewComment(e.target.value)}
                  placeholder="Justification for decision and supporting observations..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-slate-700"
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                disabled={submittingReview}
                onClick={() => setReviewModalOpen(false)}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold"
              >
                Cancel
              </button>
              <button
                disabled={submittingReview}
                onClick={submitReviewAction}
                className="px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 text-xs font-bold disabled:opacity-50"
              >
                {submittingReview ? 'Submitting...' : 'Submit Decision'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default MitreAttackDashboardPage;

