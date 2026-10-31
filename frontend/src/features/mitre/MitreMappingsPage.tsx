import React, { useState, useEffect } from 'react';
import { DetectionMapping, MappingStatistics, PaginatedMappings, ReviewAction } from '../../types/mitre';
import { mitreApi } from '../../services/mitreApi';
import { MitreMappingDetails } from '../../components/MitreMappingDetails';
import { MitreAnalystReviewModal } from '../../components/MitreAnalystReviewModal';

export const MitreMappingsPage: React.FC = () => {
  const [paginated, setPaginated] = useState<PaginatedMappings | null>(null);
  const [stats, setStats] = useState<MappingStatistics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedMapping, setSelectedMapping] = useState<DetectionMapping | null>(null);
  const [reviewMapping, setReviewMapping] = useState<DetectionMapping | null>(null);

  // Filter states
  const [filterRule, setFilterRule] = useState('');
  const [filterCategory, setFilterCategory] = useState('');
  const [filterStatus, setFilterStatus] = useState('');

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [mappingData, statsData] = await Promise.all([
        mitreApi.listMappings({
          ruleId: filterRule || undefined,
          category: filterCategory || undefined,
          reviewStatus: filterStatus || undefined,
          pageSize: 25,
        }),
        mitreApi.getMappingStatistics(),
      ]);
      setPaginated(mappingData);
      setStats(statsData);
      if (mappingData.items.length > 0 && !selectedMapping) {
        setSelectedMapping(mappingData.items[0]);
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to load mapping data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [filterRule, filterCategory, filterStatus]);

  const handleReview = async (mappingId: string, action: ReviewAction, comment: string) => {
    await mitreApi.submitReview(mappingId, { action, comment }, 'snaresight_analyst_token_2026');
    await loadData();
    if (selectedMapping && selectedMapping.mapping_id === mappingId) {
      const updated = await mitreApi.getMapping(mappingId);
      setSelectedMapping(updated);
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8 text-slate-100">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-100">
          MITRE ATT&CK Detection Mappings
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Evidence-based associations between SnareSight threat detection findings and MITRE ATT&CK Enterprise techniques.
        </p>
      </div>

      {/* KPI Stats Grid */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
            <span className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Total Mappings</span>
            <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">{stats.total_mappings}</div>
          </div>
          <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
            <span className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Directly Supported</span>
            <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">{stats.directly_supported}</div>
          </div>
          <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
            <span className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Pending Review</span>
            <div className="text-2xl font-bold font-mono text-amber-400 mt-1">{stats.pending_reviews}</div>
          </div>
          <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
            <span className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Accepted Mappings</span>
            <div className="text-2xl font-bold font-mono text-blue-400 mt-1">{stats.accepted_mappings}</div>
          </div>
          <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
            <span className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Unmapped Scenarios</span>
            <div className="text-2xl font-bold font-mono text-slate-500 mt-1">{stats.not_mapped_count}</div>
          </div>
        </div>
      )}

      {/* Filter Controls */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg flex flex-wrap gap-4 items-center">
        <input
          type="text"
          placeholder="Filter by Rule ID (e.g. AUTH-001)..."
          value={filterRule}
          onChange={(e) => setFilterRule(e.target.value)}
          className="bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
        />

        <select
          value={filterCategory}
          onChange={(e) => setFilterCategory(e.target.value)}
          className="bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
        >
          <option value="">All Categories</option>
          <option value="DIRECTLY_SUPPORTED">DIRECTLY_SUPPORTED</option>
          <option value="PARTIALLY_SUPPORTED">PARTIALLY_SUPPORTED</option>
          <option value="REQUIRES_ANALYST_REVIEW">REQUIRES_ANALYST_REVIEW</option>
        </select>

        <select
          value={filterStatus}
          onChange={(e) => setFilterStatus(e.target.value)}
          className="bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
        >
          <option value="">All Review Statuses</option>
          <option value="PENDING">PENDING</option>
          <option value="ACCEPTED">ACCEPTED</option>
          <option value="REJECTED">REJECTED</option>
          <option value="NEEDS_MORE_EVIDENCE">NEEDS_MORE_EVIDENCE</option>
        </select>

        <button
          onClick={loadData}
          className="px-3 py-1.5 text-xs font-medium rounded bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors ml-auto"
        >
          Refresh Mappings
        </button>
      </div>

      {error && (
        <div className="p-4 bg-rose-950/40 border border-rose-800/80 rounded-lg text-xs text-rose-300">
          {error}
        </div>
      )}

      {/* Main Content Layout: Table & Selected Details */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Mappings List */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
          <div className="p-4 border-b border-slate-800">
            <h3 className="text-sm font-semibold text-slate-200">
              Active Findings ({paginated?.total || 0})
            </h3>
          </div>

          {loading ? (
            <div className="p-8 text-center text-xs text-slate-500">Loading mappings...</div>
          ) : paginated?.items.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500">No matching mappings found.</div>
          ) : (
            <div className="divide-y divide-slate-800 max-h-[600px] overflow-y-auto">
              {paginated?.items.map((m) => (
                <div
                  key={m.mapping_id}
                  onClick={() => setSelectedMapping(m)}
                  className={`p-4 cursor-pointer transition-colors ${
                    selectedMapping?.mapping_id === m.mapping_id
                      ? 'bg-cyan-950/40 border-l-4 border-cyan-500'
                      : 'hover:bg-slate-800/50'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="font-mono font-bold text-cyan-400">
                      {m.subtechnique_id || m.technique_id}
                    </span>
                    <span className="text-[11px] text-slate-400 font-mono">
                      {m.rule_id}
                    </span>
                  </div>
                  <div className="text-xs text-slate-200 font-semibold truncate">
                    {m.subtechnique_name || m.technique_name}
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-slate-400 mt-2">
                    <span className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700">
                      {m.mapping_category}
                    </span>
                    <span className="font-mono">
                      Conf: <strong className="text-slate-300">{m.mapping_confidence}%</strong> ({m.mapping_confidence_level})
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Selected Mapping Details Panel */}
        <div>
          {selectedMapping ? (
            <MitreMappingDetails
              mapping={selectedMapping}
              onOpenReview={(map) => setReviewMapping(map)}
              canReview={true}
            />
          ) : (
            <div className="p-12 bg-slate-900 border border-slate-800 rounded-lg text-center text-xs text-slate-500">
              Select a mapping record to inspect evidence and review details.
            </div>
          )}
        </div>
      </div>

      {/* Review Modal */}
      <MitreAnalystReviewModal
        mapping={reviewMapping}
        isOpen={Boolean(reviewMapping)}
        onClose={() => setReviewMapping(null)}
        onSubmit={handleReview}
      />
    </div>
  );
};

