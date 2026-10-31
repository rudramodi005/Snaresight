import React from 'react';
import { DetectionMapping } from '../types/mitre';

interface MitreMappingDetailsProps {
  mapping: DetectionMapping;
  onOpenReview?: (mapping: DetectionMapping) => void;
  canReview?: boolean;
}

export const MitreMappingDetails: React.FC<MitreMappingDetailsProps> = ({
  mapping,
  onOpenReview,
  canReview = true,
}) => {
  const getCategoryBadgeClass = (category: string) => {
    switch (category) {
      case 'DIRECTLY_SUPPORTED':
        return 'badge-success';
      case 'PARTIALLY_SUPPORTED':
        return 'badge-info';
      case 'REQUIRES_ANALYST_REVIEW':
        return 'badge-warning';
      default:
        return 'badge-neutral';
    }
  };

  const getConfidenceLevelClass = (level: string) => {
    switch (level) {
      case 'HIGH':
        return 'text-emerald-400';
      case 'MODERATE':
        return 'text-amber-400';
      case 'LOW':
        return 'text-rose-400';
      default:
        return 'text-gray-400';
    }
  };

  const getStatusBadgeClass = (status: string) => {
    switch (status) {
      case 'ACCEPTED':
        return 'border-emerald-500 text-emerald-400 bg-emerald-950/40';
      case 'REJECTED':
        return 'border-rose-500 text-rose-400 bg-rose-950/40';
      case 'NEEDS_MORE_EVIDENCE':
        return 'border-amber-500 text-amber-400 bg-amber-950/40';
      default:
        return 'border-blue-500 text-blue-400 bg-blue-950/40';
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 space-y-6 text-slate-100">
      {/* Warning Notice */}
      <div className="p-4 bg-amber-950/30 border border-amber-600/40 rounded-md text-amber-300 text-sm">
        <strong>⚠️ OPERATIONAL CAUTION:</strong> An ATT&CK mapping indicates that observed behavior is
        consistent with a documented adversary technique. It does not, by itself, establish attacker identity,
        successful compromise, intent, or completion of an attack.
      </div>

      {/* Header Info */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-3">
            <span className="text-xl font-bold font-mono text-cyan-400">
              {mapping.subtechnique_id || mapping.technique_id}
            </span>
            <span className="text-lg font-semibold text-slate-200">
              {mapping.subtechnique_name || mapping.technique_name}
            </span>
            {mapping.tactic_name && (
              <span className="px-2 py-0.5 text-xs font-mono rounded bg-slate-800 text-slate-400 border border-slate-700">
                {mapping.tactic_name}
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Detection Rule: <span className="font-mono text-slate-300">{mapping.rule_id}</span> (v{mapping.rule_version}) • Dataset: <span className="font-mono text-slate-300">{mapping.dataset_version}</span>
          </p>
        </div>

        <div className="flex items-center gap-3">
          <span className={`px-2.5 py-1 text-xs font-medium rounded-full border ${getStatusBadgeClass(mapping.review_status)}`}>
            {mapping.review_status}
          </span>
          {canReview && onOpenReview && (
            <button
              onClick={() => onOpenReview(mapping)}
              className="px-3 py-1.5 text-xs font-medium rounded bg-cyan-600 hover:bg-cyan-500 text-white transition-colors"
            >
              Analyst Review
            </button>
          )}
        </div>
      </div>

      {/* Confidence & Category Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-slate-950/60 p-4 rounded border border-slate-800 space-y-2">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Mapping Evidential Category
          </span>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded text-xs font-mono font-medium bg-slate-800 text-cyan-300 border border-slate-700">
              {mapping.mapping_category}
            </span>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed pt-1">
            {mapping.mapping_rationale}
          </p>
        </div>

        <div className="bg-slate-950/60 p-4 rounded border border-slate-800 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Mapping Confidence
            </span>
            <span className={`text-sm font-bold font-mono ${getConfidenceLevelClass(mapping.mapping_confidence_level)}`}>
              {mapping.mapping_confidence}% ({mapping.mapping_confidence_level})
            </span>
          </div>
          {/* Progress Bar */}
          <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
            <div
              className={`h-full ${
                mapping.mapping_confidence >= 80
                  ? 'bg-emerald-500'
                  : mapping.mapping_confidence >= 50
                  ? 'bg-amber-500'
                  : 'bg-rose-500'
              }`}
              style={{ width: `${mapping.mapping_confidence}%` }}
            />
          </div>
          <p className="text-xs text-slate-400 leading-relaxed pt-1">
            {mapping.confidence_explanation}
          </p>
        </div>
      </div>

      {/* Supporting Event Evidence */}
      <div className="space-y-3">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          Corroborating Telemetry Evidence ({mapping.evidence.length})
        </h4>

        {mapping.evidence.length === 0 ? (
          <p className="text-xs text-slate-500 italic">No direct raw event records attached.</p>
        ) : (
          <div className="space-y-2">
            {mapping.evidence.map((ev) => (
              <div key={ev.id} className="p-3 bg-slate-950/40 rounded border border-slate-800 text-xs space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-cyan-400">{ev.evidence_type}</span>
                  <span className="text-slate-500 text-[11px] font-mono">{ev.evidence_timestamp}</span>
                </div>
                <p className="text-slate-300">{ev.evidence_description}</p>
                {ev.evidence_fields && (
                  <pre className="bg-slate-900 p-2 rounded text-[11px] text-slate-300 font-mono overflow-x-auto mt-1 border border-slate-800/80">
                    {JSON.stringify(ev.evidence_fields, null, 2)}
                  </pre>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Review Information */}
      {mapping.reviewed_by && (
        <div className="pt-2 border-t border-slate-800 text-xs text-slate-400 flex items-center justify-between">
          <span>
            Reviewed by: <strong className="text-slate-300 font-mono">{mapping.reviewed_by}</strong> on {mapping.reviewed_at}
          </span>
          {mapping.review_comment && (
            <span className="italic text-slate-300">"{mapping.review_comment}"</span>
          )}
        </div>
      )}
    </div>
  );
};

