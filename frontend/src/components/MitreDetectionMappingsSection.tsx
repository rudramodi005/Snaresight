import React, { useState, useEffect } from 'react';
import { DetectionMapping } from '../types/mitre';
import { mitreApi } from '../services/mitreApi';
import { MitreMappingDetails } from './MitreMappingDetails';
import { MitreAnalystReviewModal } from './MitreAnalystReviewModal';

interface MitreDetectionMappingsSectionProps {
  detectionId: string;
}

export const MitreDetectionMappingsSection: React.FC<MitreDetectionMappingsSectionProps> = ({
  detectionId,
}) => {
  const [mappings, setMappings] = useState<DetectionMapping[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedMapping, setSelectedMapping] = useState<DetectionMapping | null>(null);
  const [reviewMapping, setReviewMapping] = useState<DetectionMapping | null>(null);

  const fetchMappings = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await mitreApi.getMappingsForDetection(detectionId);
      setMappings(data);
      if (data.length > 0 && !selectedMapping) {
        setSelectedMapping(data[0]);
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to fetch ATT&CK mappings.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (detectionId) {
      fetchMappings();
    }
  }, [detectionId]);

  const handleReviewSubmit = async (mappingId: string, action: any, comment: string) => {
    await mitreApi.submitReview(mappingId, { action, comment }, 'snaresight_analyst_token_2026');
    await fetchMappings();
  };

  if (loading) {
    return (
      <div className="p-6 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-400 animate-pulse">
        Loading associated MITRE ATT&CK techniques...
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-4 bg-rose-950/40 border border-rose-800/80 rounded-lg text-xs text-rose-300">
        {error}
      </div>
    );
  }

  if (mappings.length === 0) {
    return (
      <div className="p-6 bg-slate-900/60 border border-slate-800/60 rounded-lg text-center space-y-2">
        <h4 className="text-sm font-semibold text-slate-300">No ATT&CK Techniques Mapped</h4>
        <p className="text-xs text-slate-500 max-w-md mx-auto">
          The telemetry observed for this detection does not satisfy the conservative evidential criteria
          for an official MITRE ATT&CK Enterprise technique.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
        <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider">
          Associated MITRE ATT&CK Techniques ({mappings.length})
        </h3>
        <span className="text-xs text-slate-400">
          Curated Evidence-Based Mappings
        </span>
      </div>

      {/* Technique Selection Tabs */}
      <div className="flex flex-wrap gap-2">
        {mappings.map((m) => (
          <button
            key={m.mapping_id}
            onClick={() => setSelectedMapping(m)}
            className={`px-3 py-1.5 text-xs font-mono font-medium rounded border transition-colors ${
              selectedMapping?.mapping_id === m.mapping_id
                ? 'bg-cyan-950 border-cyan-500 text-cyan-300'
                : 'bg-slate-950/40 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
            }`}
          >
            {m.subtechnique_id || m.technique_id} • {m.technique_name}
          </button>
        ))}
      </div>

      {/* Selected Mapping Detail View */}
      {selectedMapping && (
        <MitreMappingDetails
          mapping={selectedMapping}
          onOpenReview={(map) => setReviewMapping(map)}
          canReview={true}
        />
      )}

      {/* Analyst Review Modal */}
      <MitreAnalystReviewModal
        mapping={reviewMapping}
        isOpen={Boolean(reviewMapping)}
        onClose={() => setReviewMapping(null)}
        onSubmit={handleReviewSubmit}
      />
    </div>
  );
};

