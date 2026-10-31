import React, { useState } from 'react';
import { SessionTimeline, TimelineEntry, TimelineEntryType } from '../types/session';

interface SessionTimelineProps {
  timeline: SessionTimeline;
  onSelectDetection?: (detectionId: string) => void;
  onSelectTechnique?: (techniqueId: string) => void;
}

export const SessionTimelineView: React.FC<SessionTimelineProps> = ({
  timeline,
  onSelectDetection,
  onSelectTechnique,
}) => {
  const [expandedEntries, setExpandedEntries] = useState<Record<string, boolean>>({});

  const toggleExpand = (entryId: string) => {
    setExpandedEntries((prev) => ({
      ...prev,
      [entryId]: !prev[entryId],
    }));
  };

  const getEntryBadge = (entryType: TimelineEntryType, severity?: string | null) => {
    if (entryType === 'DETECTION_GENERATED') {
      const sevColor =
        severity === 'CRITICAL'
          ? 'bg-rose-950 border-rose-500 text-rose-300'
          : severity === 'HIGH'
          ? 'bg-orange-950 border-orange-500 text-orange-300'
          : 'bg-amber-950 border-amber-500 text-amber-300';
      return <span className={`px-2 py-0.5 text-xs font-mono font-semibold rounded border ${sevColor}`}>DETECTION</span>;
    }
    if (entryType === 'ATTACK_MAPPING_GENERATED') {
      return <span className="px-2 py-0.5 text-xs font-mono font-semibold rounded border bg-cyan-950 border-cyan-500 text-cyan-300">ATT&CK</span>;
    }
    if (entryType === 'AUTHENTICATION_FAILURE') {
      return <span className="px-2 py-0.5 text-xs font-mono font-semibold rounded border bg-rose-950/60 border-rose-600 text-rose-300">AUTH FAIL</span>;
    }
    if (entryType === 'DECOY_AUTHENTICATION_ACCEPTED') {
      return <span className="px-2 py-0.5 text-xs font-mono font-semibold rounded border bg-amber-950/60 border-amber-500 text-amber-300">DECOY ACCEPT</span>;
    }
    if (entryType === 'DIRECTORY_TRAVERSAL') {
      return <span className="px-2 py-0.5 text-xs font-mono font-semibold rounded border bg-purple-950 border-purple-500 text-purple-300">TRAVERSAL</span>;
    }
    if (entryType === 'CONNECTION_CLOSED') {
      return <span className="px-2 py-0.5 text-xs font-mono font-semibold rounded border bg-slate-800 border-slate-600 text-slate-400">CLOSED</span>;
    }
    return <span className="px-2 py-0.5 text-xs font-mono rounded border bg-slate-800/80 border-slate-700 text-slate-300">EVENT</span>;
  };

  return (
    <div className="space-y-6 text-slate-100">
      {/* Operational Warning Notice */}
      <div className="p-3.5 bg-amber-950/30 border border-amber-600/40 rounded-md text-amber-300 text-xs leading-relaxed">
        <strong>⚠️ OPERATIONAL WARNING:</strong> A correlated activity session is a grouping of observations
        based on available identifiers and correlation policy. It does not establish that every event came from
        the same human, prove malicious intent, or demonstrate completion of an attack.
      </div>

      {/* Timeline Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-3">
        <div>
          <h3 className="text-base font-semibold text-slate-200">
            Investigation Timeline ({timeline.total_entries} entries)
          </h3>
          <p className="text-xs text-slate-400 mt-0.5 font-mono">
            Session: <span className="text-cyan-400">{timeline.session_id}</span> • Decoy: <span className="text-slate-300">{timeline.decoy_id}</span> • Source: <span className="text-slate-300">{timeline.source_address}</span>
          </p>
        </div>
        <div className="text-right text-xs text-slate-400">
          <div>Span: <span className="font-mono text-slate-300">{timeline.first_observed_at.substring(11, 19)}</span> — <span className="font-mono text-slate-300">{timeline.last_activity_at.substring(11, 19)}</span> UTC</div>
        </div>
      </div>

      {/* Vertical Timeline Nodes */}
      <div className="relative pl-6 space-y-4 border-l-2 border-slate-800 ml-3">
        {timeline.entries.map((entry) => {
          const isExpanded = expandedEntries[entry.entry_id];
          return (
            <div key={entry.entry_id} className="relative group">
              {/* Bullet Node */}
              <div
                className={`absolute -left-[31px] top-1.5 w-3.5 h-3.5 rounded-full border-2 ${
                  entry.is_detection
                    ? 'bg-rose-500 border-slate-900'
                    : entry.entry_type === 'ATTACK_MAPPING_GENERATED'
                    ? 'bg-cyan-500 border-slate-900'
                    : 'bg-slate-700 border-slate-900 group-hover:bg-slate-500'
                }`}
              />

              {/* Card Container */}
              <div
                className={`p-3.5 rounded-lg border transition-colors ${
                  entry.is_detection
                    ? 'bg-rose-950/20 border-rose-900/60'
                    : entry.entry_type === 'ATTACK_MAPPING_GENERATED'
                    ? 'bg-cyan-950/20 border-cyan-900/60'
                    : 'bg-slate-900/80 border-slate-800/80 hover:border-slate-700'
                }`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-slate-400">
                      {entry.timestamp.substring(11, 19)} UTC
                    </span>
                    {getEntryBadge(entry.entry_type, entry.severity)}
                    <span className="text-xs font-semibold text-slate-200">
                      {entry.title}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 text-xs">
                    {entry.related_technique_id && onSelectTechnique && (
                      <button
                        onClick={() => onSelectTechnique(entry.related_technique_id!)}
                        className="px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-700 hover:bg-cyan-900"
                      >
                        {entry.related_technique_id}
                      </button>
                    )}
                    {entry.is_late_arrival && (
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-950 text-amber-300 border border-amber-700">
                        LATE ARRIVAL
                      </span>
                    )}
                    <button
                      onClick={() => toggleExpand(entry.entry_id)}
                      className="text-slate-400 hover:text-slate-200 text-xs underline font-mono"
                    >
                      {isExpanded ? 'Less' : 'Details'}
                    </button>
                  </div>
                </div>

                <p className="text-xs text-slate-300 mt-1.5 leading-relaxed">
                  {entry.description}
                </p>

                {/* Expandable Evidence Payload */}
                {isExpanded && (
                  <div className="mt-3 pt-3 border-t border-slate-800/80 space-y-2 text-xs">
                    <div className="text-[11px] text-slate-400 font-mono">
                      Source Record ID: <span className="text-slate-300">{entry.source_record_id}</span>
                      {entry.ingestion_timestamp && (
                        <> • Ingested: <span className="text-slate-300">{entry.ingestion_timestamp}</span></>
                      )}
                    </div>
                    {Object.keys(entry.metadata).length > 0 && (
                      <pre className="bg-slate-950 p-2.5 rounded font-mono text-[11px] text-slate-300 overflow-x-auto border border-slate-800">
                        {JSON.stringify(entry.metadata, null, 2)}
                      </pre>
                    )}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

