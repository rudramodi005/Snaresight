import React, { useState } from 'react';
import { SequenceTimelineEntry, SequenceMemberType } from '../types/sequence';

interface SequenceTimelineProps {
  entries: SequenceTimelineEntry[];
  sequenceId: string;
}

export const SequenceTimeline: React.FC<SequenceTimelineProps> = ({ entries, sequenceId }) => {
  const [filterType, setFilterType] = useState<string>('ALL');
  const [expandedEntry, setExpandedEntry] = useState<string | null>(null);

  const filteredEntries = entries.filter((e) => {
    if (filterType === 'ALL') return true;
    return e.member_type === filterType;
  });

  const getSeverityBadge = (sev: string | null) => {
    if (!sev) return null;
    const colors: Record<string, string> = {
      CRITICAL: 'bg-red-900/60 text-red-300 border-red-700',
      HIGH: 'bg-orange-900/60 text-orange-300 border-orange-700',
      MEDIUM: 'bg-amber-900/60 text-amber-300 border-amber-700',
      LOW: 'bg-blue-900/60 text-blue-300 border-blue-700',
      INFO: 'bg-slate-800 text-slate-300 border-slate-700',
    };
    const c = colors[sev.toUpperCase()] || colors.INFO;
    return (
      <span className={`px-2 py-0.5 text-xs font-semibold rounded border ${c}`}>
        {sev}
      </span>
    );
  };

  const getMemberTypePill = (type: SequenceMemberType) => {
    switch (type) {
      case 'SESSION':
        return <span className="px-2 py-0.5 text-xs font-mono rounded bg-cyan-950 text-cyan-300 border border-cyan-800">SESSION</span>;
      case 'DETECTION':
        return <span className="px-2 py-0.5 text-xs font-mono rounded bg-rose-950 text-rose-300 border border-rose-800">DETECTION</span>;
      case 'ATTACK_MAPPING':
        return <span className="px-2 py-0.5 text-xs font-mono rounded bg-purple-950 text-purple-300 border border-purple-800">MITRE ATT&CK</span>;
      default:
        return <span className="px-2 py-0.5 text-xs font-mono rounded bg-slate-800 text-slate-300 border border-slate-700">{type}</span>;
    }
  };

  return (
    <div className="space-y-4">
      {/* Filter Chips */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-1.5 text-xs font-medium text-slate-400">
          <span>Filter:</span>
          {['ALL', 'SESSION', 'DETECTION', 'ATTACK_MAPPING'].map((t) => (
            <button
              key={t}
              onClick={() => setFilterType(t)}
              className={`px-2.5 py-1 rounded transition-colors ${
                filterType === t
                  ? 'bg-cyan-600 text-white font-semibold'
                  : 'bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800'
              }`}
            >
              {t === 'ALL' ? 'All Entries' : t}
            </button>
          ))}
        </div>
        <span className="text-xs text-slate-500">
          Showing {filteredEntries.length} of {entries.length} observations
        </span>
      </div>

      {/* Operational Disclaimer Banner */}
      <div className="p-3 bg-amber-950/20 border border-amber-800/40 rounded text-xs text-amber-200/90 leading-relaxed">
        <strong className="text-amber-300 font-semibold">Sequence Chronology:</strong> Multi-session timeline reflects wall-clock observed activity ordered across decoy instances. Correlation indicates potential behavioral linkage and does not confirm shared human identity.
      </div>

      {/* Timeline Stream */}
      <div className="relative pl-6 space-y-4 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
        {filteredEntries.map((entry) => {
          const isExpanded = expandedEntry === entry.entry_id;
          return (
            <div key={entry.entry_id} className="relative group">
              {/* Timeline Marker Dot */}
              <div
                className={`absolute -left-6 top-1.5 w-3.5 h-3.5 rounded-full border-2 ${
                  entry.member_type === 'DETECTION'
                    ? 'bg-rose-500 border-rose-950 ring-2 ring-rose-500/20'
                    : entry.member_type === 'ATTACK_MAPPING'
                    ? 'bg-purple-500 border-purple-950 ring-2 ring-purple-500/20'
                    : 'bg-cyan-500 border-cyan-950 ring-2 ring-cyan-500/20'
                }`}
              />

              <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-3 hover:border-slate-700 transition-colors">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    {getMemberTypePill(entry.member_type)}
                    <span className="font-semibold text-sm text-slate-200">
                      {entry.title}
                    </span>
                    {getSeverityBadge(entry.severity)}
                  </div>
                  <span className="text-xs font-mono text-slate-500">
                    {entry.timestamp}
                  </span>
                </div>

                <p className="mt-1 text-xs text-slate-400 leading-normal">
                  {entry.description}
                </p>

                {entry.session_id && (
                  <div className="mt-2 flex items-center gap-3 text-xs text-slate-400">
                    <span>
                      Session: <code className="text-cyan-400">{entry.session_id}</code>
                    </span>
                    {entry.decoy_id && (
                      <span>
                        Decoy: <strong className="text-slate-300">{entry.decoy_id}</strong>
                      </span>
                    )}
                    {entry.technique_id && (
                      <span>
                        Technique: <code className="text-purple-400 font-bold">{entry.technique_id}</code>
                      </span>
                    )}
                  </div>
                )}

                {/* Inspect Details Toggle */}
                {entry.details && Object.keys(entry.details).length > 0 && (
                  <div className="mt-2">
                    <button
                      onClick={() => setExpandedEntry(isExpanded ? null : entry.entry_id)}
                      className="text-xs text-cyan-400 hover:text-cyan-300 underline font-mono"
                    >
                      {isExpanded ? 'Hide Details' : 'Inspect Telemetry Details'}
                    </button>
                    {isExpanded && (
                      <pre className="mt-2 p-2 bg-slate-950 rounded text-xs font-mono text-slate-300 border border-slate-800 overflow-x-auto">
                        {JSON.stringify(entry.details, null, 2)}
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

