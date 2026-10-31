import React, { useState } from 'react';
import { SequenceMember, SequenceRelationship } from '../types/sequence';

interface SequenceRelationshipGraphProps {
  members: SequenceMember[];
  relationships: SequenceRelationship[];
  sequenceId: string;
}

export const SequenceRelationshipGraph: React.FC<SequenceRelationshipGraphProps> = ({
  members,
  relationships,
  sequenceId,
}) => {
  const [selectedRelationship, setSelectedRelationship] = useState<SequenceRelationship | null>(null);

  const getMemberById = (id: string) => members.find((m) => m.id === id);

  const getBadgeForType = (type: string) => {
    switch (type) {
      case 'SESSION':
        return 'bg-cyan-950 text-cyan-300 border-cyan-800';
      case 'DETECTION':
        return 'bg-rose-950 text-rose-300 border-rose-800';
      case 'ATTACK_MAPPING':
        return 'bg-purple-950 text-purple-300 border-purple-800';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="space-y-4">
      {/* Topology Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          Behavioral Sequence Topology ({members.length} Nodes, {relationships.length} Edges)
        </h4>
        <span className="text-xs text-slate-500 font-mono">ID: {sequenceId}</span>
      </div>

      {/* Structured Graph Canvas (Node & Edge Matrix) */}
      <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg overflow-x-auto">
        <div className="min-w-[600px] flex items-start gap-8">
          {/* Members Column */}
          <div className="w-1/2 space-y-3">
            <div className="text-xs font-medium text-slate-400 mb-2">Sequence Entities (Nodes)</div>
            {members.map((m, idx) => (
              <div
                key={m.id}
                className="p-3 bg-slate-900 border border-slate-800 rounded-lg hover:border-slate-700 transition-colors"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className={`px-2 py-0.5 text-xs font-mono font-semibold rounded border ${getBadgeForType(m.member_type)}`}>
                    #{idx + 1} {m.member_type}
                  </span>
                  <span className="text-xs font-mono text-slate-500">{m.observed_at.split('T')[1] || m.observed_at}</span>
                </div>
                <div className="mt-1 text-xs font-mono text-cyan-400 truncate">
                  {m.member_record_id}
                </div>
                <p className="mt-1 text-xs text-slate-400 line-clamp-2">
                  {m.relationship_reason}
                </p>
              </div>
            ))}
          </div>

          {/* Relationship Edges Column */}
          <div className="w-1/2 space-y-3">
            <div className="text-xs font-medium text-slate-400 mb-2">Evidence-Backed Linkages (Edges)</div>
            {relationships.length === 0 ? (
              <div className="p-4 text-xs text-slate-500 italic bg-slate-900/40 rounded border border-slate-800">
                No directed inter-entity relationships established yet.
              </div>
            ) : (
              relationships.map((rel) => {
                const src = getMemberById(rel.source_member_id);
                const tgt = getMemberById(rel.target_member_id);
                const isSelected = selectedRelationship?.id === rel.id;
                return (
                  <div
                    key={rel.id}
                    onClick={() => setSelectedRelationship(isSelected ? null : rel)}
                    className={`p-3 rounded-lg border transition-all cursor-pointer ${
                      isSelected
                        ? 'bg-slate-900 border-cyan-500 ring-1 ring-cyan-500/20'
                        : 'bg-slate-900/80 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="px-2 py-0.5 text-xs font-mono font-bold rounded bg-amber-950 text-amber-300 border border-amber-800">
                        {rel.relationship_type}
                      </span>
                      <span className="text-xs text-slate-400 font-mono">
                        Conf: {rel.confidence_score}%
                      </span>
                    </div>

                    <div className="mt-2 text-xs flex items-center gap-1.5 text-slate-400">
                      <span className="truncate max-w-[120px] font-mono text-slate-300">
                        {src ? src.member_record_id.slice(0, 14) : 'Source'}
                      </span>
                      <span className="text-cyan-400 font-bold">&rarr;</span>
                      <span className="truncate max-w-[120px] font-mono text-slate-300">
                        {tgt ? tgt.member_record_id.slice(0, 14) : 'Target'}
                      </span>
                    </div>

                    <p className="mt-1 text-xs text-slate-300 leading-relaxed">
                      {rel.explanation}
                    </p>

                    {isSelected && (
                      <div className="mt-3 pt-2 border-t border-slate-800 text-xs">
                        <span className="font-semibold text-slate-300">Evidence Details:</span>
                        <pre className="mt-1 p-2 bg-slate-950 rounded text-xs font-mono text-slate-400 border border-slate-800 overflow-x-auto">
                          {JSON.stringify(rel.evidence_payload, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

