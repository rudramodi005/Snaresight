import React, { useState } from 'react';
import { ClusterRelationship, ClusterMembership } from '../types/campaign';

interface CampaignRelationshipGraphProps {
  clusterId: string;
  clusterTitle: string;
  members: ClusterMembership[];
  relationships: ClusterRelationship[];
}

export const CampaignRelationshipGraph: React.FC<CampaignRelationshipGraphProps> = ({
  clusterId,
  clusterTitle,
  members,
  relationships,
}) => {
  const [selectedEdge, setSelectedEdge] = useState<ClusterRelationship | null>(null);

  // Group members by type
  const sessionCount = members.filter((m) => m.member_type === 'SESSION').length;
  const profileCount = members.filter((m) => m.member_type === 'SOURCE_PROFILE').length;
  const alertCount = members.filter((m) => m.member_type === 'ALERT').length;
  const sequenceCount = members.filter((m) => m.member_type === 'SEQUENCE').length;

  return (
    <div className="p-4 bg-[#242E49] border border-[#37415C] rounded-xl space-y-4">
      <div className="flex justify-between items-center">
        <div>
          <span className="text-xs uppercase tracking-wider font-semibold text-[#FDA481]">
            Evidence-Backed Cluster Relationship Topology
          </span>
          <p className="text-xs text-[#94A3B8] mt-0.5">
            Topology showing member distributions and cross-cluster behavioral links with confidence scores.
          </p>
        </div>
        <span className="px-2 py-0.5 text-xs font-mono bg-[#181A2F] text-[#FDA481] border border-[#37415C] rounded">
          {relationships.length} Relationship(s)
        </span>
      </div>

      {/* SVG Topology Visualization */}
      <div className="relative w-full h-80 bg-[#181A2F] border border-[#37415C] rounded-lg overflow-hidden flex items-center justify-center">
        <svg className="w-full h-full" viewBox="0 0 600 300">
          <defs>
            <linearGradient id="clusterGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#B4182D" stopOpacity="0.95" />
              <stop offset="100%" stopColor="#54162B" stopOpacity="0.85" />
            </linearGradient>
            <marker id="arrow" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#FDA481" />
            </marker>
          </defs>

          {/* Lines from Central Cluster to Member Orbit Nodes */}
          {/* Member 1: Sessions */}
          <line x1="300" y1="150" x2="140" y2="80" stroke="#37415C" strokeWidth="2" strokeDasharray="4 2" />
          {/* Member 2: Profiles */}
          <line x1="300" y1="150" x2="140" y2="220" stroke="#37415C" strokeWidth="2" strokeDasharray="4 2" />
          {/* Member 3: Alerts */}
          <line x1="300" y1="150" x2="460" y2="80" stroke="#37415C" strokeWidth="2" strokeDasharray="4 2" />
          {/* Member 4: Sequences */}
          <line x1="300" y1="150" x2="460" y2="220" stroke="#37415C" strokeWidth="2" strokeDasharray="4 2" />

          {/* Member Nodes */}
          <g>
            <circle cx="140" cy="80" r="28" fill="#242E49" stroke="#FDA481" strokeWidth="2" />
            <text x="140" y="78" textAnchor="middle" fill="#FDA481" fontSize="11" fontWeight="bold">
              {sessionCount}
            </text>
            <text x="140" y="94" textAnchor="middle" fill="#94A3B8" fontSize="9">
              Sessions
            </text>
          </g>

          <g>
            <circle cx="140" cy="220" r="28" fill="#242E49" stroke="#FDA481" strokeWidth="2" />
            <text x="140" y="218" textAnchor="middle" fill="#FDA481" fontSize="11" fontWeight="bold">
              {profileCount}
            </text>
            <text x="140" y="234" textAnchor="middle" fill="#94A3B8" fontSize="9">
              Profiles
            </text>
          </g>

          <g>
            <circle cx="460" cy="80" r="28" fill="#242E49" stroke="#FDA481" strokeWidth="2" />
            <text x="460" y="78" textAnchor="middle" fill="#FDA481" fontSize="11" fontWeight="bold">
              {alertCount}
            </text>
            <text x="460" y="94" textAnchor="middle" fill="#94A3B8" fontSize="9">
              Alerts
            </text>
          </g>

          <g>
            <circle cx="460" cy="220" r="28" fill="#242E49" stroke="#FDA481" strokeWidth="2" />
            <text x="460" y="218" textAnchor="middle" fill="#FDA481" fontSize="11" fontWeight="bold">
              {sequenceCount}
            </text>
            <text x="460" y="234" textAnchor="middle" fill="#94A3B8" fontSize="9">
              Sequences
            </text>
          </g>

          {/* Central Investigation Cluster Node */}
          <g>
            <circle cx="300" cy="150" r="42" fill="url(#clusterGrad)" stroke="#B4182D" strokeWidth="3" />
            <text x="300" y="146" textAnchor="middle" fill="#FFFFFF" fontSize="11" fontWeight="bold">
              {clusterId.substring(0, 9)}
            </text>
            <text x="300" y="162" textAnchor="middle" fill="#FDA481" fontSize="9" fontWeight="bold">
              Investigation
            </text>
          </g>
        </svg>

        {/* Floating Overlay Info */}
        <div className="absolute bottom-2 left-2 text-[10px] text-[#94A3B8] font-mono">
          Central Node: {clusterId}
        </div>
      </div>

      {/* Relationships Table / Inspector */}
      {relationships.length > 0 && (
        <div className="space-y-2">
          <span className="text-xs uppercase tracking-wider font-semibold text-[#CBD5E1] block">
            Correlated Inter-Cluster Relationships
          </span>
          <div className="space-y-2">
            {relationships.map((rel) => {
              const otherCluster =
                rel.source_cluster_id === clusterId ? rel.target_cluster_id : rel.source_cluster_id;
              return (
                <div
                  key={rel.relationship_id}
                  onClick={() => setSelectedEdge(rel)}
                  className="p-3 bg-[#181A2F] border border-[#37415C] hover:border-[#FDA481] rounded-lg cursor-pointer transition text-xs flex justify-between items-center"
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-[#FDA481]">{rel.relationship_type}</span>
                      <span className="font-mono text-[#CBD5E1]">with {otherCluster}</span>
                    </div>
                    <div className="text-[11px] text-[#94A3B8] mt-0.5">
                      Review Status: <strong className="text-white">{rel.analyst_review_status}</strong>
                    </div>
                  </div>
                  <span className="px-2 py-0.5 text-xs font-bold rounded bg-[#54162B] text-[#FDA481] border border-[#B4182D]">
                    {rel.relationship_confidence}% Confidence
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Selected Edge Inspector Modal / Popover */}
      {selectedEdge && (
        <div className="p-3.5 bg-[#181A2F] border border-[#FDA481] rounded-lg text-xs space-y-2">
          <div className="flex justify-between items-center">
            <span className="font-bold text-white">
              Relationship Evidence: {selectedEdge.relationship_id}
            </span>
            <button
              onClick={() => setSelectedEdge(null)}
              className="text-[#94A3B8] hover:text-[#FDA481]"
            >
              ✕
            </button>
          </div>
          <div className="text-[#CBD5E1] font-mono">
            Type: {selectedEdge.relationship_type} (Confidence: {selectedEdge.relationship_confidence}%)
          </div>
          <div className="p-2 bg-[#242E49] rounded text-[#FDA481] font-mono text-[11px]">
            {JSON.stringify(selectedEdge.supporting_evidence, null, 2)}
          </div>
        </div>
      )}
    </div>
  );
};
export default CampaignRelationshipGraph;
