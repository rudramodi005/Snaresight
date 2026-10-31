"""Dedicated explainable relationship scoring engine for investigation clusters (Task P24)."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple


SCORING_POLICY_VERSION = "1.0"
MINIMUM_RELATIONSHIP_THRESHOLD = 50


class RelationshipScorer:
    """Computes transparent, evidence-based relationship confidence scores between observations.
    
    IMPORTANT: Decouples Event Severity, Detection Confidence, Profile Priority,
    Behavioral Similarity, and Cluster Relationship Confidence.
    """

    @classmethod
    def evaluate_relationship(
        cls,
        shared_sequences: int = 0,
        source_similarity: float = 0.0,
        shared_decoys: int = 0,
        shared_techniques: int = 0,
        temporal_gap_hours: float = 0.0,
        tempo_ratio: float = 1.0,
        differing_protocols: bool = False,
    ) -> Dict[str, Any]:
        """Evaluates whether two investigative entities (sessions, profiles, sequences) are related.
        
        Returns:
            Dictionary with score (0-100), interpretation, contributing signals,
            contradicting signals, and metadata.
        """
        contributing: List[Dict[str, Any]] = []
        contradicting: List[Dict[str, Any]] = []
        missing: List[str] = []

        total_points = 0.0

        # Signal 1: Shared Behavioral Sequence (Weight: 35)
        if shared_sequences > 0:
            pts = min(35.0, shared_sequences * 25.0)
            total_points += pts
            contributing.append({
                "signal": "SHARED_BEHAVIORAL_SEQUENCE",
                "weight": 35,
                "score_contribution": round(pts, 1),
                "rationale": f"Linked across {shared_sequences} multi-session behavioral sequence(s).",
            })
        else:
            missing.append("SHARED_BEHAVIORAL_SEQUENCE")

        # Signal 2: Profile Behavioral Similarity (Weight: 25)
        if source_similarity >= 70.0:
            pts = 25.0 * (source_similarity / 100.0)
            total_points += pts
            contributing.append({
                "signal": "PROFILE_BEHAVIORAL_SIMILARITY",
                "weight": 25,
                "score_contribution": round(pts, 1),
                "rationale": f"High behavioral similarity vector alignment ({source_similarity:.1f}%).",
            })
        elif source_similarity >= 40.0:
            pts = 15.0 * (source_similarity / 100.0)
            total_points += pts
            contributing.append({
                "signal": "PROFILE_BEHAVIORAL_SIMILARITY",
                "weight": 25,
                "score_contribution": round(pts, 1),
                "rationale": f"Moderate behavioral similarity alignment ({source_similarity:.1f}%).",
            })
        else:
            missing.append("PROFILE_BEHAVIORAL_SIMILARITY")

        # Signal 3: Target Decoy Affinity & Temporal Alignment (Weight: 20)
        if shared_decoys > 0 and temporal_gap_hours <= 48.0:
            pts = min(20.0, shared_decoys * 10.0)
            total_points += pts
            contributing.append({
                "signal": "TARGET_DECOY_AFFINITY",
                "weight": 20,
                "score_contribution": round(pts, 1),
                "rationale": f"Targeted {shared_decoys} identical deception endpoint(s) within {temporal_gap_hours:.1f}h window.",
            })
        elif shared_decoys > 0:
            pts = min(10.0, shared_decoys * 5.0)
            total_points += pts
            contributing.append({
                "signal": "TARGET_DECOY_AFFINITY",
                "weight": 20,
                "score_contribution": round(pts, 1),
                "rationale": f"Targeted {shared_decoys} identical decoy(s) across wider time window ({temporal_gap_hours:.1f}h).",
            })
        else:
            missing.append("TARGET_DECOY_AFFINITY")

        # Signal 4: Shared MITRE ATT&CK Techniques (Weight: 20)
        if shared_techniques >= 2:
            pts = 20.0
            total_points += pts
            contributing.append({
                "signal": "SHARED_MITRE_TECHNIQUES",
                "weight": 20,
                "score_contribution": round(pts, 1),
                "rationale": f"Overlapping MITRE technique footprint ({shared_techniques} shared techniques).",
            })
        elif shared_techniques == 1:
            pts = 10.0
            total_points += pts
            contributing.append({
                "signal": "SHARED_MITRE_TECHNIQUES",
                "weight": 20,
                "score_contribution": round(pts, 1),
                "rationale": "Shared 1 MITRE ATT&CK technique.",
            })
        else:
            missing.append("SHARED_MITRE_TECHNIQUES")

        # Contradicting Signal 1: Divergent Tempo Gap
        if tempo_ratio > 10.0:
            penalty = 20.0
            total_points -= penalty
            contradicting.append({
                "signal": "CONTRADICTORY_TEMPO_DISPARITY",
                "penalty": -penalty,
                "rationale": f"Severe velocity discrepancy ({tempo_ratio:.1f}x difference between fast scan and deliberate interaction).",
            })

        # Contradicting Signal 2: Disparate Protocol with Zero Shared Techniques
        if differing_protocols and shared_techniques == 0:
            penalty = 15.0
            total_points -= penalty
            contradicting.append({
                "signal": "DISPARATE_PROTOCOL_NO_TECHNIQUES",
                "penalty": -penalty,
                "rationale": "Different application protocols with zero overlapping ATT&CK techniques.",
            })

        # Contradicting Signal 3: Stale Gap (Over 14 days apart with no recurring baseline)
        if temporal_gap_hours > 336.0 and shared_sequences == 0:
            penalty = 15.0
            total_points -= penalty
            contradicting.append({
                "signal": "EXCESSIVE_TEMPORAL_SEPARATION",
                "penalty": -penalty,
                "rationale": f"Activity separated by {temporal_gap_hours / 24.0:.1f} days without intermediate recurrence.",
            })

        final_score = int(max(0.0, min(100.0, round(total_points))))

        if final_score >= 80:
            interpretation = "STRONG_INVESTIGATION_RELATIONSHIP"
        elif final_score >= 60:
            interpretation = "MODERATE_INVESTIGATION_RELATIONSHIP"
        elif final_score >= MINIMUM_RELATIONSHIP_THRESHOLD:
            interpretation = "CANDIDATE_INVESTIGATION_RELATIONSHIP"
        else:
            interpretation = "INSUFFICIENT_EVIDENCE_FOR_GROUPING"

        return {
            "score": final_score,
            "interpretation": interpretation,
            "is_above_threshold": final_score >= MINIMUM_RELATIONSHIP_THRESHOLD,
            "threshold_applied": MINIMUM_RELATIONSHIP_THRESHOLD,
            "contributing_signals": contributing,
            "contradicting_signals": contradicting,
            "missing_signals": missing,
            "scoring_policy_version": SCORING_POLICY_VERSION,
            "calculated_at": datetime.now(timezone.utc).isoformat(),
        }

