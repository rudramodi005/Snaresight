"""Confidence scoring engine for SnareSight threat assessments.

Calculates evidence reliability ratings (0–100) using configurable component weights
and documented penalties. Guarantees independence from severity assessment.
"""

from typing import Any, Dict, List, Tuple
from app.detection.scoring_policy import ConfidenceLevel, ScoringPolicyDefinition


class ConfidenceScorer:
    """Calculates explainable, reproducible evidence confidence scores."""

    @classmethod
    def calculate_confidence(
        cls,
        evidence_metrics: Dict[str, Any],
        matched_conditions: List[Dict[str, Any]],
        policy: ScoringPolicyDefinition,
    ) -> Tuple[ConfidenceLevel, int, str]:
        """Calculates (confidence_level, numeric_score, explanation).
        
        Formula:
            Raw Score = Sum(Component_Score_i * Weight_i) - Documented_Penalties
            Clamped to [0, 100]
        """
        weights = policy.confidence_weights
        component_scores: Dict[str, float] = {}
        factor_explanations: List[str] = []

        # 1. Rule Match Quality (0 - 100)
        match_count = len(matched_conditions)
        if match_count > 0:
            match_score = 100.0
            factor_explanations.append(f"Explicit predicate match verified ({match_count} conditions: 100 pts)")
        else:
            match_score = 50.0
            factor_explanations.append("Heuristic or default rule match (50 pts)")
        component_scores["rule_match_quality"] = match_score

        # 2. Event Validity (0 - 100)
        if evidence_metrics.get("event_valid", False):
            val_score = 100.0
            factor_explanations.append("Schema and data integrity verified (100 pts)")
        else:
            val_score = 30.0
            factor_explanations.append("Unverified or incomplete schema structure (30 pts)")
        component_scores["event_validity"] = val_score

        # 3. Source Reliability (0 - 100)
        if evidence_metrics.get("source_reliable", False):
            src_score = 100.0
            factor_explanations.append("Registered active collector source (100 pts)")
        else:
            src_score = 40.0
            factor_explanations.append("Unregistered or missing collector identifier (40 pts)")
        component_scores["source_reliability"] = src_score

        # 4. Provenance Fidelity (0 - 100)
        prov_type = evidence_metrics.get("provenance_type", "UNKNOWN")
        if prov_type in ("LIVE_HONEYPOT", "CONTROLLED_TEST"):
            prov_score = 100.0
            factor_explanations.append(f"Verified provenance '{prov_type}' (100 pts)")
        elif prov_type == "SYNTHETIC_SIMULATION":
            prov_score = 90.0
            factor_explanations.append("Synthetic test harness provenance (90 pts)")
        else:
            prov_score = 40.0
            factor_explanations.append("Uncertain or unclassified provenance (40 pts)")
        component_scores["provenance_fidelity"] = prov_score

        # 5. Session Consistency (0 - 100)
        if evidence_metrics.get("has_session", False):
            sess_score = 100.0
            factor_explanations.append("Valid decoy session context (100 pts)")
        else:
            sess_score = 20.0
            factor_explanations.append("Missing session context (20 pts)")
        component_scores["session_consistency"] = sess_score

        # 6. Timestamp Quality (0 - 100)
        if evidence_metrics.get("timestamp_valid", False):
            ts_score = 100.0
            factor_explanations.append("Accurate UTC timestamp within clock tolerances (100 pts)")
        else:
            ts_score = 0.0
            factor_explanations.append("Invalid or corrupted timestamp (0 pts)")
        component_scores["timestamp_quality"] = ts_score

        # Compute Weighted Base Score
        weighted_score = (
            component_scores["rule_match_quality"] * weights.rule_match_quality
            + component_scores["event_validity"] * weights.event_validity
            + component_scores["source_reliability"] * weights.source_reliability
            + component_scores["provenance_fidelity"] * weights.provenance_fidelity
            + component_scores["session_consistency"] * weights.session_consistency
            + component_scores["timestamp_quality"] * weights.timestamp_quality
        )

        # Apply Documented Evidence Penalties
        penalties_applied: List[str] = []
        if not evidence_metrics.get("timestamp_valid", False):
            pen = policy.penalties.get("invalid_timestamp", 30.0)
            weighted_score -= pen
            penalties_applied.append(f"Invalid timestamp penalty (-{pen} pts)")

        if evidence_metrics.get("has_contradiction", False):
            pen = policy.penalties.get("contradictory_evidence", 25.0)
            weighted_score -= pen
            penalties_applied.append(f"Contradictory evidence penalty (-{pen} pts)")

        if not evidence_metrics.get("has_session", False):
            pen = policy.penalties.get("missing_session_context", 15.0)
            weighted_score -= pen
            penalties_applied.append(f"Missing session penalty (-{pen} pts)")

        # Enforce strict 0 to 100 boundaries
        final_score = int(round(max(0.0, min(100.0, weighted_score))))

        # Derive Confidence Level from Configured Policy Thresholds
        tiers = policy.confidence_tier_boundaries
        if final_score >= tiers.get("VERY_HIGH", 80):
            level = ConfidenceLevel.VERY_HIGH
        elif final_score >= tiers.get("HIGH", 60):
            level = ConfidenceLevel.HIGH
        elif final_score >= tiers.get("MODERATE", 40):
            level = ConfidenceLevel.MODERATE
        elif final_score >= tiers.get("LOW", 20):
            level = ConfidenceLevel.LOW
        else:
            level = ConfidenceLevel.VERY_LOW

        explanation = (
            f"Confidence calculated as {level.value} (Score: {final_score}/100). "
            f"Positive factors: {'; '.join(factor_explanations)}. "
        )
        if penalties_applied:
            explanation += f"Penalties: {'; '.join(penalties_applied)}. "
        explanation += "Note: Score reflects evidence reliability, not real-world compromise probability."

        return level, final_score, explanation

