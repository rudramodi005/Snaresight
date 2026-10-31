"""Explainable Scoring Engine for Behavioral Sequences (Task P22).

Separates:
1. Event Severity (individual behavior significance)
2. Detection Confidence (rule evidence strength)
3. Correlation Confidence (strength of linkage across sessions)
4. Sequence Relevance (operational investigation priority)
"""

from typing import Any, Dict, List, Tuple
from app.modules.correlation.sequence_schemas import SequencePatternType


class SequenceScorer:
    """Calculates distinct correlation confidence and sequence relevance scores with factor explanations."""

    SEVERITY_ORDER = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFO": 1,
    }
    REVERSE_SEVERITY = {v: k for k, v in SEVERITY_ORDER.items()}

    @classmethod
    def compute_scores(
        cls,
        sessions: List[Dict[str, Any]],
        detections: List[Dict[str, Any]],
        mappings: List[Dict[str, Any]],
        pattern: SequencePatternType,
        has_shared_trusted_id: bool = False,
        has_shared_source_context: bool = False,
    ) -> Tuple[int, int, str, Dict[str, Any]]:
        """Calculates (correlation_confidence, sequence_relevance, aggregate_severity, explanation_factors)."""
        conf_factors: List[str] = []
        rel_factors: List[str] = []

        # ---------------------------------------------------------------------
        # 1. Correlation Confidence (Evidential linkage strength: 0 - 100)
        # ---------------------------------------------------------------------
        confidence = 50  # Baseline contextual candidate score

        if has_shared_trusted_id:
            confidence += 30
            conf_factors.append("+30: Shared trusted interaction identifier present in telemetry")
        elif has_shared_source_context:
            confidence += 15
            conf_factors.append("+15: Shared source address context corroborated across sessions")

        if len(detections) >= 2:
            confidence += 10
            conf_factors.append(f"+10: Corroborated by {len(detections)} detection findings")

        if len(mappings) >= 1:
            confidence += 10
            conf_factors.append(f"+10: Corroborated by {len(mappings)} evidence-backed ATT&CK mappings")

        # Bound confidence
        final_confidence = max(10, min(100, confidence))

        # ---------------------------------------------------------------------
        # 2. Sequence Relevance (Operational SOC investigation priority: 0 - 100)
        # ---------------------------------------------------------------------
        relevance = 30  # Baseline relevance

        # Factor in highest detection severity
        highest_sev_rank = 0
        for d in detections:
            sev = str(d.get("severity") or "INFO").upper()
            rank = cls.SEVERITY_ORDER.get(sev, 1)
            if rank > highest_sev_rank:
                highest_sev_rank = rank

        if highest_sev_rank >= 5:  # CRITICAL
            relevance += 40
            rel_factors.append("+40: Includes CRITICAL severity detection finding")
        elif highest_sev_rank == 4:  # HIGH
            relevance += 30
            rel_factors.append("+30: Includes HIGH severity detection finding")
        elif highest_sev_rank == 3:  # MEDIUM
            relevance += 20
            rel_factors.append("+20: Includes MEDIUM severity detection finding")
        elif highest_sev_rank == 2:  # LOW
            relevance += 10
            rel_factors.append("+10: Includes LOW severity detection finding")

        # Pattern relevance weight
        pattern_weights = {
            SequencePatternType.MULTI_TECHNIQUE_PROGRESSION: 25,
            SequencePatternType.ENUMERATION_THEN_EXPLOIT: 25,
            SequencePatternType.AUTH_THEN_ENUMERATION: 20,
            SequencePatternType.CROSS_PROTOCOL_INTERACTION: 20,
            SequencePatternType.REPEATED_AUTHENTICATION: 15,
            SequencePatternType.RECURRING_HONEYPOT_TARGET: 15,
        }
        p_weight = pattern_weights.get(pattern, 10)
        relevance += p_weight
        rel_factors.append(f"+{p_weight}: Pattern complexity weight for {pattern.value}")

        # Session volume weight (up to +15)
        sess_weight = min(len(sessions) * 5, 15)
        relevance += sess_weight
        rel_factors.append(f"+{sess_weight}: Scaled across {len(sessions)} correlated sessions")

        final_relevance = max(10, min(100, relevance))
        aggregate_severity = cls.REVERSE_SEVERITY.get(highest_sev_rank, "INFO")

        explanation = {
            "correlation_confidence": final_confidence,
            "sequence_relevance": final_relevance,
            "aggregate_severity": aggregate_severity,
            "confidence_factors": conf_factors,
            "relevance_factors": rel_factors,
            "disclaimer": "Scores represent analytical confidence in relationship linkage and operational investigation priority. They do NOT represent probability of human identity attribution.",
        }

        return final_confidence, final_relevance, aggregate_severity, explanation
