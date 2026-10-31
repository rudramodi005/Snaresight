"""Explainable Mapping Confidence Assessment Engine (Task P20).

Calculates independent mapping confidence ratings measuring the degree of alignment
between observed security telemetry and specific MITRE ATT&CK techniques.

INVARIANT: Independent of detection confidence (which measures rule signal reliability).
"""

from typing import Any, Dict, List, Optional, Tuple
from app.modules.mitre.mapping.schemas import (
    MappingCategory,
    MappingConfidenceLevel,
    MappingDefinitionSchema,
)


class MappingConfidenceAssessment:
    """Detailed result of mapping confidence computation."""

    def __init__(
        self,
        score: int,
        level: MappingConfidenceLevel,
        explanation: str,
        factors: Dict[str, Any],
    ):
        self.score = score
        self.level = level
        self.explanation = explanation
        self.factors = factors


class MappingConfidenceEngine:
    """Computes transparent, auditable confidence scores for MITRE ATT&CK associations."""

    POLICY_VERSION = "1.0"

    # Base confidence by evidential category
    CATEGORY_BASE_SCORES = {
        MappingCategory.DIRECTLY_SUPPORTED: 75,
        MappingCategory.PARTIALLY_SUPPORTED: 55,
        MappingCategory.REQUIRES_ANALYST_REVIEW: 40,
        MappingCategory.NOT_MAPPED: 0,
    }

    @classmethod
    def calculate_confidence(
        cls,
        definition: MappingDefinitionSchema,
        event: Dict[str, Any],
        related_event_ids: Optional[List[str]] = None,
        is_subtechnique: bool = False,
        is_simulated_decoy: bool = True,
    ) -> MappingConfidenceAssessment:
        """Computes mapping confidence score (0-100) and human-readable explanation."""

        if definition.mapping_category == MappingCategory.NOT_MAPPED:
            return MappingConfidenceAssessment(
                score=0,
                level=MappingConfidenceLevel.LOW,
                explanation="Mapping category is NOT_MAPPED; observed behavior lacks specific technique alignment.",
                factors={"base_score": 0, "category": "NOT_MAPPED"},
            )

        factors: Dict[str, Any] = {}
        score = cls.CATEGORY_BASE_SCORES.get(definition.mapping_category, 50)
        factors["base_category_score"] = score

        explanation_parts: List[str] = [
            f"Base confidence initialized to {score} based on evidential category '{definition.mapping_category.value}'."
        ]

        # 1. Telemetry Reliability Modifier
        # Telemetry from controlled honeypot sensor provides deterministic forensic capture
        score += 10
        factors["telemetry_source_reliability"] = +10
        explanation_parts.append("Telemetry source reliability: +10 (validated honeypot decoy audit stream).")

        # 2. Corroborating Evidence Volume
        evidence_count = 1 + (len(related_event_ids) if related_event_ids else 0)
        factors["evidence_event_count"] = evidence_count
        if evidence_count >= 3:
            score += 10
            factors["evidence_volume_modifier"] = +10
            explanation_parts.append(f"Corroborating evidence volume: +10 (session contains {evidence_count} supporting events).")
        else:
            factors["evidence_volume_modifier"] = 0
            explanation_parts.append("Corroborating evidence volume: +0 (single or minimal event observation).")

        # 3. Sub-Technique Specificity Modifier
        if is_subtechnique and definition.subtechnique_id:
            score += 5
            factors["subtechnique_specificity_modifier"] = +5
            explanation_parts.append(f"Sub-technique specificity bonus: +5 (mapped to granular technique {definition.subtechnique_id}).")

        # 4. Decoy Simulation Caution Modifier
        # If the detection is a decoy simulated credential acceptance, reduce automated certainty
        if definition.rule_id == "AUTH-002" or definition.mapping_category == MappingCategory.REQUIRES_ANALYST_REVIEW:
            score -= 15
            factors["decoy_simulation_caution_modifier"] = -15
            explanation_parts.append(
                "Decoy simulation caveat: -15 (observed interaction occurred on trap account; real system compromise unproven)."
            )

        # 5. Clamp to valid 0-100 interval
        final_score = max(0, min(100, score))
        factors["final_score"] = final_score

        # 6. Map to categorical level
        if final_score >= 80:
            level = MappingConfidenceLevel.HIGH
        elif final_score >= 50:
            level = MappingConfidenceLevel.MODERATE
        else:
            level = MappingConfidenceLevel.LOW

        factors["confidence_level"] = level.value
        explanation_parts.append(f"Final calculated mapping confidence: {final_score}% ({level.value}).")

        return MappingConfidenceAssessment(
            score=final_score,
            level=level,
            explanation=" ".join(explanation_parts),
            factors=factors,
        )

