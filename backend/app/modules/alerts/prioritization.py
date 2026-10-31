"""Transparent, configurable, and evidence-based alert prioritization engine.

Separates severity (inherent impact) and confidence (analytical certainty) from operational priority (triage urgency).
Formula Version: 1.0 (SnareSight Evidence-Weighted Priority Index).
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class PrioritizationConfig(BaseModel):
    """Configurable weights for the SnareSight Prioritization Formula."""
    formula_version: str = "1.0"
    
    # Severity weights (Max 40 pts)
    severity_weights: Dict[str, float] = Field(
        default_factory=lambda: {
            "CRITICAL": 40.0,
            "HIGH": 30.0,
            "MEDIUM": 20.0,
            "LOW": 10.0,
            "INFO": 5.0,
        }
    )
    
    # Confidence weight multiplier (Max 25 pts)
    # confidence (0..100) * 0.25 -> 0..25 pts
    confidence_factor: float = 0.25
    
    # Evidence strength weights (Max 15 pts)
    evidence_strength_weights: Dict[str, float] = Field(
        default_factory=lambda: {
            "DEFINITIVE": 15.0,
            "STRONG": 12.0,
            "CORROBORATED": 8.0,
            "WEAK": 4.0,
        }
    )
    
    # Supporting event count bonus (Max 5 pts, 1 pt per event over 1)
    max_event_count_bonus: float = 5.0
    
    # Cross-subsystem context bonus (Max 10 pts)
    context_linked_bonus: float = 10.0
    
    # Recency urgency bonus (Max 5 pts)
    # < 2 hours = 5 pts, < 12 hours = 3 pts, < 24 hours = 1 pt, else 0 pts
    recency_tiers: List[Dict[str, Any]] = Field(
        default_factory=lambda: [
            {"max_age_hours": 2, "points": 5.0},
            {"max_age_hours": 12, "points": 3.0},
            {"max_age_hours": 24, "points": 1.0},
        ]
    )


class PrioritizationResult(BaseModel):
    """Detailed explainable breakdown of an alert's calculated prioritization score."""
    priority_score: float = Field(..., ge=0.0, le=100.0, description="Calculated priority score (0-100)")
    priority_level: str = Field(..., description="P1_CRITICAL, P2_HIGH, P3_MEDIUM, or P4_LOW")
    formula_version: str = Field(default="1.0")
    severity_component: float
    confidence_component: float
    evidence_component: float
    context_component: float
    recency_component: float
    rationale: str
    non_attribution_notice: str = (
        "Priority reflects telemetry severity, detection confidence, and operational urgency. "
        "It does not infer attacker capability, nation-state attribution, or confirmed human identity."
    )


class AlertPrioritizer:
    """Evaluates and explains operational triage priority for SnareSight security alerts."""

    def __init__(self, config: Optional[PrioritizationConfig] = None):
        self.config = config or PrioritizationConfig()

    def calculate_priority(
        self,
        severity: str,
        confidence: int,
        evidence_strength: str,
        supporting_events_count: int = 1,
        has_investigation_or_sequence: bool = False,
        generated_at: Optional[datetime] = None,
    ) -> PrioritizationResult:
        """Calculates a transparent, multi-factor operational priority score."""
        # 1. Severity component (0-40)
        sev_upper = severity.upper() if severity else "MEDIUM"
        sev_score = self.config.severity_weights.get(sev_upper, 20.0)

        # 2. Confidence component (0-25)
        conf_clamped = max(0, min(100, confidence))
        conf_score = round(conf_clamped * self.config.confidence_factor, 2)

        # 3. Evidence component (0-20)
        ev_strength_score = self.config.evidence_strength_weights.get(evidence_strength.upper(), 8.0)
        ev_count_bonus = min(self.config.max_event_count_bonus, max(0, (supporting_events_count - 1) * 1.0))
        ev_total_score = round(ev_strength_score + ev_count_bonus, 2)

        # 4. Context component (0-10)
        context_score = self.config.context_linked_bonus if has_investigation_or_sequence else 0.0

        # 5. Recency component (0-5)
        recency_score = 0.0
        if generated_at:
            now_utc = datetime.now(timezone.utc)
            if generated_at.tzinfo is None:
                generated_at = generated_at.replace(tzinfo=timezone.utc)
            age_hours = (now_utc - generated_at).total_seconds() / 3600.0
            for tier in self.config.recency_tiers:
                if age_hours <= tier["max_age_hours"]:
                    recency_score = tier["points"]
                    break

        total_score = round(min(100.0, sev_score + conf_score + ev_total_score + context_score + recency_score), 2)

        # Assign priority tier
        if total_score >= 75.0:
            priority_level = "P1_CRITICAL"
        elif total_score >= 50.0:
            priority_level = "P2_HIGH"
        elif total_score >= 30.0:
            priority_level = "P3_MEDIUM"
        else:
            priority_level = "P4_LOW"

        # Formulate human-readable rationale
        rationale_parts = [
            f"Severity contribution: {sev_score} pts ({sev_upper})",
            f"Confidence contribution: {conf_score} pts ({conf_clamped}%)",
            f"Evidence contribution: {ev_total_score} pts ({evidence_strength}, {supporting_events_count} events)",
        ]
        if context_score > 0:
            rationale_parts.append(f"Context linkage bonus: +{context_score} pts (Sequence/Investigation attached)")
        if recency_score > 0:
            rationale_parts.append(f"Recency urgency bonus: +{recency_score} pts")

        rationale = f"Priority score {total_score} ({priority_level}) derived from: " + "; ".join(rationale_parts) + "."

        return PrioritizationResult(
            priority_score=total_score,
            priority_level=priority_level,
            formula_version=self.config.formula_version,
            severity_component=sev_score,
            confidence_component=conf_score,
            evidence_component=ev_total_score,
            context_component=context_score,
            recency_component=recency_score,
            rationale=rationale,
        )


# Global default prioritizer
default_prioritizer = AlertPrioritizer()

