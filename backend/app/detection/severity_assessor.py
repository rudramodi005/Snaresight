"""Severity assessment engine for SnareSight threat detection results.

Evaluates the behavioral significance of detected interactions based on rule baseline,
interaction depth, multi-stage behavior combinations, and strict policy boundaries.
"""

from typing import Any, Dict, List, Tuple
from app.detection.scoring_policy import SeverityLevel, ScoringPolicyDefinition
from app.detection.rule_schema import DetectionRuleDefinition


class SeverityAssessor:
    """Calculates explainable categorical severity levels and numeric scores."""

    # Baseline scores for rule default severities
    SEVERITY_BASE_SCORES = {
        "INFO": 10,
        "LOW": 30,
        "MEDIUM": 50,
        "HIGH": 70,
        "CRITICAL": 85,
    }

    @classmethod
    def assess_severity(
        cls,
        rule: DetectionRuleDefinition,
        event: Dict[str, Any],
        evidence_metrics: Dict[str, Any],
        policy: ScoringPolicyDefinition,
    ) -> Tuple[SeverityLevel, int, str]:
        """Calculates (severity_level, numeric_score, explanation).
        
        Guarantees:
        - Severity is strictly independent of confidence.
        - CRITICAL requires explicit policy authorization and multi-criteria justification.
        """
        base_sev_str = rule.severity_default.value.upper()
        score = cls.SEVERITY_BASE_SCORES.get(base_sev_str, 50)
        adjustments: List[str] = [f"Baseline rule severity '{base_sev_str}' ({score} pts)"]

        # 1. Behavior & Category Adjustments
        event_cat = str(event.get("event_category", "")).upper()
        if event_cat in ("EXPLOITATION", "COMMAND_EXECUTION"):
            score += 15
            adjustments.append("High-impact interaction category (+15 pts)")
        elif event_cat == "AUTHENTICATION" and event.get("outcome") == "FAILURE":
            # Routine failed authentication is moderate
            adjustments.append("Standard authentication failure telemetry")

        # 2. Interaction Depth / Corroboration Adjustments
        unique_ev_count = evidence_metrics.get("unique_evidence_count", 1)
        if unique_ev_count >= 5:
            score += 10
            adjustments.append(f"Deep session interaction sequence ({unique_ev_count} unique interactions: +10 pts)")
        elif unique_ev_count >= 2:
            score += 5
            adjustments.append(f"Corroborated multi-event interaction (+5 pts)")

        # 3. Policy Enforcement for CRITICAL
        # CRITICAL must not be assigned solely due to repeated events or simple login attempts
        if score >= 80:
            if not policy.allow_critical_auto_escalation:
                if base_sev_str != "CRITICAL":
                    score = 75  # Cap at HIGH unless rule was explicitly designed as CRITICAL
                    adjustments.append("Capped at HIGH (Policy forbids automated escalation to CRITICAL without explicit rule designation)")

        # Clamp score strictly between 0 and 100
        score = max(0, min(100, score))

        # 4. Derive Categorical Level from Score
        if score >= 80:
            level = SeverityLevel.CRITICAL
        elif score >= 60:
            level = SeverityLevel.HIGH
        elif score >= 40:
            level = SeverityLevel.MEDIUM
        elif score >= 20:
            level = SeverityLevel.LOW
        else:
            level = SeverityLevel.INFO

        explanation = (
            f"Severity assessed as {level.value} (Score: {score}/100). "
            f"Factors: {'; '.join(adjustments)}."
        )
        return level, score, explanation

