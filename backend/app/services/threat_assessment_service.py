"""Threat assessment service coordinating severity, confidence, and evidence evaluation.

Provides the primary interface for evaluating detection results, recording assessments,
managing analyst reviews, and maintaining historical assessment audits.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.detection.assessment_result import (
    ThreatAssessmentResult,
    AnalystReview,
    AssessmentHistoryRecord,
)
from app.detection.confidence_scorer import ConfidenceScorer
from app.detection.evidence_assessor import EvidenceAssessor
from app.detection.exceptions import AssessmentError
from app.detection.registry import RuleRegistry, rule_registry
from app.detection.scoring_policy import (
    ScoringPolicyDefinition,
    ScoringPolicyRegistry,
    scoring_policy_registry,
    SeverityLevel,
)
from app.detection.severity_assessor import SeverityAssessor
from app.schemas.detection import DetectionResult, EvaluationStatus


class ThreatAssessmentService:
    """Service facade for threat assessment, confidence scoring, and analyst review workflows."""

    def __init__(
        self,
        policies: Optional[ScoringPolicyRegistry] = None,
        rules: Optional[RuleRegistry] = None,
    ):
        self.policies = policies or scoring_policy_registry
        self.rules = rules or rule_registry
        # In-memory storage: {assessment_id: ThreatAssessmentResult}
        self._assessments: Dict[str, ThreatAssessmentResult] = {}
        # Mapping: {detection_result_id: assessment_id}
        self._detection_assessment_map: Dict[str, str] = {}
        # History audit log: [AssessmentHistoryRecord, ...]
        self._history: List[AssessmentHistoryRecord] = []

    def assess_detection(
        self,
        detection_result: DetectionResult,
        event: Dict[str, Any],
        related_events: Optional[List[Dict[str, Any]]] = None,
        policy_id: str = "DEFAULT_SCORING_POLICY",
        policy_version: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> ThreatAssessmentResult:
        """Evaluates severity and confidence for a detection result.
        
        Guarantees:
        - Strictly evaluates only MATCHED detection results.
        - Idempotent: returns existing assessment if detection_result_id already evaluated.
        - Original event and detection result are never modified or destroyed.
        """
        # Idempotency check
        existing_id = self._detection_assessment_map.get(detection_result.detection_result_id)
        if existing_id and existing_id in self._assessments:
            return self._assessments[existing_id]

        policy = self.policies.get_policy(policy_id, version=policy_version)
        rule = self.rules.get_rule(detection_result.rule_id, version=detection_result.rule_version)

        # 1. Evidence Quality & Strength Assessment
        evidence_strength, evidence_metrics = EvidenceAssessor.assess_evidence(
            event=event,
            related_events=related_events,
            evidence_references=detection_result.evidence_references,
        )

        # 2. Severity Assessment (Independent of confidence)
        sev_level, sev_score, sev_expl = SeverityAssessor.assess_severity(
            rule=rule,
            event=event,
            evidence_metrics=evidence_metrics,
            policy=policy,
        )

        # 3. Confidence Calculation (Independent of severity)
        conf_level, conf_score, conf_expl = ConfidenceScorer.calculate_confidence(
            evidence_metrics=evidence_metrics,
            matched_conditions=detection_result.matched_conditions,
            policy=policy,
        )

        # 4. Assemble Immutable Assessment Result
        assessment = ThreatAssessmentResult(
            detection_result_id=detection_result.detection_result_id,
            rule_id=detection_result.rule_id,
            rule_version=detection_result.rule_version,
            severity_level=sev_level,
            severity_score=sev_score,
            confidence_score=conf_score,
            confidence_level=conf_level,
            evidence_strength=evidence_strength,
            severity_explanation=sev_expl,
            confidence_explanation=conf_expl,
            supporting_event_ids=evidence_metrics.get("deduplicated_event_ids", [str(event.get("event_id", ""))]),
            supporting_evidence_ids=[str(ref.get("event_id", "")) for ref in detection_result.evidence_references if ref.get("event_id")],
            provenance=dict(detection_result.provenance),
            scoring_policy_id=policy.policy_id,
            scoring_policy_version=policy.policy_version,
            assessed_at=datetime.now(timezone.utc).isoformat(),
            assessment_version=1,
            analyst_review=None,
        )

        # Cache assessment
        self._assessments[assessment.assessment_id] = assessment
        self._detection_assessment_map[detection_result.detection_result_id] = assessment.assessment_id

        # Record initial history entry
        self._history.append(
            AssessmentHistoryRecord(
                assessment_id=assessment.assessment_id,
                assessment_version=1,
                previous_severity=sev_level,
                updated_severity=sev_level,
                previous_confidence=conf_score,
                updated_confidence=conf_score,
                reason="Initial automated threat assessment",
                initiator="system",
            )
        )

        return assessment

    def submit_analyst_review(
        self,
        assessment_id: str,
        reviewer_id: str,
        proposed_severity: Optional[SeverityLevel] = None,
        proposed_confidence: Optional[int] = None,
        review_reason: str = "Standard manual triage review",
    ) -> ThreatAssessmentResult:
        """Attaches an auditable manual analyst review without silently overwriting the automated assessment."""
        if assessment_id not in self._assessments:
            raise AssessmentError(f"Assessment '{assessment_id}' not found")

        assessment = self._assessments[assessment_id]
        prev_sev = assessment.severity_level
        prev_conf = assessment.confidence_score

        # Attach review record
        assessment.analyst_review = AnalystReview(
            reviewed=True,
            reviewer_id=reviewer_id,
            reviewed_at=datetime.now(timezone.utc).isoformat(),
            proposed_severity=proposed_severity or prev_sev,
            proposed_confidence=proposed_confidence if proposed_confidence is not None else prev_conf,
            review_reason=review_reason,
            approval_status="APPROVED",
        )
        assessment.assessment_version += 1

        # Record audit history entry
        self._history.append(
            AssessmentHistoryRecord(
                assessment_id=assessment_id,
                assessment_version=assessment.assessment_version,
                previous_severity=prev_sev,
                updated_severity=proposed_severity or prev_sev,
                previous_confidence=prev_conf,
                updated_confidence=proposed_confidence if proposed_confidence is not None else prev_conf,
                reason=f"Analyst review by {reviewer_id}: {review_reason}",
                initiator=reviewer_id,
            )
        )

        return assessment

    def get_assessment(self, assessment_id: str) -> Optional[ThreatAssessmentResult]:
        """Retrieves an assessment by ID."""
        return self._assessments.get(assessment_id)

    def get_assessment_for_detection(self, detection_result_id: str) -> Optional[ThreatAssessmentResult]:
        """Retrieves assessment associated with a specific detection result."""
        aid = self._detection_assessment_map.get(detection_result_id)
        if aid:
            return self._assessments.get(aid)
        return None

    def get_assessment_history(self, assessment_id: Optional[str] = None) -> List[AssessmentHistoryRecord]:
        """Returns history audit records."""
        if assessment_id:
            return [h for h in self._history if h.assessment_id == assessment_id]
        return list(self._history)

    def clear(self) -> None:
        """Clears memory state for unit test isolation."""
        self._assessments.clear()
        self._detection_assessment_map.clear()
        self._history.clear()


# Module-level default singleton service
threat_assessment_service = ThreatAssessmentService()

