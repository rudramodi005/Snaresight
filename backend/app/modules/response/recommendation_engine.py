"""Rule-based defensive response recommendation engine.

Analyzes underlying alerts, events, sessions, profiles, and campaigns to suggest
explainable, safe defensive actions with explicit human approval requirements.
No opaque or ungrounded generative recommendations are emitted.
"""

import uuid
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.db.models.alert import AlertModel
from app.db.models.event import SecurityEventModel
from app.db.models.correlation import ActivitySessionModel
from app.db.models.source_profile import SourceProfileModel
from app.db.models.campaign import InvestigationClusterModel
from app.db.models.response import ResponseCaseModel, ResponseRecommendationModel


class DefensiveRecommendationEngine:
    """Rule-based recommendation engine synthesizing explainable defensive actions."""

    VERSION = "1.0"

    @classmethod
    def evaluate_case(cls, db: Session, case: ResponseCaseModel) -> List[ResponseRecommendationModel]:
        """Evaluates a case against grounded defensive recommendation rules."""
        recommendations: List[ResponseRecommendationModel] = []

        # 1. Fetch primary alert if linked
        primary_alert = None
        if case.primary_alert_id:
            try:
                alert_uuid = uuid.UUID(case.primary_alert_id)
                primary_alert = db.query(AlertModel).filter(
                    or_(AlertModel.alert_id == alert_uuid, AlertModel.id == alert_uuid)
                ).first()
            except (ValueError, AttributeError):
                pass

        # Rule A: Repeated Authentication Failures
        if primary_alert and ("auth" in primary_alert.title.lower() or "login" in primary_alert.title.lower() or "credential" in primary_alert.title.lower()):
            recommendations.append(
                ResponseRecommendationModel(
                    id=uuid.uuid4(),
                    recommendation_id=f"REC-{uuid.uuid4().hex[:8].upper()}",
                    case_id=case.case_id,
                    rule_id="REC-RULE-AUTH-01",
                    rule_version=cls.VERSION,
                    title="Review Authentication Failures & Preserve Decoy Evidence",
                    explanation=(
                        f"Detected repeated authentication failures on decoy '{primary_alert.decoy_id}'. "
                        "Recommend reviewing username sequences for targeted account enumeration, increasing "
                        "monitoring priority on the source profile, and placing an evidence preservation hold on session events."
                    ),
                    triggering_evidence={
                        "alert_id": str(primary_alert.alert_id),
                        "alert_title": primary_alert.title,
                        "decoy_id": primary_alert.decoy_id,
                        "source_address": primary_alert.source_address,
                        "severity": primary_alert.severity,
                    },
                    supporting_event_ids=[],
                    priority="HIGH",
                    confidence="HIGH",
                    required_permission="execute_defensive_action",
                    requires_approval=True,
                    potential_impact="Elevates case priority, creates evidence preservation hold, and adjusts monitoring focus within SnareSight.",
                    reversal_guidance="Preservation holds can be released by an authorized analyst with recorded justification.",
                    status="PENDING",
                )
            )

        # Rule B: Web Path Enumeration
        if primary_alert and ("web" in primary_alert.title.lower() or "path" in primary_alert.title.lower() or "traversal" in primary_alert.title.lower() or "enum" in primary_alert.title.lower()):
            recommendations.append(
                ResponseRecommendationModel(
                    id=uuid.uuid4(),
                    recommendation_id=f"REC-{uuid.uuid4().hex[:8].upper()}",
                    case_id=case.case_id,
                    rule_id="REC-RULE-WEB-02",
                    rule_version=cls.VERSION,
                    title="Inspect Web Traversal Patterns & Correlate Decoy Sessions",
                    explanation=(
                        f"Observed automated directory or URI enumeration targeting decoy '{primary_alert.decoy_id}'. "
                        "Recommend comparing URI path patterns across related sessions and preserving raw HTTP request headers."
                    ),
                    triggering_evidence={
                        "alert_id": str(primary_alert.alert_id),
                        "decoy_id": primary_alert.decoy_id,
                        "target_service": primary_alert.target_service,
                    },
                    supporting_event_ids=[],
                    priority="MEDIUM",
                    confidence="HIGH",
                    required_permission="execute_defensive_action",
                    requires_approval=False,
                    potential_impact="Adds analytic tags and queues web enumeration playbook.",
                    reversal_guidance="Tags and playbook execution status can be archived.",
                    status="PENDING",
                )
            )

        # Rule C: Suspicious Request Pattern / Command Execution
        if primary_alert and ("command" in primary_alert.title.lower() or "injection" in primary_alert.title.lower() or "shell" in primary_alert.title.lower()):
            recommendations.append(
                ResponseRecommendationModel(
                    id=uuid.uuid4(),
                    recommendation_id=f"REC-{uuid.uuid4().hex[:8].upper()}",
                    case_id=case.case_id,
                    rule_id="REC-RULE-REQ-03",
                    rule_version=cls.VERSION,
                    title="Forensic Command Sequence Review & Immediate Evidence Lock",
                    explanation=(
                        f"Detected attempted command execution or shell injection payload. "
                        "Recommend isolating the affected session events, computing SHA-256 integrity hashes, "
                        "and requesting senior analyst review."
                    ),
                    triggering_evidence={
                        "alert_id": str(primary_alert.alert_id),
                        "severity": primary_alert.severity,
                        "detection_rule_id": primary_alert.detection_rule_id,
                    },
                    supporting_event_ids=[],
                    priority="CRITICAL",
                    confidence="VERY_HIGH",
                    required_permission="approve_defensive_action",
                    requires_approval=True,
                    potential_impact="Escalates case to P1_CRITICAL and places mandatory evidence hold.",
                    reversal_guidance="Requires administrator or lead analyst approval to resolve.",
                    status="PENDING",
                )
            )

        # Rule D: Multi-Session Suspicious Activity
        if primary_alert and primary_alert.source_address:
            source_profile = db.query(SourceProfileModel).filter(
                SourceProfileModel.source_ip == primary_alert.source_address
            ).first()
            if source_profile and source_profile.total_sessions > 1:
                recommendations.append(
                    ResponseRecommendationModel(
                        id=uuid.uuid4(),
                        recommendation_id=f"REC-{uuid.uuid4().hex[:8].upper()}",
                        case_id=case.case_id,
                        rule_id="REC-RULE-SESS-04",
                        rule_version=cls.VERSION,
                        title="Analyze Multi-Session Temporal Footprint (Strict Non-Attribution)",
                        explanation=(
                            f"Source address '{primary_alert.source_address}' is associated with {source_profile.total_sessions} "
                            "distinct interaction sessions. Recommend evaluating cross-session behavioral consistency while strictly "
                            "avoiding physical identity attribution due to intermediate proxies or VPN relays."
                        ),
                        triggering_evidence={
                            "source_ip": source_profile.source_ip,
                            "total_sessions": source_profile.total_sessions,
                            "profile_priority": source_profile.profile_priority,
                        },
                        supporting_event_ids=[],
                        priority="MEDIUM",
                        confidence="MODERATE",
                        required_permission="execute_defensive_action",
                        requires_approval=False,
                        potential_impact="Links source profile timeline to case workspace.",
                        reversal_guidance="Source profile linkage can be disassociated if determined to be benign co-location.",
                        status="PENDING",
                    )
                )

        # Rule E: Suspected Campaign Association
        if case.primary_cluster_id:
            cluster = db.query(InvestigationClusterModel).filter(
                InvestigationClusterModel.cluster_id == case.primary_cluster_id
            ).first()
            if cluster:
                recommendations.append(
                    ResponseRecommendationModel(
                        id=uuid.uuid4(),
                        recommendation_id=f"REC-{uuid.uuid4().hex[:8].upper()}",
                        case_id=case.case_id,
                        rule_id="REC-RULE-CAMP-05",
                        rule_version=cls.VERSION,
                        title="Coordinate Campaign Investigation & ATT&CK Alignment",
                        explanation=(
                            f"Case is linked to Campaign Investigation Cluster '{cluster.cluster_id}' ({cluster.title}). "
                            "Recommend reviewing linked ATT&CK techniques, verifying shared infrastructure indicators, and "
                            "aligning response steps across participating decoys."
                        ),
                        triggering_evidence={
                            "cluster_id": cluster.cluster_id,
                            "cluster_title": cluster.title,
                            "lifecycle_status": cluster.lifecycle_status,
                            "priority": cluster.priority,
                        },
                        supporting_event_ids=[],
                        priority="HIGH",
                        confidence="HIGH",
                        required_permission="approve_defensive_action",
                        requires_approval=True,
                        potential_impact="Synchronizes case priority with campaign cluster.",
                        reversal_guidance="Cluster linkage can be unlinked in campaign management.",
                        status="PENDING",
                    )
                )

        # Fallback baseline recommendation if none matched
        if not recommendations:
            recommendations.append(
                ResponseRecommendationModel(
                    id=uuid.uuid4(),
                    recommendation_id=f"REC-{uuid.uuid4().hex[:8].upper()}",
                    case_id=case.case_id,
                    rule_id="REC-RULE-GEN-01",
                    rule_version=cls.VERSION,
                    title="Baseline Incident Triage & Evidence Preservation",
                    explanation="Perform initial triage, review linked alert evidence, and determine if an evidence preservation hold is warranted.",
                    triggering_evidence={"case_id": case.case_id, "priority": case.priority},
                    supporting_event_ids=[],
                    priority="LOW",
                    confidence="MODERATE",
                    required_permission="execute_defensive_action",
                    requires_approval=False,
                    potential_impact="Standard triage progression.",
                    reversal_guidance="N/A",
                    status="PENDING",
                )
            )

        return recommendations
