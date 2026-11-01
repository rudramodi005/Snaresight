"""Database seeder for rich Defensive Response Center demonstration cases.

Seeds realistic cases across all priorities (P1_CRITICAL to P4_LOW) and statuses
(OPEN, INVESTIGATING, RESPONSE_RECOMMENDED, AWAITING_APPROVAL, RESOLVED)
along with analyst triage notes, actionable recommendations, approvals, and evidence holds.
"""

from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.db.models.response import (
    ResponseCaseModel,
    CaseNoteModel,
    ResponseRecommendationModel,
    PlaybookExecutionModel,
    ResponseApprovalModel,
    EvidencePreservationHoldModel,
)
from app.db.models.alert import AlertModel
from app.db.models.campaign import InvestigationClusterModel


def seed_response_cases(db: Session) -> None:
    """Seeds rich response cases if fewer than 3 cases exist."""
    count = db.query(ResponseCaseModel).count()
    if count >= 5:
        return

    # Find existing alerts and clusters to bind to
    alert_ids = [str(a.alert_id) for a in db.query(AlertModel).all()]
    cluster_ids = [str(c.cluster_id) for c in db.query(InvestigationClusterModel).all()]
    alert1 = alert_ids[0] if alert_ids else "ALT-001"
    alert2 = alert_ids[1] if len(alert_ids) > 1 else alert1
    alert3 = alert_ids[2] if len(alert_ids) > 2 else alert1
    cluster1 = cluster_ids[0] if cluster_ids else "CAMP-001"
    cluster2 = cluster_ids[1] if len(cluster_ids) > 1 else cluster1

    cases_to_seed = [
        {
            "case_id": "CASE-2026-001",
            "title": "Critical Credential Stuffing & Multi-Sensor Reconnaissance",
            "description": "High-velocity distributed credential stuffing targeting SSH-001 and API gateway decoy endpoints.",
            "priority": "P1_CRITICAL",
            "severity": "CRITICAL",
            "status": "INVESTIGATING",
            "assigned_analyst": "soc_admin",
            "primary_alert_id": alert2,
            "primary_cluster_id": cluster1,
            "created_by": "soc_admin",
            "notes": [
                (
                    "soc_admin",
                    "ADMIN",
                    "TRIAGE_NOTE",
                    "Correlated high-frequency brute force attack with username enumeration heuristics. Escalated priority to P1.",
                ),
                (
                    "soc_lead",
                    "ANALYST",
                    "ANALYST_NOTE",
                    "Initiated forensic retention hold on auth failure events. Recommending dynamic canary honeypot deployment.",
                ),
            ],
            "recommendations": [
                {
                    "recommendation_id": "REC-2026-001",
                    "rule_id": "RULE-HONEYPOT-BOOST",
                    "title": "Honeypot Sensitivity Boost on SSH-001",
                    "explanation": "Elevate logging verbosity and decoy interaction depth on SSH-001 to capture full payload profile.",
                    "priority": "HIGH",
                    "confidence": "HIGH",
                    "status": "PENDING",
                    "requires_approval": True,
                    "potential_impact": "Increases logging disk utilization by approximately 15% on sensor nodes.",
                    "reversal_guidance": "Revert sensor verbosity back to standard operational level via sensor fleet controls.",
                },
                {
                    "recommendation_id": "REC-2026-002",
                    "rule_id": "RULE-CONTAIN-IP",
                    "title": "Contain Aggressive Source IP Range",
                    "explanation": "Route all aggressive traffic from source subnet to isolated high-interaction deception container.",
                    "priority": "CRITICAL",
                    "confidence": "VERY_HIGH",
                    "status": "PENDING",
                    "requires_approval": True,
                    "potential_impact": "Adversary traffic remains in deception sandbox without impacting production resources.",
                    "reversal_guidance": "Remove temporary routing rule from honeypot orchestrator.",
                },
            ],
            "approvals": [
                {
                    "approval_id": "APP-2026-001",
                    "recommendation_id": "REC-2026-001",
                    "action_type": "HONEYPOT_SENSITIVITY_BOOST",
                    "requested_by": "soc_admin",
                    "status": "PENDING",
                    "justification": "Contain active credential stuffing probe and observe payload execution safely.",
                }
            ],
            "holds": [
                {
                    "hold_id": "HOLD-2026-001",
                    "evidence_type": "ALERT",
                    "evidence_identifier": alert2,
                    "retention_hold_status": "ACTIVE",
                    "hold_reason": "Preservation of credential enumeration telemetry for law enforcement & SOC audit.",
                    "applied_by": "soc_admin",
                }
            ],
            "executions": [
                {
                    "execution_id": "EXEC-2026-001",
                    "playbook_id": "PB-AUTH-FAILURES",
                    "initiated_by": "soc_admin",
                    "status": "IN_PROGRESS",
                    "current_step_index": 1,
                    "step_results": [{"step": 1, "action": "VERIFY_TELEMETRY", "status": "COMPLETED"}],
                }
            ],
        },
        {
            "case_id": "CASE-2026-002",
            "title": "Web Application Path Traversal & Probing Campaign",
            "description": "Repeated directory traversal patterns against WEB-001 decoy simulating CVE-2024 path probing.",
            "priority": "P2_HIGH",
            "severity": "HIGH",
            "status": "RESPONSE_RECOMMENDED",
            "assigned_analyst": "soc_lead",
            "primary_alert_id": alert3,
            "primary_cluster_id": cluster2,
            "created_by": "soc_lead",
            "notes": [
                (
                    "soc_lead",
                    "ANALYST",
                    "TRIAGE_NOTE",
                    "Observed directory traversal signatures hitting /etc/passwd decoy traps. Evidence non-destructively preserved.",
                )
            ],
            "recommendations": [
                {
                    "recommendation_id": "REC-2026-003",
                    "rule_id": "RULE-DEPLOY-DECOY",
                    "title": "Deploy Dynamic Canary Honeypot",
                    "explanation": "Spin up an elastic web decoy container to lure traversal scripts deeper into sandbox.",
                    "priority": "HIGH",
                    "confidence": "HIGH",
                    "status": "ACCEPTED",
                    "requires_approval": True,
                    "potential_impact": "Allocates 256MB memory container in local Docker runtime.",
                    "reversal_guidance": "Tear down dynamic honeypot instance via sensor management.",
                }
            ],
            "approvals": [
                {
                    "approval_id": "APP-2026-002",
                    "recommendation_id": "REC-2026-003",
                    "action_type": "DEPLOY_DYNAMIC_HONEYPOT",
                    "requested_by": "soc_lead",
                    "status": "APPROVED",
                    "justification": "Dynamic decoy deployment for enhanced adversary entrapment.",
                    "approved_by": "soc_admin",
                    "decision_reason": "Approved by lead admin for active threat entrapment.",
                    "decision_at": datetime.now(timezone.utc),
                }
            ],
        },
        {
            "case_id": "CASE-2026-003",
            "title": "Distributed Port Enumeration & Decoy Service Sweep",
            "description": "Horizontal TCP SYN sweep across decoy subnet addresses 10.0.1.10 - 10.0.1.50.",
            "priority": "P3_MEDIUM",
            "severity": "MEDIUM",
            "status": "OPEN",
            "assigned_analyst": None,
            "primary_alert_id": alert1,
            "primary_cluster_id": cluster1,
            "created_by": "system",
            "notes": [
                (
                    "system",
                    "SYSTEM",
                    "SYSTEM_NOTE",
                    "Auto-created from threshold violation: 45 decoy connection attempts within 60s.",
                )
            ],
        },
        {
            "case_id": "CASE-2026-004",
            "title": "High-Velocity Multi-Sensor Exploit Delivery",
            "description": "Automated payload transmission observed across HTTP decoy endpoint targeting Apache Struts signatures.",
            "priority": "P1_CRITICAL",
            "severity": "CRITICAL",
            "status": "AWAITING_APPROVAL",
            "assigned_analyst": "soc_admin",
            "primary_alert_id": alert3,
            "primary_cluster_id": cluster2,
            "created_by": "soc_admin",
            "notes": [
                (
                    "soc_admin",
                    "ADMIN",
                    "TRIAGE_NOTE",
                    "Identified weaponized payload in request body. Requesting immediate isolation approval.",
                )
            ],
            "approvals": [
                {
                    "approval_id": "APP-2026-003",
                    "action_type": "ISOLATE_HONEYPOT_SUBNET",
                    "requested_by": "soc_admin",
                    "status": "PENDING",
                    "justification": "Quarantine active sensor bridge to isolate adversarial shell execution.",
                }
            ],
            "holds": [
                {
                    "hold_id": "HOLD-2026-002",
                    "evidence_type": "ALERT",
                    "evidence_identifier": alert3,
                    "retention_hold_status": "ACTIVE",
                    "hold_reason": "Preserve raw exploit payload capture for reverse engineering.",
                    "applied_by": "soc_admin",
                }
            ],
        },
        {
            "case_id": "CASE-2026-005",
            "title": "Routine External Vulnerability Scanner Sweep",
            "description": "Shodan / Censys scanner activity targeting public decoy headers. Identified benign infrastructure sweep.",
            "priority": "P4_LOW",
            "severity": "LOW",
            "status": "RESOLVED",
            "assigned_analyst": "analyst",
            "primary_alert_id": alert1,
            "resolution_category": "BENIGN_TESTING",
            "resolution_summary": "Verified known research IP from scanner range. Decoy telemetry safely logged, no lateral risk detected.",
            "closed_at": datetime.now(timezone.utc),
            "created_by": "analyst",
            "notes": [
                (
                    "analyst",
                    "ANALYST",
                    "RESOLUTION_NOTE",
                    "Verified source ASN corresponds to authorized automated research crawler. Safe to close.",
                )
            ],
        },
    ]

    for cd in cases_to_seed:
        existing = db.query(ResponseCaseModel).filter(ResponseCaseModel.case_id == cd["case_id"]).first()
        if existing:
            existing.status = cd["status"]
            existing.priority = cd["priority"]
        else:
            case_obj = ResponseCaseModel(
                case_id=cd["case_id"],
                title=cd["title"],
                description=cd["description"],
                priority=cd["priority"],
                severity=cd["severity"],
                status=cd["status"],
                assigned_analyst=cd.get("assigned_analyst"),
                primary_alert_id=cd.get("primary_alert_id"),
                primary_cluster_id=cd.get("primary_cluster_id"),
                resolution_category=cd.get("resolution_category"),
                resolution_summary=cd.get("resolution_summary"),
                closed_at=cd.get("closed_at"),
                created_by=cd.get("created_by", "soc_admin"),
            )
            db.add(case_obj)
            db.flush()

        # Notes
        for author, role, ntype, content in cd.get("notes", []):
            existing_note = (
                db.query(CaseNoteModel)
                .filter(CaseNoteModel.case_id == cd["case_id"], CaseNoteModel.content == content)
                .first()
            )
            if not existing_note:
                db.add(
                    CaseNoteModel(
                        case_id=cd["case_id"],
                        author_username=author,
                        author_role=role,
                        note_type=ntype,
                        content=content,
                    )
                )

        # Recommendations
        for rec in cd.get("recommendations", []):
            existing_rec = (
                db.query(ResponseRecommendationModel)
                .filter(ResponseRecommendationModel.recommendation_id == rec["recommendation_id"])
                .first()
            )
            if not existing_rec:
                db.add(
                    ResponseRecommendationModel(
                        case_id=cd["case_id"],
                        recommendation_id=rec["recommendation_id"],
                        rule_id=rec["rule_id"],
                        title=rec["title"],
                        explanation=rec["explanation"],
                        priority=rec["priority"],
                        confidence=rec["confidence"],
                        status=rec["status"],
                        requires_approval=rec["requires_approval"],
                        potential_impact=rec["potential_impact"],
                        reversal_guidance=rec["reversal_guidance"],
                    )
                )

        # Approvals
        for app in cd.get("approvals", []):
            existing_app = (
                db.query(ResponseApprovalModel)
                .filter(ResponseApprovalModel.approval_id == app["approval_id"])
                .first()
            )
            if not existing_app:
                db.add(
                    ResponseApprovalModel(
                        case_id=cd["case_id"],
                        approval_id=app["approval_id"],
                        recommendation_id=app.get("recommendation_id"),
                        action_type=app["action_type"],
                        requested_by=app["requested_by"],
                        status=app["status"],
                        justification=app["justification"],
                        approved_by=app.get("approved_by"),
                        decision_reason=app.get("decision_reason"),
                        decision_at=app.get("decision_at"),
                    )
                )

        # Holds
        for hold in cd.get("holds", []):
            existing_hold = (
                db.query(EvidencePreservationHoldModel)
                .filter(EvidencePreservationHoldModel.hold_id == hold["hold_id"])
                .first()
            )
            if not existing_hold:
                db.add(
                    EvidencePreservationHoldModel(
                        case_id=cd["case_id"],
                        hold_id=hold["hold_id"],
                        evidence_type=hold["evidence_type"],
                        evidence_identifier=hold["evidence_identifier"],
                        retention_hold_status=hold["retention_hold_status"],
                        hold_reason=hold["hold_reason"],
                        applied_by=hold["applied_by"],
                    )
                )

        # Executions
        for exec_item in cd.get("executions", []):
            existing_exec = (
                db.query(PlaybookExecutionModel)
                .filter(PlaybookExecutionModel.execution_id == exec_item["execution_id"])
                .first()
            )
            if not existing_exec:
                db.add(
                    PlaybookExecutionModel(
                        case_id=cd["case_id"],
                        execution_id=exec_item["execution_id"],
                        playbook_id=exec_item["playbook_id"],
                        initiated_by=exec_item["initiated_by"],
                        status=exec_item["status"],
                        current_step_index=exec_item["current_step_index"],
                        step_results=exec_item["step_results"],
                        inputs={},
                    )
                )

    db.commit()
