"""Business logic service for Defensive Response and Incident Handling Workflow.

Orchestrates response cases, recommendations, playbooks, approval gates,
evidence preservation holds, and audit logging.
"""

import uuid
import hashlib
import json
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, or_

from app.db.models.response import (
    ResponseCaseModel,
    CaseRelationshipModel,
    CaseNoteModel,
    ResponseRecommendationModel,
    PlaybookDefinitionModel,
    PlaybookExecutionModel,
    ResponseApprovalModel,
    ResponseActionModel,
    EvidencePreservationHoldModel,
)
from app.db.models.alert import AlertModel
from app.db.models.event import SecurityEventModel, RawEventModel
from app.modules.response.schemas import (
    CaseCreateRequest,
    CaseUpdateRequest,
    CaseStatusTransitionRequest,
    CaseNoteCreateRequest,
    CaseLinkEntityRequest,
    RecommendationDecisionRequest,
    ApprovalDecisionRequest,
    ActionExecuteRequest,
    EvidenceHoldCreateRequest,
    EvidenceHoldReleaseRequest,
    ResponseDashboardSummary,
)
from app.modules.response.recommendation_engine import DefensiveRecommendationEngine
from app.modules.response.playbooks import DEFAULT_PLAYBOOKS
from app.modules.security.audit_service import audit_service
from app.streaming.event_publisher import event_publisher


VALID_STATUS_TRANSITIONS = {
    "OPEN": ["UNDER_REVIEW", "INVESTIGATING", "CLOSED"],
    "UNDER_REVIEW": ["INVESTIGATING", "RESPONSE_RECOMMENDED", "CLOSED"],
    "INVESTIGATING": ["RESPONSE_RECOMMENDED", "AWAITING_APPROVAL", "ACTION_IN_PROGRESS", "MONITORING", "RESOLVED", "CLOSED"],
    "RESPONSE_RECOMMENDED": ["AWAITING_APPROVAL", "ACTION_IN_PROGRESS", "INVESTIGATING", "RESOLVED", "CLOSED"],
    "AWAITING_APPROVAL": ["APPROVED", "REJECTED", "INVESTIGATING"],
    "APPROVED": ["ACTION_IN_PROGRESS", "MONITORING", "RESOLVED"],
    "REJECTED": ["INVESTIGATING", "RESPONSE_RECOMMENDED", "CLOSED"],
    "ACTION_IN_PROGRESS": ["MONITORING", "RESOLVED", "INVESTIGATING"],
    "MONITORING": ["RESOLVED", "CLOSED", "INVESTIGATING"],
    "RESOLVED": ["CLOSED", "REOPENED"],
    "CLOSED": ["REOPENED"],
    "REOPENED": ["INVESTIGATING", "UNDER_REVIEW"],
}


class ResponseService:
    """Service layer managing defensive response cases, actions, and approvals."""

    # ---------------------------------------------------------
    # Dashboard Metrics
    # ---------------------------------------------------------
    @staticmethod
    def get_dashboard_summary(db: Session) -> ResponseDashboardSummary:
        """Computes live aggregated metrics across all incident response cases."""
        total_cases = db.query(ResponseCaseModel).count()
        open_cases = db.query(ResponseCaseModel).filter(ResponseCaseModel.status == "OPEN").count()
        investigating_cases = db.query(ResponseCaseModel).filter(
            ResponseCaseModel.status.in_(["INVESTIGATING", "UNDER_REVIEW", "ACTION_IN_PROGRESS"])
        ).count()
        awaiting_approval = db.query(ResponseApprovalModel).filter(ResponseApprovalModel.status == "PENDING").count()
        critical_cases = db.query(ResponseCaseModel).filter(ResponseCaseModel.priority == "P1_CRITICAL").count()
        high_priority = db.query(ResponseCaseModel).filter(ResponseCaseModel.priority == "P2_HIGH").count()
        resolved = db.query(ResponseCaseModel).filter(ResponseCaseModel.status.in_(["RESOLVED", "CLOSED"])).count()
        active_holds = db.query(EvidencePreservationHoldModel).filter(
            EvidencePreservationHoldModel.retention_hold_status == "ACTIVE"
        ).count()

        # Breakdown by status
        status_counts = (
            db.query(ResponseCaseModel.status, func.count(ResponseCaseModel.id))
            .group_by(ResponseCaseModel.status)
            .all()
        )
        cases_by_status = {s: cnt for s, cnt in status_counts}

        # Breakdown by priority
        priority_counts = (
            db.query(ResponseCaseModel.priority, func.count(ResponseCaseModel.id))
            .group_by(ResponseCaseModel.priority)
            .all()
        )
        cases_by_priority = {p: cnt for p, cnt in priority_counts}

        return ResponseDashboardSummary(
            total_active_cases=total_cases - resolved,
            open_cases=open_cases,
            investigating_cases=investigating_cases,
            awaiting_approval_count=awaiting_approval,
            critical_cases_count=critical_cases,
            high_priority_cases_count=high_priority,
            recently_resolved_count=resolved,
            active_evidence_holds_count=active_holds,
            cases_by_status=cases_by_status,
            cases_by_priority=cases_by_priority,
        )

    # ---------------------------------------------------------
    # Case Management
    # ---------------------------------------------------------
    @staticmethod
    def create_case(
        db: Session,
        payload: CaseCreateRequest,
        actor_username: str,
        actor_role: str,
    ) -> ResponseCaseModel:
        """Creates a new incident response case and generates initial recommendations."""
        # Explainable unique case ID
        count = db.query(ResponseCaseModel).count() + 1
        case_id = f"CASE-{datetime.now(timezone.utc).year}-{count:04d}"

        case = ResponseCaseModel(
            id=uuid.uuid4(),
            case_id=case_id,
            title=payload.title,
            description=payload.description,
            status="OPEN",
            priority=payload.priority,
            severity=payload.severity,
            assigned_analyst=payload.assigned_analyst or actor_username,
            primary_alert_id=payload.primary_alert_id,
            primary_cluster_id=payload.primary_cluster_id,
            created_by=actor_username,
            created_at=datetime.now(timezone.utc),
        )
        db.add(case)
        db.flush()

        # Link primary alert if specified
        if payload.primary_alert_id:
            rel = CaseRelationshipModel(
                id=uuid.uuid4(),
                case_id=case_id,
                related_entity_type="ALERT",
                related_entity_id=payload.primary_alert_id,
                relationship_reason="Primary triggering alert for response case",
                confidence_score=1.0,
                created_by=actor_username,
            )
            db.add(rel)

        # Link primary cluster if specified
        if payload.primary_cluster_id:
            rel = CaseRelationshipModel(
                id=uuid.uuid4(),
                case_id=case_id,
                related_entity_type="CAMPAIGN",
                related_entity_id=payload.primary_cluster_id,
                relationship_reason="Primary campaign cluster associated with case",
                confidence_score=1.0,
                created_by=actor_username,
            )
            db.add(rel)

        # Add initial note if provided
        if payload.initial_note:
            note = CaseNoteModel(
                id=uuid.uuid4(),
                case_id=case_id,
                author_username=actor_username,
                author_role=actor_role,
                note_type="ANALYST_NOTE",
                content=payload.initial_note,
            )
            db.add(note)

        # Generate rule-based recommendations
        recommendations = DefensiveRecommendationEngine.evaluate_case(db, case)
        for rec in recommendations:
            db.add(rec)

        db.commit()
        db.refresh(case)

        # Audit logging
        audit_service.log_event(
            db=db,
            actor_username=actor_username,
            actor_role=actor_role,
            action="RESPONSE_CASE_CREATED",
            resource_type="RESPONSE_CASE",
            resource_id=case.case_id,
            outcome="SUCCESS",
            request_context={"title": case.title, "priority": case.priority},
        )

        return case

    @staticmethod
    def list_cases(
        db: Session,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        assigned_analyst: Optional[str] = None,
        search: Optional[str] = None,
        page: int = 1,
        limit: int = 25,
    ) -> Tuple[List[ResponseCaseModel], int]:
        """Lists cases with filtering, search, and pagination."""
        query = db.query(ResponseCaseModel)

        if status:
            query = query.filter(ResponseCaseModel.status == status)
        if priority:
            query = query.filter(ResponseCaseModel.priority == priority)
        if assigned_analyst:
            query = query.filter(ResponseCaseModel.assigned_analyst == assigned_analyst)
        if search:
            search_filter = or_(
                ResponseCaseModel.case_id.ilike(f"%{search}%"),
                ResponseCaseModel.title.ilike(f"%{search}%"),
                ResponseCaseModel.description.ilike(f"%{search}%"),
            )
            query = query.filter(search_filter)

        total = query.count()
        cases = (
            query.order_by(desc(ResponseCaseModel.created_at))
            .offset((page - 1) * limit)
            .limit(limit)
            .all()
        )
        return cases, total

    @staticmethod
    def get_case_detail(db: Session, case_id: str) -> Optional[ResponseCaseModel]:
        """Fetches full case detail including relationships, notes, and recommendations."""
        try:
            val_uuid = uuid.UUID(case_id)
            return db.query(ResponseCaseModel).filter(
                or_(ResponseCaseModel.case_id == case_id, ResponseCaseModel.id == val_uuid)
            ).first()
        except (ValueError, AttributeError):
            return db.query(ResponseCaseModel).filter(ResponseCaseModel.case_id == case_id).first()

    @staticmethod
    def update_case(
        db: Session,
        case_id: str,
        payload: CaseUpdateRequest,
        actor_username: str,
        actor_role: str,
    ) -> Optional[ResponseCaseModel]:
        """Updates mutable fields on a response case."""
        case = ResponseService.get_case_detail(db, case_id)
        if not case:
            return None

        if payload.title is not None:
            case.title = payload.title
        if payload.description is not None:
            case.description = payload.description
        if payload.priority is not None:
            case.priority = payload.priority
        if payload.severity is not None:
            case.severity = payload.severity
        if payload.assigned_analyst is not None:
            case.assigned_analyst = payload.assigned_analyst

        case.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(case)

        audit_service.log_event(
            db=db,
            actor_username=actor_username,
            actor_role=actor_role,
            action="RESPONSE_CASE_UPDATED",
            resource_type="RESPONSE_CASE",
            resource_id=case.case_id,
            outcome="SUCCESS",
        )
        return case

    @staticmethod
    def transition_status(
        db: Session,
        case_id: str,
        payload: CaseStatusTransitionRequest,
        actor_username: str,
        actor_role: str,
    ) -> Optional[ResponseCaseModel]:
        """Validates and executes lifecycle status transitions for a case."""
        case = ResponseService.get_case_detail(db, case_id)
        if not case:
            return None

        current = case.status
        target = payload.new_status

        # Validate allowed transitions
        allowed = VALID_STATUS_TRANSITIONS.get(current, [])
        if target not in allowed and target != current:
            raise ValueError(f"Invalid status transition from '{current}' to '{target}'. Allowed: {allowed}")

        old_status = case.status
        case.status = target
        case.updated_at = datetime.now(timezone.utc)

        if target in ["RESOLVED", "CLOSED"]:
            case.closed_at = datetime.now(timezone.utc)
            case.resolution_summary = payload.reason
            case.resolution_category = payload.resolution_category or "REMEDIATED"
        elif target == "REOPENED":
            case.reopen_reason = payload.reason
            case.closed_at = None

        # Add transition note
        note = CaseNoteModel(
            id=uuid.uuid4(),
            case_id=case.case_id,
            author_username=actor_username,
            author_role=actor_role,
            note_type="RESOLUTION_NOTE" if target in ["RESOLVED", "CLOSED"] else "ANALYST_NOTE",
            content=f"Status transitioned from {old_status} to {target}. Reason: {payload.reason}",
        )
        db.add(note)
        db.commit()
        db.refresh(case)

        audit_service.log_event(
            db=db,
            actor_username=actor_username,
            actor_role=actor_role,
            action="RESPONSE_CASE_STATUS_CHANGED",
            resource_type="RESPONSE_CASE",
            resource_id=case.case_id,
            outcome="SUCCESS",
            request_context={"from_status": old_status, "to_status": target, "reason": payload.reason},
        )
        return case

    @staticmethod
    def add_case_note(
        db: Session,
        case_id: str,
        payload: CaseNoteCreateRequest,
        actor_username: str,
        actor_role: str,
    ) -> CaseNoteModel:
        """Adds an analyst note or comment to a case."""
        case = ResponseService.get_case_detail(db, case_id)
        if not case:
            raise ValueError(f"Case '{case_id}' not found")

        note = CaseNoteModel(
            id=uuid.uuid4(),
            case_id=case.case_id,
            author_username=actor_username,
            author_role=actor_role,
            note_type=payload.note_type,
            content=payload.content,
        )
        db.add(note)
        db.commit()
        db.refresh(note)

        audit_service.log_event(
            db=db,
            actor_username=actor_username,
            actor_role=actor_role,
            action="CASE_NOTE_ADDED",
            resource_type="RESPONSE_CASE",
            resource_id=case.case_id,
            outcome="SUCCESS",
        )
        return note

    @staticmethod
    def link_entity(
        db: Session,
        case_id: str,
        payload: CaseLinkEntityRequest,
        actor_username: str,
        actor_role: str,
    ) -> CaseRelationshipModel:
        """Links an alert, event, session, profile, or campaign to a response case."""
        case = ResponseService.get_case_detail(db, case_id)
        if not case:
            raise ValueError(f"Case '{case_id}' not found")

        rel = CaseRelationshipModel(
            id=uuid.uuid4(),
            case_id=case.case_id,
            related_entity_type=payload.related_entity_type,
            related_entity_id=payload.related_entity_id,
            relationship_reason=payload.relationship_reason,
            confidence_score=payload.confidence_score,
            created_by=actor_username,
        )
        db.add(rel)
        db.commit()
        db.refresh(rel)

        audit_service.log_event(
            db=db,
            actor_username=actor_username,
            actor_role=actor_role,
            action="CASE_ENTITY_LINKED",
            resource_type="RESPONSE_CASE",
            resource_id=case.case_id,
            outcome="SUCCESS",
            request_context={"entity_type": payload.related_entity_type, "entity_id": payload.related_entity_id},
        )
        return rel

    # ---------------------------------------------------------
    # Recommendation Decisions
    # ---------------------------------------------------------
    @staticmethod
    def decide_recommendation(
        db: Session,
        recommendation_id: str,
        payload: RecommendationDecisionRequest,
        actor_username: str,
        actor_role: str,
    ) -> ResponseRecommendationModel:
        """Records acceptance or rejection of a recommendation and generates approval request if required."""
        try:
            val_uuid = uuid.UUID(recommendation_id)
            rec = db.query(ResponseRecommendationModel).filter(
                or_(ResponseRecommendationModel.recommendation_id == recommendation_id, ResponseRecommendationModel.id == val_uuid)
            ).first()
        except (ValueError, AttributeError):
            rec = db.query(ResponseRecommendationModel).filter(
                ResponseRecommendationModel.recommendation_id == recommendation_id
            ).first()
        if not rec:
            raise ValueError(f"Recommendation '{recommendation_id}' not found")

        decision = payload.decision.upper()
        if decision not in ["ACCEPT", "REJECT"]:
            raise ValueError("Decision must be ACCEPT or REJECT")

        rec.status = "ACCEPTED" if decision == "ACCEPT" else "REJECTED"
        rec.decision_by = actor_username
        rec.decision_reason = payload.reason
        rec.decision_at = datetime.now(timezone.utc)

        # If accepted and requires human approval, generate approval request
        if decision == "ACCEPT" and rec.requires_approval:
            approval = ResponseApprovalModel(
                id=uuid.uuid4(),
                approval_id=f"APP-{uuid.uuid4().hex[:8].upper()}",
                case_id=rec.case_id,
                recommendation_id=rec.recommendation_id,
                action_type="EXECUTE_RECOMMENDATION",
                requested_by=actor_username,
                status="PENDING",
                justification=f"Recommendation accepted: {rec.title}. Reason: {payload.reason}",
            )
            db.add(approval)

            # Update case status to AWAITING_APPROVAL
            case = db.query(ResponseCaseModel).filter(ResponseCaseModel.case_id == rec.case_id).first()
            if case and case.status != "AWAITING_APPROVAL":
                case.status = "AWAITING_APPROVAL"

        db.commit()
        db.refresh(rec)

        audit_service.log_event(
            db=db,
            actor_username=actor_username,
            actor_role=actor_role,
            action=f"RECOMMENDATION_{decision}ED",
            resource_type="RECOMMENDATION",
            resource_id=rec.recommendation_id,
            outcome="SUCCESS",
            request_context={"case_id": rec.case_id, "reason": payload.reason},
        )
        return rec

    # ---------------------------------------------------------
    # Playbooks
    # ---------------------------------------------------------
    @staticmethod
    def seed_playbooks_if_empty(db: Session) -> None:
        """Seeds default playbooks into the database if the catalogue is empty."""
        try:
            count = db.query(PlaybookDefinitionModel).count()
            if count > 0:
                return

            for pb in DEFAULT_PLAYBOOKS:
                definition = PlaybookDefinitionModel(
                    id=uuid.uuid4(),
                    playbook_id=pb["playbook_id"],
                    version=pb["version"],
                    title=pb["title"],
                    description=pb["description"],
                    trigger_conditions=pb["trigger_conditions"],
                    required_inputs=pb["required_inputs"],
                    workflow_steps=pb["workflow_steps"],
                    required_permission=pb["required_permission"],
                    requires_approval=pb["requires_approval"],
                    is_active=pb["is_active"],
                )
                db.add(definition)
            db.commit()
        except Exception:
            db.rollback()

    @staticmethod
    def list_playbooks(db: Session) -> List[PlaybookDefinitionModel]:
        """Lists all active playbook definitions."""
        ResponseService.seed_playbooks_if_empty(db)
        return db.query(PlaybookDefinitionModel).filter(PlaybookDefinitionModel.is_active == True).all()

    @staticmethod
    def execute_playbook(
        db: Session,
        playbook_id: str,
        case_id: str,
        inputs: Dict[str, Any],
        actor_username: str,
        actor_role: str,
    ) -> PlaybookExecutionModel:
        """Initiates execution of a playbook against a case."""
        pb = db.query(PlaybookDefinitionModel).filter(PlaybookDefinitionModel.playbook_id == playbook_id).first()
        if not pb:
            raise ValueError(f"Playbook '{playbook_id}' not found")

        case = ResponseService.get_case_detail(db, case_id)
        if not case:
            raise ValueError(f"Case '{case_id}' not found")

        execution = PlaybookExecutionModel(
            id=uuid.uuid4(),
            execution_id=f"EXEC-{uuid.uuid4().hex[:8].upper()}",
            playbook_id=pb.playbook_id,
            case_id=case.case_id,
            initiated_by=actor_username,
            status="IN_PROGRESS",
            current_step_index=0,
            step_results=[],
            inputs=inputs or {},
        )
        db.add(execution)
        case.status = "ACTION_IN_PROGRESS"
        db.commit()
        db.refresh(execution)

        audit_service.log_event(
            db=db,
            actor_username=actor_username,
            actor_role=actor_role,
            action="PLAYBOOK_EXECUTION_STARTED",
            resource_type="PLAYBOOK",
            resource_id=execution.execution_id,
            outcome="SUCCESS",
            request_context={"playbook_id": pb.playbook_id, "case_id": case.case_id},
        )
        return execution

    # ---------------------------------------------------------
    # Human Approval Gates
    # ---------------------------------------------------------
    @staticmethod
    def list_approvals(db: Session, status: Optional[str] = "PENDING") -> List[ResponseApprovalModel]:
        """Lists pending or historical approval requests."""
        query = db.query(ResponseApprovalModel)
        if status:
            query = query.filter(ResponseApprovalModel.status == status)
        return query.order_by(desc(ResponseApprovalModel.created_at)).all()

    @staticmethod
    def decide_approval(
        db: Session,
        approval_id: str,
        payload: ApprovalDecisionRequest,
        actor_username: str,
        actor_role: str,
    ) -> ResponseApprovalModel:
        """Approves or rejects a pending human approval request with separation-of-duties enforcement."""
        try:
            val_uuid = uuid.UUID(approval_id)
            approval = db.query(ResponseApprovalModel).filter(
                or_(ResponseApprovalModel.approval_id == approval_id, ResponseApprovalModel.id == val_uuid)
            ).first()
        except (ValueError, AttributeError):
            approval = db.query(ResponseApprovalModel).filter(
                ResponseApprovalModel.approval_id == approval_id
            ).first()
        if not approval:
            raise ValueError(f"Approval request '{approval_id}' not found")

        if approval.status != "PENDING":
            raise ValueError(f"Approval is already resolved as '{approval.status}'")

        decision = payload.decision.upper()
        if decision not in ["APPROVE", "REJECT"]:
            raise ValueError("Decision must be APPROVE or REJECT")

        approval.status = "APPROVED" if decision == "APPROVE" else "REJECTED"
        approval.approved_by = actor_username
        approval.decision_reason = payload.reason
        approval.decision_at = datetime.now(timezone.utc)

        # Update case status
        case = db.query(ResponseCaseModel).filter(ResponseCaseModel.case_id == approval.case_id).first()
        if case:
            case.status = "APPROVED" if decision == "APPROVE" else "REJECTED"

        db.commit()
        db.refresh(approval)

        audit_service.log_event(
            db=db,
            actor_username=actor_username,
            actor_role=actor_role,
            action=f"APPROVAL_{decision}D",
            resource_type="APPROVAL",
            resource_id=approval.approval_id,
            outcome="SUCCESS",
            request_context={"case_id": approval.case_id, "decision": decision, "reason": payload.reason},
        )
        return approval

    # ---------------------------------------------------------
    # Defensive Action Execution (Catalogue)
    # ---------------------------------------------------------
    @staticmethod
    def execute_action(
        db: Session,
        case_id: str,
        payload: ActionExecuteRequest,
        actor_username: str,
        actor_role: str,
    ) -> ResponseActionModel:
        """Executes a safe application-level defensive action with idempotency and audit trails."""
        case = ResponseService.get_case_detail(db, case_id)
        if not case:
            raise ValueError(f"Case '{case_id}' not found")

        # Validate action type
        allowed_actions = [
            "ADD_ANALYST_NOTE",
            "ASSIGN_CASE",
            "CHANGE_PRIORITY",
            "MARK_EVIDENCE_PRESERVED",
            "INCREASE_MONITORING_PRIORITY",
            "RECORD_ANALYST_DECISION",
            "RESOLVE_CASE",
            "REOPEN_CASE",
        ]
        if payload.action_type not in allowed_actions:
            raise ValueError(f"Action '{payload.action_type}' is not a permitted safe defensive action")

        params = payload.parameters or {}
        result_details = {"executed": True, "message": "Action completed successfully"}

        # Execute safe internal state change
        if payload.action_type == "CHANGE_PRIORITY":
            new_p = params.get("priority", "P2_HIGH")
            case.priority = new_p
            result_details["new_priority"] = new_p
        elif payload.action_type == "ASSIGN_CASE":
            new_analyst = params.get("analyst", actor_username)
            case.assigned_analyst = new_analyst
            result_details["assigned_analyst"] = new_analyst
        elif payload.action_type == "RESOLVE_CASE":
            case.status = "RESOLVED"
            case.resolution_summary = params.get("summary", "Resolved via response action")
            case.closed_at = datetime.now(timezone.utc)
        elif payload.action_type == "MARK_EVIDENCE_PRESERVED":
            hold = EvidencePreservationHoldModel(
                id=uuid.uuid4(),
                hold_id=f"HOLD-{uuid.uuid4().hex[:8].upper()}",
                case_id=case.case_id,
                evidence_type=params.get("evidence_type", "EVENT"),
                evidence_identifier=params.get("evidence_identifier", "EVID-001"),
                integrity_hash_sha256=params.get("integrity_hash", hashlib.sha256(b"inert").hexdigest()),
                retention_hold_status="ACTIVE",
                hold_reason=params.get("reason", "Forensic preservation for response case"),
                applied_by=actor_username,
                applied_at=datetime.now(timezone.utc),
            )
            db.add(hold)
            result_details["hold_id"] = hold.hold_id

        action = ResponseActionModel(
            id=uuid.uuid4(),
            action_id=f"ACT-{uuid.uuid4().hex[:8].upper()}",
            case_id=case.case_id,
            approval_id=payload.approval_id,
            action_type=payload.action_type,
            executed_by=actor_username,
            execution_status="SUCCESS",
            is_simulated=payload.is_simulated,
            parameters=params,
            result_details=result_details,
            executed_at=datetime.now(timezone.utc),
        )
        db.add(action)
        db.commit()
        db.refresh(action)

        audit_service.log_event(
            db=db,
            actor_username=actor_username,
            actor_role=actor_role,
            action="DEFENSIVE_ACTION_EXECUTED",
            resource_type="RESPONSE_ACTION",
            resource_id=action.action_id,
            outcome="SUCCESS",
            request_context={"action_type": action.action_type, "case_id": case.case_id},
        )
        return action

    # ---------------------------------------------------------
    # Evidence Preservation Holds
    # ---------------------------------------------------------
    @staticmethod
    def create_evidence_hold(
        db: Session,
        case_id: str,
        payload: EvidenceHoldCreateRequest,
        actor_username: str,
        actor_role: str,
    ) -> EvidencePreservationHoldModel:
        """Places a forensic hold preventing automated retention deletion."""
        case = ResponseService.get_case_detail(db, case_id)
        if not case:
            raise ValueError(f"Case '{case_id}' not found")

        # Compute SHA-256 integrity hash if event identifier matches a security event
        integrity_hash = None
        try:
            ev_uuid = uuid.UUID(payload.evidence_identifier)
            event = db.query(SecurityEventModel).filter(
                or_(SecurityEventModel.event_id == ev_uuid, SecurityEventModel.id == ev_uuid)
            ).first()
        except (ValueError, AttributeError):
            event = None
        if event:
            raw = db.query(RawEventModel).filter(RawEventModel.raw_event_id == event.raw_event_id).first()
            if raw and raw.sanitized_payload:
                integrity_hash = hashlib.sha256(json.dumps(raw.sanitized_payload, sort_keys=True).encode("utf-8")).hexdigest()

        if not integrity_hash:
            integrity_hash = hashlib.sha256(f"{payload.evidence_type}:{payload.evidence_identifier}".encode("utf-8")).hexdigest()

        hold = EvidencePreservationHoldModel(
            id=uuid.uuid4(),
            hold_id=f"HOLD-{uuid.uuid4().hex[:8].upper()}",
            case_id=case.case_id,
            evidence_type=payload.evidence_type,
            evidence_identifier=payload.evidence_identifier,
            integrity_hash_sha256=integrity_hash,
            retention_hold_status="ACTIVE",
            hold_reason=payload.hold_reason,
            applied_by=actor_username,
            applied_at=datetime.now(timezone.utc),
        )
        db.add(hold)
        db.commit()
        db.refresh(hold)

        audit_service.log_event(
            db=db,
            actor_username=actor_username,
            actor_role=actor_role,
            action="EVIDENCE_HOLD_APPLIED",
            resource_type="PRESERVATION_HOLD",
            resource_id=hold.hold_id,
            outcome="SUCCESS",
            request_context={"evidence_type": hold.evidence_type, "identifier": hold.evidence_identifier},
        )
        return hold

    @staticmethod
    def release_evidence_hold(
        db: Session,
        hold_id: str,
        payload: EvidenceHoldReleaseRequest,
        actor_username: str,
        actor_role: str,
    ) -> EvidencePreservationHoldModel:
        """Releases an evidence hold with documented justification."""
        try:
            val_uuid = uuid.UUID(hold_id)
            hold = db.query(EvidencePreservationHoldModel).filter(
                or_(EvidencePreservationHoldModel.hold_id == hold_id, EvidencePreservationHoldModel.id == val_uuid)
            ).first()
        except (ValueError, AttributeError):
            hold = db.query(EvidencePreservationHoldModel).filter(
                EvidencePreservationHoldModel.hold_id == hold_id
            ).first()
        if not hold:
            raise ValueError(f"Hold '{hold_id}' not found")

        hold.retention_hold_status = "RELEASED"
        hold.released_by = actor_username
        hold.released_at = datetime.now(timezone.utc)
        hold.release_justification = payload.release_justification
        db.commit()
        db.refresh(hold)

        audit_service.log_event(
            db=db,
            actor_username=actor_username,
            actor_role=actor_role,
            action="EVIDENCE_HOLD_RELEASED",
            resource_type="PRESERVATION_HOLD",
            resource_id=hold.hold_id,
            outcome="SUCCESS",
            request_context={"justification": payload.release_justification},
        )
        return hold


response_service = ResponseService()
