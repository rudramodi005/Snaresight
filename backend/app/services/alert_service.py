"""Security Alert generation, cooldown suppression, and persistence service for SnareSight.

Binds threat detection results and P17 severity/confidence assessments to persistent
database records, maintains auditable suppression, and broadcasts post-commit streaming notifications.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple
from sqlalchemy.orm import Session
from app.db.models.alert import AlertModel, AlertEvidenceModel
from app.db.models.rule import DetectionRuleModel
from app.db.models.honeypot import HoneypotModel
from app.detection.assessment_result import ThreatAssessmentResult
from app.detection.registry import RuleRegistry, rule_registry
from app.schemas.detection import DetectionResult, EvaluationStatus
from app.services.threat_assessment_service import ThreatAssessmentService, threat_assessment_service
from app.streaming.event_publisher import EventPublisher, event_publisher


class AlertSuppressionRule:
    """Specification for suppression of repetitive or expected false-positive alerts."""

    def __init__(
        self,
        suppression_id: str,
        rule_id: Optional[str] = None,
        session_id: Optional[str] = None,
        decoy_id: Optional[str] = None,
        source_address: Optional[str] = None,
        reason: str = "Automated false-positive suppression",
        created_at: Optional[datetime] = None,
    ):
        self.suppression_id = suppression_id
        self.rule_id = rule_id
        self.session_id = session_id
        self.decoy_id = decoy_id
        self.source_address = source_address
        self.reason = reason
        self.created_at = created_at or datetime.now(timezone.utc)

    def matches(
        self,
        rule_id: str,
        session_id: Optional[str] = None,
        decoy_id: Optional[str] = None,
        source_address: Optional[str] = None,
    ) -> bool:
        """Determines if the given context matches the suppression criteria."""
        if self.rule_id and self.rule_id != rule_id:
            return False
        if self.session_id and self.session_id != session_id:
            return False
        if self.decoy_id and self.decoy_id != decoy_id:
            return False
        if self.source_address and self.source_address != source_address:
            return False
        return True


class AlertService:
    """Coordinates alert creation, cooldown deduplication, persistence, and notifications."""

    DEFAULT_COOLDOWN_SECONDS = 300  # 5-minute cooldown per (rule_id, session_id)

    def __init__(
        self,
        rules: Optional[RuleRegistry] = None,
        assessment_svc: Optional[ThreatAssessmentService] = None,
        publisher: Optional[EventPublisher] = None,
    ):
        self.rules = rules or rule_registry
        self.assessment_svc = assessment_svc or threat_assessment_service
        self.publisher = publisher or event_publisher

        # In-memory cooldown tracker: {(rule_id, session_id): last_generated_datetime}
        self._cooldown_tracker: Dict[Tuple[str, str], datetime] = {}
        # Active suppression rules
        self._suppression_rules: Dict[str, AlertSuppressionRule] = {}
        # Auditable suppression history
        self._suppression_audit_log: List[Dict[str, Any]] = []

    def create_alert(
        self,
        db: Session,
        detection_result: DetectionResult,
        event: Dict[str, Any],
        related_events: Optional[List[Dict[str, Any]]] = None,
        cooldown_seconds: Optional[int] = None,
    ) -> Optional[AlertModel]:
        """Creates and commits an explainable security alert for a MATCHED detection result.
        
        Guarantees:
        - Only evaluates MATCHED detection results; non-matching results return None.
        - Enforces idempotency: duplicate evaluations return the existing alert.
        - Enforces cooldown intervals to prevent alert flooding.
        - Evaluates auditable suppression rules without deleting underlying events.
        - Post-commit SSE notification broadcast; streaming errors never abort DB transactions.
        """
        # 1. Gate: Strictly MATCHED results only
        if detection_result.evaluation_status != EvaluationStatus.MATCHED:
            return None

        rule_id = detection_result.rule_id
        rule_version = detection_result.rule_version
        session_id = str(event.get("session_id", ""))
        decoy_id = str(event.get("decoy_id", "WEB-001"))
        source_address = str(event.get("source_address", "127.0.0.1"))
        observed_source_id = str(event.get("observed_source_id") or "collector-web-01")
        target_service = str(event.get("target_service", "WEB_LOGIN"))

        # 2. Check Suppression Rules
        is_suppressed, supp_reason = self.is_suppressed(
            rule_id=rule_id,
            session_id=session_id,
            decoy_id=decoy_id,
            source_address=source_address,
        )
        if is_suppressed:
            self._record_suppression_audit(
                rule_id=rule_id,
                session_id=session_id,
                decoy_id=decoy_id,
                source_address=source_address,
                reason=supp_reason,
            )
            return None

        # 3. Check Cooldown Suppression
        now_utc = datetime.now(timezone.utc)
        cooldown = cooldown_seconds if cooldown_seconds is not None else self.DEFAULT_COOLDOWN_SECONDS
        cooldown_key = (rule_id, session_id)

        if cooldown_key in self._cooldown_tracker:
            last_alert_time = self._cooldown_tracker[cooldown_key]
            if (now_utc - last_alert_time).total_seconds() < cooldown:
                # Suppressed due to active cooldown window
                self._record_suppression_audit(
                    rule_id=rule_id,
                    session_id=session_id,
                    decoy_id=decoy_id,
                    source_address=source_address,
                    reason=f"Suppressed by cooldown interval ({cooldown}s) for session '{session_id}'",
                )
                return None

        # 4. Check Database Idempotency (Existing Alert for same evaluated_event_id and rule_id)
        existing_alert = (
            db.query(AlertModel)
            .filter(
                AlertModel.detection_rule_id == rule_id,
                AlertModel.detection_rule_version == rule_version,
            )
            .join(AlertEvidenceModel, AlertModel.alert_id == AlertEvidenceModel.alert_id)
            .filter(AlertEvidenceModel.event_id == uuid.UUID(str(event.get("event_id"))))
            .first()
        )
        if existing_alert:
            return existing_alert

        # 5. P17 Threat Assessment (Severity, Confidence, Evidence Strength)
        assessment = self.assessment_svc.assess_detection(
            detection_result=detection_result,
            event=event,
            related_events=related_events,
            db=db,
        )

        # 6. Ensure referenced honeypot exists in DB
        decoy_record = db.query(HoneypotModel).filter(HoneypotModel.decoy_id == decoy_id).first()
        if not decoy_record:
            decoy_record = HoneypotModel(
                decoy_id=decoy_id,
                name=f"Decoy {decoy_id}",
                decoy_type="WEB_LOGIN" if decoy_id.startswith("WEB") else "SSH_DAEMON",
                protocol="HTTP" if decoy_id.startswith("WEB") else "SSH",
                environment=event.get("provenance", {}).get("environment", "isolated_lab"),
                status="ACTIVE",
            )
            db.add(decoy_record)
            db.flush()

        # 7. Ensure referenced detection rule exists in DB
        rule_record = db.query(DetectionRuleModel).filter(DetectionRuleModel.rule_id == rule_id).first()
        if not rule_record:
            rule_obj = None
            try:
                rule_obj = self.rules.get_rule(rule_id, rule_version)
            except Exception:
                pass
            rule_record = DetectionRuleModel(
                rule_id=rule_id,
                rule_name=rule_obj.rule_name if rule_obj else f"Detection Rule {rule_id}",
                rule_version=rule_version,
                description=rule_obj.description if rule_obj else "Automated rule",
                category=rule_obj.category if rule_obj else "APPLICATION",
                enabled=rule_obj.enabled if rule_obj else True,
                severity=rule_obj.severity_default.value if rule_obj else "MEDIUM",
                configuration={"conditions": []},
            )
            db.add(rule_record)
            db.flush()

        # 8. Compute observation timestamps
        obs_dt = event.get("observed_at")
        if isinstance(obs_dt, str):
            try:
                obs_dt = datetime.fromisoformat(obs_dt.replace("Z", "+00:00"))
            except Exception:
                obs_dt = now_utc
        elif not isinstance(obs_dt, datetime):
            obs_dt = now_utc

        # 9. Assemble and Persist Alert Model
        new_alert_id = uuid.uuid4()
        rule_def = None
        try:
            rule_def = self.rules.get_rule(rule_id, rule_version)
        except Exception:
            pass

        title = rule_def.rule_name if rule_def else f"Security Finding: {rule_id}"
        summary = (
            f"Detected {title} observed on decoy '{decoy_id}' in session '{session_id}'. "
            f"Severity: {assessment.severity_level.value}, Confidence: {assessment.confidence_score}%."
        )

        alert_model = AlertModel(
            alert_id=new_alert_id,
            schema_version="1.0",
            detection_rule_id=rule_id,
            detection_rule_version=rule_version,
            title=title,
            summary=summary,
            severity=assessment.severity_level.value,
            confidence=assessment.confidence_score,
            assessment_status="NEW",
            evidence_strength=assessment.evidence_strength.value,
            source_address=source_address,
            observed_source_id=observed_source_id,
            decoy_id=decoy_id,
            target_service=target_service,
            first_observed_at=obs_dt,
            last_observed_at=obs_dt,
            generated_at=now_utc,
            detection_explanation=assessment.severity_explanation,
            recommendations={
                "triage_guidance": "Review session event timeline and verify honeypot decoy interactions.",
                "action": "CORRELATE_SESSION",
                "simulated_interaction_warning": "Observed activity occurred within an isolated honeypot environment. Never confuse with production compromise.",
            },
        )
        db.add(alert_model)
        db.flush()

        # 10. Persist Supporting Evidence Junction Records
        supporting_eids: Set[str] = set()
        primary_eid = str(event.get("event_id", ""))
        if primary_eid:
            supporting_eids.add(primary_eid)
        for rel_eid in detection_result.related_event_ids:
            if rel_eid:
                supporting_eids.add(str(rel_eid))

        for eid_str in supporting_eids:
            try:
                ev_uuid = uuid.UUID(eid_str)
                role = "TRIGGERING_OBSERVATION" if eid_str == primary_eid else "CORRELATED_OBSERVATION"
                evidence_link = AlertEvidenceModel(
                    alert_id=new_alert_id,
                    event_id=ev_uuid,
                    evidence_role=role,
                    evidence_summary=f"Supporting event {eid_str} evaluated for {rule_id}",
                    created_at=now_utc,
                )
                db.add(evidence_link)
            except Exception:
                pass

        # Commit Persistent Transaction
        db.commit()

        # Update Cooldown Cache
        self._cooldown_tracker[cooldown_key] = now_utc

        # 11. Post-Commit Live Streaming Notification
        alert_payload = {
            "alert_id": str(new_alert_id),
            "rule_id": rule_id,
            "rule_version": rule_version,
            "title": title,
            "severity": assessment.severity_level.value,
            "confidence": assessment.confidence_score,
            "evidence_strength": assessment.evidence_strength.value,
            "decoy_id": decoy_id,
            "session_id": session_id,
            "source_address": source_address,
            "target_service": target_service,
            "generated_at": now_utc.isoformat(),
            "provenance": event.get("provenance", {}),
        }

        try:
            self.publisher.publish_persisted_alert(alert_payload, generated_at=now_utc)
        except Exception:
            # Invariant: Streaming failure must NEVER roll back or affect persistent DB state
            pass

        # 12. Post-Commit Evidence-Based MITRE ATT&CK Mapping Evaluation (Task P20)
        try:
            from app.modules.mitre.mapping.evaluator import mapping_evaluator
            mapping_evaluator.evaluate_alert(
                db=db,
                alert=alert_model,
                event=event,
                related_event_ids=list(detection_result.related_event_ids) if detection_result else None,
            )
        except Exception:
            # Operational Invariant: Mapping failure must NEVER invalidate the alert or cause detection failure
            pass

        return alert_model

    # --- Suppression Management ---

    def add_suppression_rule(
        self,
        suppression_id: str,
        rule_id: Optional[str] = None,
        session_id: Optional[str] = None,
        decoy_id: Optional[str] = None,
        source_address: Optional[str] = None,
        reason: str = "Standard test suppression",
    ) -> AlertSuppressionRule:
        """Registers an explicit false-positive suppression rule."""
        supp = AlertSuppressionRule(
            suppression_id=suppression_id,
            rule_id=rule_id,
            session_id=session_id,
            decoy_id=decoy_id,
            source_address=source_address,
            reason=reason,
        )
        self._suppression_rules[suppression_id] = supp
        return supp

    def remove_suppression_rule(self, suppression_id: str) -> bool:
        """Removes a suppression rule by ID."""
        if suppression_id in self._suppression_rules:
            del self._suppression_rules[suppression_id]
            return True
        return False

    def is_suppressed(
        self,
        rule_id: str,
        session_id: Optional[str] = None,
        decoy_id: Optional[str] = None,
        source_address: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Checks if an alert candidate matches any active suppression rule."""
        for supp in self._suppression_rules.values():
            if supp.matches(rule_id=rule_id, session_id=session_id, decoy_id=decoy_id, source_address=source_address):
                return True, supp.reason
        return False, ""

    def _record_suppression_audit(
        self,
        rule_id: str,
        session_id: str,
        decoy_id: str,
        source_address: str,
        reason: str,
    ) -> None:
        """Records an auditable trace of suppressed alerts."""
        self._suppression_audit_log.append(
            {
                "rule_id": rule_id,
                "session_id": session_id,
                "decoy_id": decoy_id,
                "source_address": source_address,
                "reason": reason,
                "suppressed_at": datetime.now(timezone.utc).isoformat(),
            }
        )

    def get_suppression_audit_log(self) -> List[Dict[str, Any]]:
        """Returns all suppression audit records."""
        return list(self._suppression_audit_log)

    def clear(self) -> None:
        """Resets in-memory trackers for unit test isolation."""
        self._cooldown_tracker.clear()
        self._suppression_rules.clear()
        self._suppression_audit_log.clear()


# Default singleton alert service
alert_service = AlertService()
