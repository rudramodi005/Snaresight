"""Internal platform security rules engine.

Evaluates control plane security events and operational indicators to detect
internal attacks, misconfigurations, audit tampering, and infrastructure failures.
"""

from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
import uuid
from sqlalchemy.orm import Session
from sqlalchemy import select, and_, func

from app.db.models.resilience import InternalSecurityEventModel, InternalSecurityAlertModel


class InternalRule:
    """Specification of an internal control-plane detection rule."""

    def __init__(
        self,
        rule_id: str,
        rule_version: str,
        title: str,
        description: str,
        severity: str,
        recommended_action: str,
    ):
        self.rule_id = rule_id
        self.rule_version = rule_version
        self.title = title
        self.description = description
        self.severity = severity
        self.recommended_action = recommended_action

    def evaluate(self, db: Session, event: InternalSecurityEventModel) -> Optional[Dict[str, Any]]:
        """Returns evidence dict if rule matches, else None."""
        raise NotImplementedError


class AuthFailureRule(InternalRule):
    """RULE-INT-AUTH-01: Detects repeated authentication failures targeting control plane accounts."""

    def __init__(self):
        super().__init__(
            rule_id="RULE-INT-AUTH-01",
            rule_version="1.0",
            title="Repeated Internal Authentication Failures",
            description="Multiple consecutive authentication failures detected against SnareSight management interface.",
            severity="HIGH",
            recommended_action="Inspect source IP, temporarily lock targeted account if suspicious, and review audit trail.",
        )

    def evaluate(self, db: Session, event: InternalSecurityEventModel) -> Optional[Dict[str, Any]]:
        if event.event_type not in ("AUTH_FAILURE", "LOGIN_FAILED", "TOKEN_REJECTED"):
            return None

        # Check metadata attempt count or query window
        window_start = datetime.now(timezone.utc) - timedelta(minutes=10)
        recent_fails = db.scalars(
            select(InternalSecurityEventModel).where(
                and_(
                    InternalSecurityEventModel.event_type.in_(["AUTH_FAILURE", "LOGIN_FAILED", "TOKEN_REJECTED"]),
                    InternalSecurityEventModel.actor_username == event.actor_username,
                    InternalSecurityEventModel.timestamp >= window_start,
                )
            )
        ).all()

        fail_count = len(recent_fails)
        if fail_count >= 5 or event.metadata_payload.get("failed_attempts", 0) >= 5:
            return {
                "target_username": event.actor_username,
                "failure_count": max(fail_count, event.metadata_payload.get("failed_attempts", 0)),
                "source_component": event.source_component,
                "window_minutes": 10,
                "last_failure_time": event.timestamp.isoformat(),
            }
        return None


class PrivilegeEscalationRule(InternalRule):
    """RULE-INT-PRIV-02: Unauthorized role or privilege escalation attempt."""

    def __init__(self):
        super().__init__(
            rule_id="RULE-INT-PRIV-02",
            rule_version="1.0",
            title="Unauthorized Privilege Escalation Attempt",
            description="Attempt detected by non-administrative user to alter user roles, permissions, or escalate privileges.",
            severity="CRITICAL",
            recommended_action="Terminate session immediately, freeze account permissions, and audit user activity.",
        )

    def evaluate(self, db: Session, event: InternalSecurityEventModel) -> Optional[Dict[str, Any]]:
        if event.event_type in ("ROLE_CHANGE_ATTEMPT", "PRIVILEGE_ESCALATION", "UNAUTHORIZED_ADMIN_ACTION"):
            return {
                "actor_username": event.actor_username,
                "actor_role": event.actor_role,
                "event_type": event.event_type,
                "details": event.metadata_payload,
            }
        if event.outcome == "BLOCKED" and "privilege" in str(event.metadata_payload).lower():
            return {
                "actor_username": event.actor_username,
                "actor_role": event.actor_role,
                "reason": "Blocked privilege escalation attempt",
                "details": event.metadata_payload,
            }
        return None


class AuthzAnomalyRule(InternalRule):
    """RULE-INT-AUTHZ-03: Excessive access denied (403) anomalies across control plane."""

    def __init__(self):
        super().__init__(
            rule_id="RULE-INT-AUTHZ-03",
            rule_version="1.0",
            title="Access Denied Anomaly on Administrative Control Plane",
            description="Repeated 403 Forbidden outcomes indicating internal authorization probing or token abuse.",
            severity="MEDIUM",
            recommended_action="Review requested endpoints, check whether token is expired or unauthorized API probing occurred.",
        )

    def evaluate(self, db: Session, event: InternalSecurityEventModel) -> Optional[Dict[str, Any]]:
        if event.event_type not in ("ACCESS_DENIED", "FORBIDDEN_ENDPOINT"):
            return None

        window_start = datetime.now(timezone.utc) - timedelta(minutes=15)
        recent_denies = db.scalars(
            select(InternalSecurityEventModel).where(
                and_(
                    InternalSecurityEventModel.event_type.in_(["ACCESS_DENIED", "FORBIDDEN_ENDPOINT"]),
                    InternalSecurityEventModel.actor_username == event.actor_username,
                    InternalSecurityEventModel.timestamp >= window_start,
                )
            )
        ).all()

        if len(recent_denies) >= 4 or event.metadata_payload.get("denial_count", 0) >= 4:
            return {
                "actor_username": event.actor_username,
                "denial_count": max(len(recent_denies), event.metadata_payload.get("denial_count", 0)),
                "window_minutes": 15,
                "endpoints_targeted": list({e.metadata_payload.get("path", "unknown") for e in recent_denies}),
            }
        return None


class ConfigTamperingRule(InternalRule):
    """RULE-INT-CFG-04: Critical administrative configuration tampering."""

    def __init__(self):
        super().__init__(
            rule_id="RULE-INT-CFG-04",
            rule_version="1.0",
            title="Critical System Configuration Modification",
            description="Changes applied to system security settings, encryption policies, or defensive thresholds.",
            severity="MEDIUM",
            recommended_action="Confirm change ticket authorization with security lead and inspect configuration diff.",
        )

    def evaluate(self, db: Session, event: InternalSecurityEventModel) -> Optional[Dict[str, Any]]:
        if event.event_type in ("SYSTEM_CONFIG_CHANGED", "SECURITY_POLICY_ALTERED", "RETENTION_POLICY_MUTATED"):
            return {
                "modified_by": event.actor_username,
                "role": event.actor_role,
                "config_key": event.metadata_payload.get("key", "global"),
                "change_details": event.metadata_payload,
            }
        return None


class AuditTamperingRule(InternalRule):
    """RULE-INT-AUDIT-05: Audit persistence failure or hash chain integrity failure."""

    def __init__(self):
        super().__init__(
            rule_id="RULE-INT-AUDIT-05",
            rule_version="1.0",
            title="Audit Trail Integrity Anomaly or Persistence Failure",
            description="Audit persistence was disrupted, or cryptographic hash chain verification detected corrupted records.",
            severity="CRITICAL",
            recommended_action="Inspect database filesystem, verify audit table constraints, and initiate forensic integrity audit.",
        )

    def evaluate(self, db: Session, event: InternalSecurityEventModel) -> Optional[Dict[str, Any]]:
        if event.event_type in ("AUDIT_PERSISTENCE_FAILURE", "AUDIT_HASH_CORRUPTION", "AUDIT_CHAIN_BROKEN"):
            return {
                "component": event.source_component,
                "failure_reason": event.metadata_payload.get("error", "Unknown audit anomaly"),
                "detected_at": event.timestamp.isoformat(),
                "details": event.metadata_payload,
            }
        return None


class BackupFailureRule(InternalRule):
    """RULE-INT-BCK-06: Database backup or restore verification failure."""

    def __init__(self):
        super().__init__(
            rule_id="RULE-INT-BCK-06",
            rule_version="1.0",
            title="Database Backup or Recovery Verification Failure",
            description="Scheduled or manual database backup failed, or isolated sandbox restore test failed.",
            severity="HIGH",
            recommended_action="Examine storage space, check database dump permissions, and trigger an immediate isolated recovery test.",
        )

    def evaluate(self, db: Session, event: InternalSecurityEventModel) -> Optional[Dict[str, Any]]:
        if event.event_type in ("BACKUP_FAILED", "RESTORE_TEST_FAILED", "BACKUP_CORRUPTED"):
            return {
                "backup_id": event.metadata_payload.get("backup_id", "unknown"),
                "error_details": event.metadata_payload.get("error", "Backup/Restore failure"),
                "failure_type": event.event_type,
            }
        return None


class IngestionAnomalyRule(InternalRule):
    """RULE-INT-INGEST-07: Honeypot telemetry ingestion rejection anomaly."""

    def __init__(self):
        super().__init__(
            rule_id="RULE-INT-INGEST-07",
            rule_version="1.0",
            title="Honeypot Telemetry Ingestion Anomaly",
            description="Abnormal spike in rejected honeypot payloads or sensor authentication failures at the collector boundary.",
            severity="HIGH",
            recommended_action="Inspect honeypot network connectivity, check sensor credentials, and verify telemetry parser health.",
        )

    def evaluate(self, db: Session, event: InternalSecurityEventModel) -> Optional[Dict[str, Any]]:
        if event.event_type in ("INGESTION_SPIKE_REJECTIONS", "SENSOR_AUTH_FLOOD", "CORRUPTED_TELEMETRY_BATCH"):
            return {
                "sensor_id": event.metadata_payload.get("sensor_id", "unknown"),
                "rejection_count": event.metadata_payload.get("rejection_count", 1),
                "reason": event.metadata_payload.get("reason", "Malformed or unauthenticated telemetry"),
            }
        return None


class InternalRuleEngine:
    """Coordinates internal rule evaluation and alert creation."""

    def __init__(self):
        self.rules: List[InternalRule] = [
            AuthFailureRule(),
            PrivilegeEscalationRule(),
            AuthzAnomalyRule(),
            ConfigTamperingRule(),
            AuditTamperingRule(),
            BackupFailureRule(),
            IngestionAnomalyRule(),
        ]

    def evaluate_event(self, db: Session, event: InternalSecurityEventModel) -> List[InternalSecurityAlertModel]:
        """Evaluates an event across all rules, creating or updating open alerts."""
        generated_alerts: List[InternalSecurityAlertModel] = []

        for rule in self.rules:
            evidence = rule.evaluate(db, event)
            if evidence:
                alert = self._create_or_update_alert(db, rule, evidence, event)
                generated_alerts.append(alert)

        return generated_alerts

    def _create_or_update_alert(
        self,
        db: Session,
        rule: InternalRule,
        evidence: Dict[str, Any],
        event: InternalSecurityEventModel,
    ) -> InternalSecurityAlertModel:
        # Check if an open alert exists for this rule
        existing_alert = db.scalars(
            select(InternalSecurityAlertModel).where(
                and_(
                    InternalSecurityAlertModel.rule_id == rule.rule_id,
                    InternalSecurityAlertModel.status.in_(["OPEN", "ACKNOWLEDGED"]),
                )
            ).order_by(InternalSecurityAlertModel.created_at.desc())
        ).first()

        now = datetime.now(timezone.utc)

        if existing_alert:
            existing_alert.last_observed_at = now
            # Update evidence
            combined_evidence = dict(existing_alert.evidence_payload)
            combined_evidence.update(evidence)
            combined_evidence["last_event_id"] = str(event.id)
            existing_alert.evidence_payload = combined_evidence
            db.commit()
            db.refresh(existing_alert)
            return existing_alert

        # Create new alert
        alert_id = f"INT-ALT-{uuid.uuid4().hex[:8].upper()}"
        alert = InternalSecurityAlertModel(
            alert_id=alert_id,
            rule_id=rule.rule_id,
            rule_version=rule.rule_version,
            title=rule.title,
            description=rule.description,
            severity=rule.severity,
            status="OPEN",
            first_observed_at=now,
            last_observed_at=now,
            evidence_payload=evidence,
            recommended_action=rule.recommended_action,
            created_at=now,
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        return alert


internal_rule_engine = InternalRuleEngine()

