"""Centralized security audit logging service.

Records all security-relevant operational actions to the system_audit_logs table.
Normal users are strictly prohibited from mutating or deleting audit records.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session

from app.db.models.security import SystemAuditLogModel


class AuditService:
    """Service for recording immutable security audit events."""

    @staticmethod
    def log_event(
        db: Session,
        actor_username: str,
        actor_role: str,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        outcome: str = "SUCCESS",
        status_code: Optional[int] = None,
        reason: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_context: Optional[Dict[str, Any]] = None,
    ) -> SystemAuditLogModel:
        """Records an audit log entry in the database.
        
        Guarantees that sensitive fields (passwords, tokens) are omitted.
        """
        # Redact any accidental tokens in request_context
        safe_context = None
        if request_context:
            safe_context = {}
            for k, v in request_context.items():
                if any(sec in k.lower() for sec in ("password", "token", "secret", "auth", "key")):
                    safe_context[k] = "[REDACTED]"
                else:
                    safe_context[k] = v

        entry = SystemAuditLogModel(
            id=str(uuid.uuid4()),
            actor_username=actor_username or "anonymous",
            actor_role=actor_role or "UNAUTHENTICATED",
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            status_code=status_code,
            reason=reason,
            ip_address=ip_address,
            user_agent=user_agent[:255] if user_agent else None,
            request_context=safe_context,
            created_at=datetime.now(timezone.utc),
        )
        try:
            db.add(entry)
            db.commit()
            db.refresh(entry)
            return entry
        except Exception:
            db.rollback()
            raise


audit_service = AuditService()

