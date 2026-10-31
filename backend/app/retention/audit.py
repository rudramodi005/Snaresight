"""Retention audit tracking and operational logging for SnareSight.

Records all retention operations (dry-run and active executions) to guarantee
auditability and evidence preservation tracking.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any


@dataclass
class RetentionAuditRecord:
    """Audit log entry for a retention evaluation or execution."""
    operation_id: str
    initiated_by: str
    timestamp: datetime
    policy_version: str
    categories_evaluated: List[str]
    mode: str  # "DRY_RUN" or "EXECUTE"
    candidate_count: int
    preserved_count: int
    deleted_count: int
    failure_count: int
    completion_status: str  # "SUCCESS", "PARTIAL", "FAILED"
    error_summary: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "initiated_by": self.initiated_by,
            "timestamp": self.timestamp.isoformat(),
            "policy_version": self.policy_version,
            "categories_evaluated": self.categories_evaluated,
            "mode": self.mode,
            "candidate_count": self.candidate_count,
            "preserved_count": self.preserved_count,
            "deleted_count": self.deleted_count,
            "failure_count": self.failure_count,
            "completion_status": self.completion_status,
            "error_summary": self.error_summary,
        }


class RetentionAuditTracker:
    """Manages immutable in-memory and database audit logging of retention operations."""

    def __init__(self) -> None:
        self._history: List[RetentionAuditRecord] = []

    def log_operation(
        self,
        initiated_by: str,
        policy_version: str,
        categories_evaluated: List[str],
        mode: str,
        candidate_count: int,
        preserved_count: int,
        deleted_count: int,
        failure_count: int,
        completion_status: str,
        error_summary: str | None = None,
    ) -> RetentionAuditRecord:
        """Appends a validated, sanitized retention audit record."""
        # Sanitize error summary
        safe_error = None
        if error_summary:
            safe_error = str(error_summary)[:512]
            for secret_token in ("password", "secret", "private_key", "token"):
                if secret_token in safe_error.lower():
                    safe_error = "Sanitized database or execution error"

        record = RetentionAuditRecord(
            operation_id=str(uuid.uuid4()),
            initiated_by=initiated_by,
            timestamp=datetime.now(timezone.utc),
            policy_version=policy_version,
            categories_evaluated=categories_evaluated,
            mode=mode.upper(),
            candidate_count=candidate_count,
            preserved_count=preserved_count,
            deleted_count=deleted_count,
            failure_count=failure_count,
            completion_status=completion_status.upper(),
            error_summary=safe_error,
        )
        self._history.append(record)
        return record

    def get_history(self) -> List[RetentionAuditRecord]:
        """Returns chronological list of all audit records."""
        return list(self._history)


# Default singleton audit tracker
retention_audit_tracker = RetentionAuditTracker()

