"""Investigation Cluster Lifecycle State Machine and Transition Governance (Task P24)."""

from datetime import datetime, timezone
from typing import Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.db.models.campaign import InvestigationClusterModel, ClusterAuditLogModel


VALID_TRANSITIONS = {
    "CANDIDATE": {"UNDER_REVIEW", "CLOSED", "MERGED"},
    "UNDER_REVIEW": {"ACTIVE", "MONITORING", "CLOSED", "MERGED"},
    "ACTIVE": {"MONITORING", "CLOSED", "MERGED", "SPLIT"},
    "MONITORING": {"ACTIVE", "CLOSED", "MERGED"},
    "CLOSED": {"ACTIVE"},  # Analyst reopening
    "MERGED": set(),       # Terminal state
    "SPLIT": set(),        # Terminal state
}


class ClusterLifecycleManager:
    """Enforces strict state transitions and guarantees full audit trails for investigation clusters."""

    @classmethod
    def validate_transition(cls, current_status: str, target_status: str) -> None:
        """Verifies if transition from current_status to target_status is permitted.
        
        Raises HTTPException(400) if invalid.
        """
        curr = current_status.upper()
        target = target_status.upper()

        if curr == target:
            return

        allowed = VALID_TRANSITIONS.get(curr, set())
        if target not in allowed:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Invalid lifecycle transition from '{curr}' to '{target}'. "
                    f"Allowed target states: {sorted(list(allowed)) if allowed else 'None (Terminal state)'}"
                ),
            )

    @classmethod
    def transition(
        cls,
        db: Session,
        cluster: InvestigationClusterModel,
        target_status: str,
        actor: str,
        reason: str,
        destination_cluster_id: Optional[str] = None,
    ) -> InvestigationClusterModel:
        """Executes a validated lifecycle transition and records an immutable audit log."""
        target = target_status.upper()
        cls.validate_transition(cluster.lifecycle_status, target)

        now_utc = datetime.now(timezone.utc)
        prev_state = {
            "lifecycle_status": cluster.lifecycle_status,
            "destination_cluster_id": cluster.destination_cluster_id,
        }

        cluster.lifecycle_status = target
        cluster.updated_at = now_utc

        if destination_cluster_id:
            cluster.destination_cluster_id = destination_cluster_id

        new_state = {
            "lifecycle_status": cluster.lifecycle_status,
            "destination_cluster_id": cluster.destination_cluster_id,
        }

        # Immutable Audit Log
        audit = ClusterAuditLogModel(
            cluster_id=cluster.cluster_id,
            actor=actor,
            action="LIFECYCLE_STATUS_CHANGED",
            target=cluster.cluster_id,
            previous_state=prev_state,
            new_state=new_state,
            reason=reason,
            timestamp=now_utc,
        )
        db.add(audit)
        db.flush()

        return cluster
