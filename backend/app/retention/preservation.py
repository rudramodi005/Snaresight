"""Evidence preservation engine for SnareSight.

Protects security records linked to active investigations, alert evidence,
or formal preservation holds from automated retention deletion.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Set
from sqlalchemy.orm import Session
from app.db.models.alert import AlertEvidenceModel


@dataclass
class PreservationHold:
    """Formal record of an investigation preservation hold."""
    hold_id: str
    investigation_id: str
    target_id: str  # event_id, raw_event_id, or alert_id
    target_type: str  # "SECURITY_EVENT", "RAW_EVENT", "ALERT"
    reason: str
    authorized_analyst: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    released_at: datetime | None = None
    is_active: bool = True


class EvidencePreservationService:
    """Manages active legal/investigative preservation holds and evidence protection."""

    def __init__(self) -> None:
        self._holds: Dict[str, PreservationHold] = {}  # hold_id -> Hold
        self._target_index: Dict[str, Set[str]] = {}  # target_id -> set of active hold_ids

    def place_hold(
        self,
        investigation_id: str,
        target_id: str,
        target_type: str,
        reason: str,
        authorized_analyst: str,
    ) -> PreservationHold:
        """Places an active preservation hold on a security record."""
        hold_id = str(uuid.uuid4())
        hold = PreservationHold(
            hold_id=hold_id,
            investigation_id=investigation_id,
            target_id=str(target_id),
            target_type=target_type.upper(),
            reason=reason,
            authorized_analyst=authorized_analyst,
            is_active=True,
        )
        self._holds[hold_id] = hold
        target_str = str(target_id)
        if target_str not in self._target_index:
            self._target_index[target_str] = set()
        self._target_index[target_str].add(hold_id)
        return hold

    def release_hold(self, hold_id: str, authorized_analyst: str) -> bool:
        """Releases an active preservation hold with analyst authorization."""
        if hold_id not in self._holds:
            return False
        hold = self._holds[hold_id]
        if not hold.is_active:
            return False
        hold.is_active = False
        hold.released_at = datetime.now(timezone.utc)
        target_str = hold.target_id
        if target_str in self._target_index:
            self._target_index[target_str].discard(hold_id)
            if not self._target_index[target_str]:
                del self._target_index[target_str]
        return True

    def is_target_preserved(self, db: Session | None, target_id: str | uuid.UUID, target_type: str) -> bool:
        """Determines if a target entity is protected from retention deletion.
        
        Checks:
        1. In-memory active preservation holds.
        2. Database alert_evidence links (if entity is a security_event).
        """
        target_str = str(target_id)
        # Check active explicit holds
        if target_str in self._target_index and self._target_index[target_str]:
            return True

        # Check database alert evidence foreign keys
        if db is not None and target_type.upper() == "SECURITY_EVENT":
            try:
                target_uuid = uuid.UUID(target_str) if isinstance(target_id, str) else target_id
                evidence_count = db.query(AlertEvidenceModel).filter(
                    AlertEvidenceModel.event_id == target_uuid
                ).count()
                if evidence_count > 0:
                    return True
            except Exception:
                # If error querying, fail-safe to preserving
                return True

        return False

    def get_active_holds(self) -> list[PreservationHold]:
        """Returns all currently active preservation holds."""
        return [h for h in self._holds.values() if h.is_active]


# Default singleton preservation service
preservation_service = EvidencePreservationService()

