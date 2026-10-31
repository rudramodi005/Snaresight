"""Session Correlation Processing Engine (Task P21).

Binds incoming validated security events into coherent, chronological activity sessions
using hierarchical identity resolution, configurable boundary policies, and transactional persistence.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.db.models.correlation import (
    ActivitySessionEventModel,
    ActivitySessionModel,
    SessionCorrelationHistoryModel,
)
from app.correlation.exceptions import CorrelationError
from app.correlation.identity import SessionIdentity, SessionIdentityResolver
from app.correlation.policy import CorrelationPolicy, default_correlation_policy
from app.correlation.schemas import CorrelationMethod, SessionStatus


class CorrelationEngine:
    """Core processor coordinating session resolution, temporal boundary checks, and event association."""

    def __init__(self, policy: Optional[CorrelationPolicy] = None):
        self.policy = policy or default_correlation_policy

    def correlate_event(self, db: Session, event: Dict[str, Any]) -> ActivitySessionModel:
        """Associates a normalized event with an activity session.
        
        Guarantees:
        - Deterministic & Idempotent: Re-processing an event returns its existing session association.
        - Resilient: Incomplete contextual signals trigger standalone session isolation rather than failure.
        - Auditable: Every session creation and event association is logged to history.
        """
        event_id_str = str(event.get("event_id"))
        try:
            event_uuid = uuid.UUID(event_id_str)
        except Exception:
            raise CorrelationError(f"Invalid event UUID format: {event_id_str}")

        # 1. Idempotency Check: Has this event already been correlated?
        existing_assoc = (
            db.query(ActivitySessionEventModel)
            .filter(ActivitySessionEventModel.event_id == event_uuid)
            .first()
        )
        if existing_assoc:
            existing_sess = (
                db.query(ActivitySessionModel)
                .filter(ActivitySessionModel.session_id == existing_assoc.session_id)
                .first()
            )
            if existing_sess:
                return existing_sess

        # 2. Parse Timestamps
        obs_dt = self._parse_datetime(event.get("observed_at"))
        ingest_dt = self._parse_datetime(event.get("received_at")) or datetime.now(timezone.utc)

        # 3. Resolve Identity Signals (Levels 1–4)
        identity = SessionIdentityResolver.resolve_identity(event)

        # 4. Standalone observations get an isolated standalone session
        if identity.correlation_method == CorrelationMethod.STANDALONE:
            return self._create_new_session(
                db=db,
                identity=identity,
                event=event,
                event_uuid=event_uuid,
                obs_dt=obs_dt,
                ingest_dt=ingest_dt,
                reason="Isolated standalone session due to insufficient correlation signals",
            )

        # 5. Search for an existing compatible ACTIVE or IDLE session matching the correlation key
        candidate_session = (
            db.query(ActivitySessionModel)
            .filter(
                ActivitySessionModel.correlation_key == identity.correlation_key,
                ActivitySessionModel.session_status.in_([SessionStatus.ACTIVE.value, SessionStatus.IDLE.value]),
            )
            .order_by(ActivitySessionModel.last_activity_at.desc())
            .first()
        )

        if candidate_session:
            # 6. Check temporal boundary constraints
            is_valid_bound, bound_reason = self.policy.is_event_within_session_boundaries(
                event_observed_at=obs_dt,
                session_first_observed=candidate_session.first_observed_at,
                session_last_activity=candidate_session.last_activity_at,
                session_status=candidate_session.session_status,
            )

            if is_valid_bound:
                # Associate event with existing session
                return self._attach_event_to_session(
                    db=db,
                    session=candidate_session,
                    event=event,
                    event_uuid=event_uuid,
                    obs_dt=obs_dt,
                    ingest_dt=ingest_dt,
                    identity=identity,
                )
            else:
                # Boundary exceeded: Mark previous session as TIMED_OUT and create new session
                candidate_session.session_status = SessionStatus.TIMED_OUT.value
                candidate_session.updated_at = datetime.now(timezone.utc)
                self._record_history(
                    db=db,
                    session_id=candidate_session.session_id,
                    event_id=event_uuid,
                    action="SESSION_TIMEOUT",
                    prev_status=SessionStatus.ACTIVE.value,
                    new_status=SessionStatus.TIMED_OUT.value,
                    reason=bound_reason,
                )

        # 7. Create New Activity Session
        return self._create_new_session(
            db=db,
            identity=identity,
            event=event,
            event_uuid=event_uuid,
            obs_dt=obs_dt,
            ingest_dt=ingest_dt,
            reason=f"New session initiated via {identity.correlation_method.value}",
        )

    def _create_new_session(
        self,
        db: Session,
        identity: SessionIdentity,
        event: Dict[str, Any],
        event_uuid: uuid.UUID,
        obs_dt: datetime,
        ingest_dt: datetime,
        reason: str,
    ) -> ActivitySessionModel:
        """Instantiates and commits a new activity session and associates its initial event."""
        new_session_id = f"act-sess-{uuid.uuid4().hex[:16]}"
        now_utc = datetime.now(timezone.utc)

        session_model = ActivitySessionModel(
            session_id=new_session_id,
            decoy_id=identity.decoy_id,
            honeypot_type=identity.honeypot_type,
            explicit_session_id=identity.explicit_session_id,
            connection_id=identity.connection_id,
            correlation_method=identity.correlation_method.value,
            correlation_key=identity.correlation_key,
            source_address=identity.source_address,
            source_port=identity.source_port,
            target_service=identity.target_service,
            protocol=identity.protocol,
            first_observed_at=obs_dt,
            last_activity_at=obs_dt,
            ended_at=None,
            first_ingested_at=ingest_dt,
            last_ingested_at=ingest_dt,
            session_status=SessionStatus.ACTIVE.value,
            event_count=1,
            detection_count=0,
            correlation_policy_version=self.policy.policy_version,
            metadata_summary={
                "initial_event_type": event.get("event_type"),
                "initial_category": event.get("event_category"),
                "initial_outcome": event.get("outcome"),
                "identity_diagnostic": identity.resolution_diagnostic,
            },
            created_at=now_utc,
        )
        db.add(session_model)
        db.flush()

        # Association record
        assoc = ActivitySessionEventModel(
            session_id=new_session_id,
            event_id=event_uuid,
            raw_event_id=self._parse_uuid_safe(event.get("raw_event_id")),
            event_type=str(event.get("event_type") or "request"),
            event_category=str(event.get("event_category") or "request"),
            action=str(event.get("action") or "REQUEST"),
            outcome=str(event.get("outcome") or "SUCCESS"),
            observed_at=obs_dt,
            ingested_at=ingest_dt,
            association_method=identity.correlation_method.value,
            correlation_confidence=100 if identity.is_trustworthy else 70,
            is_late_arrival=False,
            associated_at=now_utc,
        )
        db.add(assoc)

        # Audit History
        self._record_history(
            db=db,
            session_id=new_session_id,
            event_id=event_uuid,
            action="SESSION_CREATED",
            prev_status=None,
            new_status=SessionStatus.ACTIVE.value,
            reason=reason,
            details={"correlation_method": identity.correlation_method.value},
        )
        db.commit()

        # Post-Commit Streaming Notification
        self._notify_streaming(session_model, event_type="session.created")

        return session_model

    def _attach_event_to_session(
        self,
        db: Session,
        session: ActivitySessionModel,
        event: Dict[str, Any],
        event_uuid: uuid.UUID,
        obs_dt: datetime,
        ingest_dt: datetime,
        identity: SessionIdentity,
    ) -> ActivitySessionModel:
        """Attaches an event to an active session, updating boundaries and counters."""
        now_utc = datetime.now(timezone.utc)
        is_late = False

        # Update Session Boundaries
        sess_first = session.first_observed_at
        if sess_first and sess_first.tzinfo is None:
            sess_first = sess_first.replace(tzinfo=timezone.utc)
        sess_last = session.last_activity_at
        if sess_last and sess_last.tzinfo is None:
            sess_last = sess_last.replace(tzinfo=timezone.utc)

        if obs_dt < sess_first:
            is_late = True
            session.first_observed_at = obs_dt
        elif obs_dt > sess_last:
            session.last_activity_at = obs_dt

        session.last_ingested_at = ingest_dt
        session.event_count += 1
        session.session_status = SessionStatus.ACTIVE.value
        session.updated_at = now_utc

        # Explicit termination check (logout / disconnect)
        if event.get("action") in ("DISCONNECT", "LOGOUT", "TERMINATE"):
            session.ended_at = obs_dt
            session.session_status = SessionStatus.CLOSED.value

        assoc = ActivitySessionEventModel(
            session_id=session.session_id,
            event_id=event_uuid,
            raw_event_id=self._parse_uuid_safe(event.get("raw_event_id")),
            event_type=str(event.get("event_type") or "request"),
            event_category=str(event.get("event_category") or "request"),
            action=str(event.get("action") or "REQUEST"),
            outcome=str(event.get("outcome") or "SUCCESS"),
            observed_at=obs_dt,
            ingested_at=ingest_dt,
            association_method=identity.correlation_method.value,
            correlation_confidence=100 if identity.is_trustworthy else 70,
            is_late_arrival=is_late,
            associated_at=now_utc,
        )
        db.add(assoc)

        # Audit History
        action_name = "LATE_EVENT_ATTACHED" if is_late else "EVENT_ASSOCIATED"
        self._record_history(
            db=db,
            session_id=session.session_id,
            event_id=event_uuid,
            action=action_name,
            prev_status=session.session_status,
            new_status=session.session_status,
            reason=f"Event {event_uuid} associated via {identity.correlation_method.value}",
            details={"is_late_arrival": is_late, "event_count": session.event_count},
        )
        db.commit()

        # Post-Commit Streaming Notification
        self._notify_streaming(session, event_type="session.event_associated")

        return session

    @staticmethod
    def _record_history(
        db: Session,
        session_id: str,
        event_id: Optional[uuid.UUID],
        action: str,
        prev_status: Optional[str],
        new_status: Optional[str],
        reason: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Appends an immutable audit entry in session_correlation_history."""
        hist = SessionCorrelationHistoryModel(
            session_id=session_id,
            event_id=event_id,
            correlation_action=action,
            previous_status=prev_status,
            new_status=new_status,
            policy_version="1.0",
            reason=reason,
            details=details,
            timestamp=datetime.now(timezone.utc),
        )
        db.add(hist)

    @staticmethod
    def _parse_datetime(val: Any) -> datetime:
        """Parses string or datetime to UTC datetime."""
        if not val:
            return datetime.now(timezone.utc)
        if isinstance(val, datetime):
            if val.tzinfo is None:
                return val.replace(tzinfo=timezone.utc)
            return val
        try:
            return datetime.fromisoformat(str(val).replace("Z", "+00:00"))
        except Exception:
            return datetime.now(timezone.utc)

    @staticmethod
    def _parse_uuid_safe(val: Any) -> Optional[uuid.UUID]:
        if not val:
            return None
        if isinstance(val, uuid.UUID):
            return val
        try:
            return uuid.UUID(str(val))
        except Exception:
            return None

    @staticmethod
    def _notify_streaming(session: ActivitySessionModel, event_type: str = "session.updated") -> None:
        """Broadcasts real-time SSE notification post-commit."""
        try:
            from app.streaming.event_publisher import event_publisher
            payload = {
                "session_id": session.session_id,
                "decoy_id": session.decoy_id,
                "source_address": session.source_address,
                "session_status": session.session_status,
                "event_count": session.event_count,
                "detection_count": session.detection_count,
                "last_activity_at": session.last_activity_at.isoformat(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            event_publisher.publish_custom_event(
                event_type=event_type,
                data=payload,
                event_id=session.session_id,
            )
        except Exception:
            pass


# Global singleton engine
correlation_engine = CorrelationEngine()
