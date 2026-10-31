"""Stream cursor engine for SnareSight event reconnection and replay.

Implements cursor formatting, parsing, validation, and database-backed replay
of missed security events after client reconnects.
"""

import uuid
from datetime import datetime, timezone
from typing import Tuple, List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import asc

from app.db.models.event import SecurityEventModel
from app.streaming.exceptions import StreamCursorError
from app.streaming.authorization import StreamUser


class StreamCursor:
    """Manages event cursors and replay of missed persisted security events."""

    CURSOR_PREFIX = "cur"

    @classmethod
    def generate_cursor(cls, observed_at: datetime, event_id: uuid.UUID | str) -> str:
        """Constructs a deterministic, monotonic event cursor string."""
        ts_utc = observed_at if observed_at.tzinfo else observed_at.replace(tzinfo=timezone.utc)
        ts_iso = ts_utc.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
        short_id = str(event_id).replace("-", "")[:12]
        return f"{cls.CURSOR_PREFIX}_{ts_iso}_{short_id}"

    @classmethod
    def parse_cursor(cls, cursor_str: str) -> Tuple[datetime, str]:
        """Parses a cursor string into its constituent timestamp and event id prefix."""
        parts = cursor_str.strip().split("_")
        if len(parts) != 3 or parts[0] != cls.CURSOR_PREFIX:
            raise StreamCursorError(f"Malformed stream cursor format: '{cursor_str}'")

        ts_str = parts[1]
        id_part = parts[2]

        try:
            dt = datetime.strptime(ts_str, "%Y%m%dT%H%M%S%f").replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise StreamCursorError(f"Invalid timestamp in stream cursor: {str(exc)}")

        return dt, id_part

    @classmethod
    def replay_missed_events(
        cls,
        db: Session,
        last_event_id: str,
        user: StreamUser,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Queries persistent storage for events that occurred strictly after the cursor.
        
        Enforces user decoy access boundaries and stable chronological ordering.
        """
        cursor_dt, _ = cls.parse_cursor(last_event_id)

        query = db.query(SecurityEventModel).filter(
            SecurityEventModel.observed_at > cursor_dt
        ).order_by(asc(SecurityEventModel.observed_at))

        # Filter by allowed decoys if user has restricted access
        if not user.is_admin and user.allowed_decoys is not None:
            query = query.filter(SecurityEventModel.decoy_id.in_(user.allowed_decoys))

        records = query.limit(limit).all()

        replayed_events: List[Dict[str, Any]] = []
        for rec in records:
            event_dict = {
                "event_id": str(rec.event_id),
                "raw_event_id": str(rec.raw_event_id),
                "event_type": rec.event_type,
                "event_category": rec.event_category,
                "action": rec.action,
                "outcome": rec.outcome,
                "decoy_id": rec.decoy_id,
                "session_id": rec.session_id,
                "source_address": rec.source_address,
                "target_service": rec.target_service,
                "observed_at": rec.observed_at.isoformat(),
                "provenance": rec.provenance,
                "cursor_id": cls.generate_cursor(rec.observed_at, rec.event_id),
            }
            replayed_events.append(event_dict)

        return replayed_events

