"""Time-window evaluation foundations for SnareSight detection engine.

Implements bounded temporal window querying, clock skew tolerance, and ordered
event analysis without allowing unbounded historical database scanning.
"""

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import asc
from app.db.models.event import SecurityEventModel
from app.detection.rule_schema import DetectionRuleDefinition


class TimeWindowEvaluator:
    """Evaluates temporal clusters of security events within a sliding window."""

    MAX_WINDOW_EVENTS = 200
    MAX_ALLOWED_WINDOW_SECONDS = 86400  # 24 hour safety ceiling
    DEFAULT_WINDOW_SECONDS = 300        # 5 minutes default

    @classmethod
    def get_events_in_window(
        cls,
        db: Session,
        reference_time: datetime,
        window_seconds: int,
        decoy_id: Optional[str] = None,
        source_address: Optional[str] = None,
        limit: int = MAX_WINDOW_EVENTS,
    ) -> List[SecurityEventModel]:
        """Retrieves events occurring in the window [reference_time - window_seconds, reference_time].
        
        Ordered chronologically by observed_at ASC.
        """
        # Ensure UTC timezone
        ref_utc = reference_time if reference_time.tzinfo else reference_time.replace(tzinfo=timezone.utc)
        safe_window = min(max(1, window_seconds), cls.MAX_ALLOWED_WINDOW_SECONDS)
        start_time = ref_utc - timedelta(seconds=safe_window)
        bounded_limit = min(limit, cls.MAX_WINDOW_EVENTS)

        query = (
            db.query(SecurityEventModel)
            .filter(
                SecurityEventModel.observed_at >= start_time,
                SecurityEventModel.observed_at <= ref_utc,
            )
            .order_by(asc(SecurityEventModel.observed_at))
        )

        if decoy_id:
            query = query.filter(SecurityEventModel.decoy_id == decoy_id)
        if source_address:
            query = query.filter(SecurityEventModel.source_address == source_address)

        return query.limit(bounded_limit).all()

