"""Event subscriber context managing per-client bounded queues and independent filters."""

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from app.streaming.authorization import StreamUser
from app.streaming.exceptions import StreamQueueFullError


class EventSubscriber:
    """Represents an active SSE client connection with bounded queue and filter rules."""

    DEFAULT_QUEUE_SIZE = 100

    def __init__(
        self,
        user: StreamUser,
        filter_event_type: Optional[str] = None,
        filter_event_category: Optional[str] = None,
        filter_decoy_id: Optional[str] = None,
        filter_provenance: Optional[str] = None,
        queue_size: int = DEFAULT_QUEUE_SIZE,
    ) -> None:
        self.subscriber_id: str = str(uuid.uuid4())
        self.user: StreamUser = user
        self.filter_event_type: Optional[str] = filter_event_type.upper() if filter_event_type else None
        self.filter_event_category: Optional[str] = filter_event_category.upper() if filter_event_category else None
        self.filter_decoy_id: Optional[str] = filter_decoy_id
        self.filter_provenance: Optional[str] = filter_provenance
        self.queue: asyncio.Queue[str] = asyncio.Queue(maxsize=queue_size)
        self.connected_at: datetime = datetime.now(timezone.utc)
        self.last_delivered_at: Optional[datetime] = None
        self.messages_delivered: int = 0
        self.is_active: bool = True
        self.is_slow_client: bool = False

    def matches_filter(self, event_data: Dict[str, Any]) -> bool:
        """Evaluates whether an event matches this subscriber's permissions and filters."""
        # 1. Decoy authorization boundary check
        decoy_id = str(event_data.get("decoy_id", ""))
        if not self.user.can_access_decoy(decoy_id):
            return False

        # 2. Decoy filter
        if self.filter_decoy_id and decoy_id != self.filter_decoy_id:
            return False

        # 3. Event Type filter
        if self.filter_event_type:
            ev_type = str(event_data.get("event_type", "")).upper()
            if ev_type != self.filter_event_type:
                return False

        # 4. Event Category filter
        if self.filter_event_category:
            ev_cat = str(event_data.get("event_category", "")).upper()
            if ev_cat != self.filter_event_category:
                return False

        # 5. Provenance filter
        if self.filter_provenance:
            prov = event_data.get("provenance", {})
            prov_str = str(prov.get("source_type", prov.get("collection_method", ""))).lower()
            if self.filter_provenance.lower() not in prov_str:
                return False

        return True

    def enqueue_message(self, message: str) -> None:
        """Pushes an SSE message into the client's bounded queue.
        
        Raises StreamQueueFullError without blocking if client queue is saturated.
        """
        if not self.is_active:
            return

        try:
            self.queue.put_nowait(message)
        except asyncio.QueueFull:
            self.is_slow_client = True
            raise StreamQueueFullError(
                f"Client '{self.subscriber_id}' queue overflowed (capacity: {self.queue.maxsize})"
            )

