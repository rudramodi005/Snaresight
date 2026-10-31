"""Stream connection and subscriber manager for SnareSight.

Enforces connection concurrency limits, per-user limits, and safe client lifecycle.
"""

from typing import Dict, List, Optional
from app.streaming.authorization import StreamUser
from app.streaming.event_subscriber import EventSubscriber
from app.streaming.exceptions import StreamResourceLimitExceeded


class StreamManager:
    """Coordinates active SSE subscribers and enforces resource boundaries."""

    MAX_CONCURRENT_CLIENTS = 50
    MAX_CONNECTIONS_PER_USER = 5

    def __init__(self) -> None:
        self._subscribers: Dict[str, EventSubscriber] = {}
        self._user_connection_counts: Dict[str, int] = {}
        self._slow_clients_disconnected: int = 0

    def register_subscriber(
        self,
        user: StreamUser,
        filter_event_type: Optional[str] = None,
        filter_event_category: Optional[str] = None,
        filter_decoy_id: Optional[str] = None,
        filter_provenance: Optional[str] = None,
        queue_size: int = EventSubscriber.DEFAULT_QUEUE_SIZE,
    ) -> EventSubscriber:
        """Registers a new SSE client connection subject to resource limits."""
        # Check global limit
        if len(self._subscribers) >= self.MAX_CONCURRENT_CLIENTS:
            raise StreamResourceLimitExceeded(
                f"Maximum concurrent streaming connections ({self.MAX_CONCURRENT_CLIENTS}) reached"
            )

        # Check per-user limit
        user_current = self._user_connection_counts.get(user.user_id, 0)
        if user_current >= self.MAX_CONNECTIONS_PER_USER:
            raise StreamResourceLimitExceeded(
                f"User '{user.username}' exceeded max concurrent streaming connections ({self.MAX_CONNECTIONS_PER_USER})"
            )

        subscriber = EventSubscriber(
            user=user,
            filter_event_type=filter_event_type,
            filter_event_category=filter_event_category,
            filter_decoy_id=filter_decoy_id,
            filter_provenance=filter_provenance,
            queue_size=queue_size,
        )

        self._subscribers[subscriber.subscriber_id] = subscriber
        self._user_connection_counts[user.user_id] = user_current + 1
        return subscriber

    def unregister_subscriber(self, subscriber_id: str) -> None:
        """Removes a client connection and cleans up resource allocations."""
        if subscriber_id in self._subscribers:
            sub = self._subscribers.pop(subscriber_id)
            sub.is_active = False
            user_id = sub.user.user_id
            if user_id in self._user_connection_counts:
                self._user_connection_counts[user_id] = max(0, self._user_connection_counts[user_id] - 1)
                if self._user_connection_counts[user_id] == 0:
                    del self._user_connection_counts[user_id]

    def remove_slow_client(self, subscriber_id: str) -> None:
        """Terminates an unresponsive slow client to protect server memory."""
        self.unregister_subscriber(subscriber_id)
        self._slow_clients_disconnected += 1

    def get_active_subscribers(self) -> List[EventSubscriber]:
        """Returns list of currently active subscribers."""
        return [s for s in self._subscribers.values() if s.is_active]

    @property
    def active_connections_count(self) -> int:
        return len(self._subscribers)

    @property
    def slow_clients_disconnected_count(self) -> int:
        return self._slow_clients_disconnected


# Default singleton stream manager
stream_manager = StreamManager()
