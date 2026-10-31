"""Post-commit event publisher broadcasting persisted security events and alerts to active SSE subscribers."""

import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from app.streaming.stream_manager import StreamManager, stream_manager
from app.streaming.stream_cursor import StreamCursor
from app.streaming.exceptions import StreamQueueFullError


class EventPublisher:
    """Publishes persisted security events and alerts to authorized streaming clients."""

    def __init__(self, manager: StreamManager | None = None) -> None:
        self.manager = manager or stream_manager
        self._total_published = 0
        self._total_delivered = 0
        self._total_delivery_failures = 0
        self._total_alerts_published = 0
        self._total_alerts_delivered = 0

    def publish_persisted_event(
        self,
        event_dict: Dict[str, Any],
        observed_at: datetime | None = None,
    ) -> int:
        """Publishes a confirmed persisted security event to active subscribers.
        
        INVARIANT: Must only be invoked AFTER database transaction has committed.
        
        Returns:
            Count of subscribers that successfully received the notification.
        """
        self._total_published += 1

        obs_dt = observed_at or event_dict.get("observed_at")
        if isinstance(obs_dt, str):
            try:
                obs_dt = datetime.fromisoformat(obs_dt.replace("Z", "+00:00"))
            except Exception:
                obs_dt = datetime.now(timezone.utc)
        elif not isinstance(obs_dt, datetime):
            obs_dt = datetime.now(timezone.utc)

        event_id = event_dict.get("event_id", "")
        cursor_id = StreamCursor.generate_cursor(obs_dt, str(event_id))

        # Build sanitized notification payload (Zero password guarantee)
        notification_payload = {
            "event_id": str(event_id),
            "raw_event_id": str(event_dict.get("raw_event_id", "")),
            "event_type": str(event_dict.get("event_type", "")),
            "event_category": str(event_dict.get("event_category", "")),
            "action": str(event_dict.get("action", "")),
            "outcome": str(event_dict.get("outcome", "")),
            "decoy_id": str(event_dict.get("decoy_id", "")),
            "session_id": str(event_dict.get("session_id", "")),
            "source_address": str(event_dict.get("source_address", "")),
            "target_service": str(event_dict.get("target_service", "")),
            "observed_at": obs_dt.isoformat(),
            "provenance": event_dict.get("provenance", {}),
            "cursor_id": cursor_id,
        }

        serialized_data = json.dumps(notification_payload)
        sse_message = f"id: {cursor_id}\nevent: security_event\ndata: {serialized_data}\n\n"

        delivered_count = 0
        active_subscribers = self.manager.get_active_subscribers()

        for subscriber in active_subscribers:
            # Check subscriber filter matching and authorization
            if not subscriber.matches_filter(notification_payload):
                continue

            try:
                subscriber.enqueue_message(sse_message)
                subscriber.messages_delivered += 1
                subscriber.last_delivered_at = datetime.now(timezone.utc)
                delivered_count += 1
                self._total_delivered += 1
            except StreamQueueFullError:
                # Slow client handling: drop unresponsive client without blocking server
                self._total_delivery_failures += 1
                self.manager.remove_slow_client(subscriber.subscriber_id)
            except Exception:
                self._total_delivery_failures += 1

        return delivered_count

    def publish_persisted_alert(
        self,
        alert_dict: Dict[str, Any],
        generated_at: Optional[datetime] = None,
    ) -> int:
        """Publishes a confirmed persisted security alert to active subscribers.
        
        INVARIANT: Must only be invoked AFTER database transaction has committed.
        
        Returns:
            Count of subscribers that successfully received the alert notification.
        """
        self._total_alerts_published += 1

        gen_dt = generated_at or alert_dict.get("generated_at")
        if isinstance(gen_dt, str):
            try:
                gen_dt = datetime.fromisoformat(gen_dt.replace("Z", "+00:00"))
            except Exception:
                gen_dt = datetime.now(timezone.utc)
        elif not isinstance(gen_dt, datetime):
            gen_dt = datetime.now(timezone.utc)

        alert_id = alert_dict.get("alert_id", "")
        cursor_id = StreamCursor.generate_cursor(gen_dt, str(alert_id))

        notification_payload = {
            "alert_id": str(alert_id),
            "rule_id": str(alert_dict.get("rule_id") or alert_dict.get("detection_rule_id", "")),
            "rule_version": str(alert_dict.get("rule_version") or alert_dict.get("detection_rule_version", "")),
            "title": str(alert_dict.get("title", "")),
            "severity": str(alert_dict.get("severity", "")),
            "confidence": int(alert_dict.get("confidence", 0)),
            "evidence_strength": str(alert_dict.get("evidence_strength", "")),
            "decoy_id": str(alert_dict.get("decoy_id", "")),
            "session_id": str(alert_dict.get("session_id", "")),
            "source_address": str(alert_dict.get("source_address", "")),
            "target_service": str(alert_dict.get("target_service", "")),
            "generated_at": gen_dt.isoformat(),
            "provenance": alert_dict.get("provenance", {}),
            "cursor_id": cursor_id,
        }

        serialized_data = json.dumps(notification_payload)
        sse_message = f"id: {cursor_id}\nevent: security_alert\ndata: {serialized_data}\n\n"

        delivered_count = 0
        active_subscribers = self.manager.get_active_subscribers()

        for subscriber in active_subscribers:
            if not subscriber.matches_filter(notification_payload):
                continue

            try:
                subscriber.enqueue_message(sse_message)
                subscriber.messages_delivered += 1
                subscriber.last_delivered_at = datetime.now(timezone.utc)
                delivered_count += 1
                self._total_alerts_delivered += 1
            except StreamQueueFullError:
                self.manager.remove_slow_client(subscriber.subscriber_id)
            except Exception:
                pass

        return delivered_count

    def publish_investigation_event(
        self,
        event_name: str,
        cluster_id: str,
        payload: Dict[str, Any],
    ) -> int:
        """Publishes an investigation cluster lifecycle or membership event to active subscribers.
        
        INVARIANT: Must only be invoked AFTER database transaction has committed.
        """
        now_dt = datetime.now(timezone.utc)
        cursor_id = StreamCursor.generate_cursor(now_dt, str(cluster_id))
        notification_payload = {
            "event_type": event_name,
            "cluster_id": cluster_id,
            "payload": payload,
            "cursor_id": cursor_id,
            "timestamp": now_dt.isoformat(),
        }
        serialized_data = json.dumps(notification_payload)
        sse_message = f"id: {cursor_id}\nevent: {event_name}\ndata: {serialized_data}\n\n"

        delivered_count = 0
        active_subscribers = self.manager.get_active_subscribers()
        for subscriber in active_subscribers:
            try:
                subscriber.enqueue_message(sse_message)
                subscriber.messages_delivered += 1
                subscriber.last_delivered_at = now_dt
                delivered_count += 1
            except StreamQueueFullError:
                self.manager.remove_slow_client(subscriber.subscriber_id)
            except Exception:
                pass
        return delivered_count

    def publish_alert_lifecycle_event(
        self,
        event_name: str,
        alert_id: str,
        payload: Dict[str, Any],
    ) -> int:
        """Publishes an alert triage lifecycle event (e.g. status change, assignment) to active subscribers.
        
        INVARIANT: Must only be invoked AFTER database transaction has committed.
        """
        now_dt = datetime.now(timezone.utc)
        cursor_id = StreamCursor.generate_cursor(now_dt, str(alert_id))
        notification_payload = {
            "event_type": event_name,
            "alert_id": str(alert_id),
            "payload": payload,
            "cursor_id": cursor_id,
            "timestamp": now_dt.isoformat(),
        }
        serialized_data = json.dumps(notification_payload)
        sse_message = f"id: {cursor_id}\nevent: {event_name}\ndata: {serialized_data}\n\n"

        delivered_count = 0
        active_subscribers = self.manager.get_active_subscribers()
        for subscriber in active_subscribers:
            try:
                subscriber.enqueue_message(sse_message)
                subscriber.messages_delivered += 1
                subscriber.last_delivered_at = now_dt
                delivered_count += 1
            except StreamQueueFullError:
                self.manager.remove_slow_client(subscriber.subscriber_id)
            except Exception:
                pass
        return delivered_count

    @property
    def total_published(self) -> int:
        return self._total_published

    @property
    def total_delivered(self) -> int:
        return self._total_delivered

    @property
    def total_delivery_failures(self) -> int:
        return self._total_delivery_failures

    @property
    def total_alerts_published(self) -> int:
        return self._total_alerts_published

    @property
    def total_alerts_delivered(self) -> int:
        return self._total_alerts_delivered


# Default singleton event publisher
event_publisher = EventPublisher()
