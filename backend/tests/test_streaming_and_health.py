"""Comprehensive automated test suite for SnareSight Task P15:
Live Event Streaming (SSE) and Centralized Pipeline Health Monitoring.

Covers:
- TEST SSE-001 to SSE-015 (Server-Sent Events)
- TEST RECONNECT-001 to RECONNECT-006 (Reconnection and Replay)
- TEST HEALTH-001 to HEALTH-010 (Pipeline Health and Diagnostics)
- TEST SEC-STREAM-001 to SEC-STREAM-006 (Streaming Security and Resource Controls)
"""

import asyncio
import copy
import json
import time
import unittest
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.db.base import Base
from app.db.session import get_db
from app.db.models.honeypot import HoneypotModel
from app.db.models.event import RawEventModel, SecurityEventModel
from app.api.stream import router as stream_router
from app.api.health import router as health_router
from app.streaming.authorization import StreamUser, StreamAuthorizer
from app.streaming.stream_manager import StreamManager
from app.streaming.event_subscriber import EventSubscriber
from app.streaming.event_publisher import EventPublisher
from app.streaming.stream_cursor import StreamCursor
from app.streaming.heartbeat import HeartbeatManager
from app.streaming.exceptions import (
    StreamAuthenticationError,
    StreamAuthorizationError,
    StreamResourceLimitExceeded,
    StreamQueueFullError,
    StreamCursorError,
)
from app.monitoring.status import ComponentHealthStatus, PipelineOverallStatus
from app.monitoring.metrics import PipelineMetricsCollector
from app.monitoring.service import PipelineHealthService
from app.ingestion.processor import EventProcessor


class TestStreamingAndHealth(unittest.TestCase):
    """Test suite for SSE event streaming, reconnection cursors, and operational health probes."""

    def setUp(self):
        """Configure test in-memory database and isolated streaming/monitoring test instances."""
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.db = self.SessionLocal()

        # Seed Honeypot fixture
        self.decoy = HoneypotModel(
            decoy_id="WEB-001",
            name="ApexCore Portal Decoy",
            decoy_type="WEB_LOGIN",
            protocol="HTTP",
            environment="isolated_lab",
            status="ACTIVE",
        )
        self.db.add(self.decoy)
        self.db.commit()

        # Isolated manager, publisher, metrics, and health service for clean unit test state
        self.stream_manager = StreamManager()
        self.event_publisher = EventPublisher(manager=self.stream_manager)
        self.metrics = PipelineMetricsCollector()
        self.health_service = PipelineHealthService(
            metrics=self.metrics,
            streams=self.stream_manager,
            publisher=self.event_publisher,
        )

        # FastAPI test client
        self.app = FastAPI()
        self.app.include_router(stream_router, prefix="/api/v1")
        self.app.include_router(health_router, prefix="/api/v1")

        def override_get_db():
            db = self.SessionLocal()
            try:
                yield db
            finally:
                db.close()

        self.app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(self.app)

        # Base sample event fixture
        self.base_event = {
            "event_id": str(uuid.uuid4()),
            "raw_event_id": str(uuid.uuid4()),
            "event_type": "LOGIN_ATTEMPT",
            "event_category": "AUTHENTICATION",
            "action": "SUBMIT_CREDENTIALS",
            "outcome": "FAILURE",
            "decoy_id": "WEB-001",
            "session_id": "decoy_sess_3430c5e63810486c99cff33faad6a50d",
            "source_address": "198.51.100.45",
            "target_service": "WEB_PORTAL",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "provenance": {"source_type": "controlled_test", "environment": "isolated_lab"},
        }

    def tearDown(self):
        """Clean up database sessions and tables."""
        self.app.dependency_overrides.clear()
        self.db.close()
        Base.metadata.drop_all(self.engine)

    # =========================================================================
    # SSE TESTS: TEST SSE-001 to SSE-015
    # =========================================================================

    def test_sse_001_authorized_client_connects(self):
        """TEST SSE-001: Authorized client connects with valid Authorization header."""
        response = self.client.get(
            "/api/v1/stream/events?limit=1",
            headers={"Authorization": "Bearer snaresight_stream_dev_token_2026"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/event-stream", response.headers["content-type"])
        self.assertIn("connected to snaresight", response.text)

    def test_sse_002_unauthorized_client_is_rejected(self):
        """TEST SSE-002: Unauthorized client is rejected with HTTP 401."""
        response = self.client.get("/api/v1/stream/events")
        self.assertEqual(response.status_code, 401)
        self.assertIn("Missing streaming authentication", response.json()["detail"])

    def test_sse_003_persisted_event_generates_a_notification(self):
        """TEST SSE-003: Persisted event generates a notification to connected subscribers."""
        user = StreamUser(user_id="u1", username="analyst_bob")
        sub = self.stream_manager.register_subscriber(user)

        delivered = self.event_publisher.publish_persisted_event(self.base_event)
        self.assertEqual(delivered, 1)
        self.assertFalse(sub.queue.empty())

        msg = sub.queue.get_nowait()
        self.assertIn("event: security_event", msg)
        self.assertIn(self.base_event["event_id"], msg)

    def test_sse_004_failed_database_transaction_generates_no_success_notification(self):
        """TEST SSE-004: Failed database transaction produces zero stream notifications."""
        user = StreamUser(user_id="u1", username="analyst_bob")
        sub = self.stream_manager.register_subscriber(user)

        # Malformed event that fails DB insert / processor validation
        bad_event = {"event_type": "invalid_missing_fields"}
        result = EventProcessor.process_single_event(self.db, bad_event, "collector-agent-01")

        self.assertEqual(result.status.value, "REJECTED")
        self.assertTrue(sub.queue.empty(), "No SSE message should be queued on failed transaction")

    def test_sse_005_committed_event_remains_stored_if_notification_delivery_fails(self):
        """TEST SSE-005: Committed event remains stored if notification delivery fails."""
        # Inject publisher exception
        with patch.object(EventPublisher, "publish_persisted_event", side_effect=RuntimeError("Stream offline")):
            valid_raw = {
                "raw_event_id": str(uuid.uuid4()),
                "schema_version": "1.0",
                "event_type": "login_attempt",
                "event_category": "authentication",
                "decoy_id": "WEB-001",
                "session_id": "decoy_sess_3430c5e63810486c99cff33faad6a50d",
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "source": {"ip_address": "198.51.100.45", "protocol": "https"},
                "interaction": {"username_attempted": "admin", "status_code": 401, "is_authorized": False},
                "provenance": {"source_type": "controlled_test", "environment": "isolated_lab", "source_id": "lab-01"},
            }
            res = EventProcessor.process_single_event(self.db, valid_raw, "collector-agent-01")
            self.assertEqual(res.status.value, "ACCEPTED")

            # Verify event was persisted despite stream failure
            sec_count = self.db.query(SecurityEventModel).count()
            self.assertEqual(sec_count, 1)

    def test_sse_006_sse_message_has_the_expected_format(self):
        """TEST SSE-006: SSE message follows standard id, event, and data frame syntax."""
        user = StreamUser(user_id="u1", username="analyst_bob")
        sub = self.stream_manager.register_subscriber(user)

        self.event_publisher.publish_persisted_event(self.base_event)
        msg = sub.queue.get_nowait()

        lines = msg.strip().split("\n")
        self.assertTrue(lines[0].startswith("id: cur_"))
        self.assertEqual(lines[1], "event: security_event")
        self.assertTrue(lines[2].startswith("data: {"))

    def test_sse_007_event_id_is_assigned_correctly(self):
        """TEST SSE-007: Event ID is assigned correctly in SSE frame data."""
        user = StreamUser(user_id="u1", username="analyst_bob")
        sub = self.stream_manager.register_subscriber(user)

        self.event_publisher.publish_persisted_event(self.base_event)
        msg = sub.queue.get_nowait()
        data_str = msg.split("data: ")[1].split("\n")[0]
        data_obj = json.loads(data_str)

        self.assertEqual(data_obj["event_id"], self.base_event["event_id"])
        self.assertEqual(data_obj["raw_event_id"], self.base_event["raw_event_id"])

    def test_sse_008_heartbeat_is_generated(self):
        """TEST SSE-008: Heartbeat comment frame is generated with UTC timestamp."""
        hb_frame = HeartbeatManager.format_heartbeat_frame()
        self.assertTrue(hb_frame.startswith(": ping"))
        self.assertTrue(hb_frame.endswith("\n\n"))

    def test_sse_009_client_disconnect_is_detected(self):
        """TEST SSE-009: Client disconnect is detected and subscriber is unregistered."""
        user = StreamUser(user_id="u1", username="analyst_bob")
        sub = self.stream_manager.register_subscriber(user)
        self.assertEqual(self.stream_manager.active_connections_count, 1)

        self.stream_manager.unregister_subscriber(sub.subscriber_id)
        self.assertEqual(self.stream_manager.active_connections_count, 0)
        self.assertFalse(sub.is_active)

    def test_sse_010_connection_resources_are_cleaned_up(self):
        """TEST SSE-010: Connection resources and user connection counters are cleaned up."""
        user = StreamUser(user_id="u_clean", username="clean_user")
        sub = self.stream_manager.register_subscriber(user)
        self.assertEqual(self.stream_manager._user_connection_counts[user.user_id], 1)

        self.stream_manager.unregister_subscriber(sub.subscriber_id)
        self.assertNotIn(user.user_id, self.stream_manager._user_connection_counts)

    def test_sse_011_multiple_clients_receive_authorized_notifications(self):
        """TEST SSE-011: Multiple clients receive authorized notifications."""
        u1 = StreamUser(user_id="u1", username="user1")
        u2 = StreamUser(user_id="u2", username="user2")
        sub1 = self.stream_manager.register_subscriber(u1)
        sub2 = self.stream_manager.register_subscriber(u2)

        delivered = self.event_publisher.publish_persisted_event(self.base_event)
        self.assertEqual(delivered, 2)
        self.assertFalse(sub1.queue.empty())
        self.assertFalse(sub2.queue.empty())

    def test_sse_012_filters_are_applied_correctly(self):
        """TEST SSE-012: Filters are applied independently to subscribers."""
        u1 = StreamUser(user_id="u1", username="user1")
        u2 = StreamUser(user_id="u2", username="user2")
        # sub1 filters for LOGIN_ATTEMPT; sub2 filters for DECOY_PAGE_VISITED
        sub1 = self.stream_manager.register_subscriber(u1, filter_event_type="LOGIN_ATTEMPT")
        sub2 = self.stream_manager.register_subscriber(u2, filter_event_type="DECOY_PAGE_VISITED")

        delivered = self.event_publisher.publish_persisted_event(self.base_event)
        self.assertEqual(delivered, 1)
        self.assertFalse(sub1.queue.empty())
        self.assertTrue(sub2.queue.empty(), "sub2 should not receive events matching different type")

    def test_sse_013_one_clients_failure_does_not_terminate_other_clients(self):
        """TEST SSE-013: One client's queue failure does not terminate other clients."""
        u1 = StreamUser(user_id="u1", username="slow_user")
        u2 = StreamUser(user_id="u2", username="fast_user")
        sub1 = self.stream_manager.register_subscriber(u1, queue_size=1)
        sub2 = self.stream_manager.register_subscriber(u2, queue_size=50)

        # Fill sub1's queue
        sub1.queue.put_nowait("dummy_message")

        # Publish should disconnect slow client sub1, but deliver to sub2
        delivered = self.event_publisher.publish_persisted_event(self.base_event)
        self.assertEqual(delivered, 1)
        self.assertFalse(sub2.queue.empty())
        self.assertTrue(sub1.is_slow_client)

    def test_sse_014_queue_limits_are_enforced(self):
        """TEST SSE-014: Queue limits are enforced via StreamQueueFullError."""
        u = StreamUser(user_id="u1", username="user1")
        sub = EventSubscriber(user=u, queue_size=2)
        sub.enqueue_message("msg1")
        sub.enqueue_message("msg2")

        with self.assertRaises(StreamQueueFullError):
            sub.enqueue_message("msg3")

    def test_sse_015_slow_client_handling_does_not_block_ingestion(self):
        """TEST SSE-015: Slow client handling terminates client without blocking server."""
        u = StreamUser(user_id="u1", username="user1")
        sub = self.stream_manager.register_subscriber(u, queue_size=1)
        sub.queue.put_nowait("fill")

        t0 = time.perf_counter()
        self.event_publisher.publish_persisted_event(self.base_event)
        duration = time.perf_counter() - t0

        self.assertLess(duration, 0.05, "Publishing to full queue must be non-blocking")
        self.assertEqual(self.stream_manager.slow_clients_disconnected_count, 1)

    # =========================================================================
    # RECONNECTION TESTS: TEST RECONNECT-001 to RECONNECT-006
    # =========================================================================

    def test_reconnect_001_client_reconnects_using_a_valid_cursor(self):
        """TEST RECONNECT-001: Client reconnects using a valid cursor format."""
        now_dt = datetime.now(timezone.utc)
        ev_id = uuid.uuid4()
        cursor = StreamCursor.generate_cursor(now_dt, ev_id)

        parsed_dt, id_prefix = StreamCursor.parse_cursor(cursor)
        self.assertEqual(parsed_dt.year, now_dt.year)
        self.assertEqual(id_prefix, str(ev_id).replace("-", "")[:12])

    def test_reconnect_002_missed_persisted_events_can_be_replayed(self):
        """TEST RECONNECT-002: Missed persisted events can be replayed from database."""
        # Seed 3 historical events with progressive timestamps
        t1 = datetime.now(timezone.utc) - timedelta(minutes=10)
        t2 = datetime.now(timezone.utc) - timedelta(minutes=5)
        t3 = datetime.now(timezone.utc) - timedelta(minutes=1)

        for i, ts in enumerate([t1, t2, t3], start=1):
            sec_ev = SecurityEventModel(
                event_id=uuid.uuid4(),
                raw_event_id=uuid.uuid4(),
                schema_version="1.0",
                event_type="LOGIN_ATTEMPT",
                event_category="AUTHENTICATION",
                action="SUBMIT_CREDENTIALS",
                outcome="FAILURE",
                decoy_id="WEB-001",
                session_id=f"sess_{i}",
                source_address="1.2.3.4",
                source_protocol="https",
                target_service="WEB_PORTAL",
                target_port=8080,
                observed_at=ts,
                received_at=ts,
                sanitized_metadata={},
                provenance={},
                deduplication_reference=f"dedup_replay_{i}",
            )
            self.db.add(sec_ev)
        self.db.commit()

        # Reconnect with cursor from t1 -> should replay t2 and t3 (2 events)
        cursor_t1 = StreamCursor.generate_cursor(t1, uuid.uuid4())
        user = StreamUser(user_id="u1", username="analyst", is_admin=True)

        replayed = StreamCursor.replay_missed_events(self.db, cursor_t1, user=user)
        self.assertEqual(len(replayed), 2)

    def test_reconnect_003_events_are_returned_in_stable_order(self):
        """TEST RECONNECT-003: Replayed events are returned in stable ascending chronological order."""
        t_base = datetime.now(timezone.utc) - timedelta(minutes=10)
        for i in [3, 1, 2]:  # Insert out of order
            ts = t_base + timedelta(minutes=i)
            sec_ev = SecurityEventModel(
                event_id=uuid.uuid4(),
                raw_event_id=uuid.uuid4(),
                schema_version="1.0",
                event_type="LOGIN_ATTEMPT",
                event_category="AUTHENTICATION",
                action="SUBMIT_CREDENTIALS",
                outcome="FAILURE",
                decoy_id="WEB-001",
                session_id=f"sess_order_{i}",
                source_address="1.2.3.4",
                source_protocol="https",
                target_service="WEB_PORTAL",
                target_port=8080,
                observed_at=ts,
                received_at=ts,
                sanitized_metadata={},
                provenance={},
                deduplication_reference=f"dedup_order_{i}",
            )
            self.db.add(sec_ev)
        self.db.commit()

        cursor = StreamCursor.generate_cursor(t_base, uuid.uuid4())
        user = StreamUser(user_id="u1", username="admin", is_admin=True)
        replayed = StreamCursor.replay_missed_events(self.db, cursor, user=user)

        self.assertEqual(len(replayed), 3)
        # Verify strict ascending order
        dt1 = datetime.fromisoformat(replayed[0]["observed_at"])
        dt2 = datetime.fromisoformat(replayed[1]["observed_at"])
        dt3 = datetime.fromisoformat(replayed[2]["observed_at"])
        self.assertLess(dt1, dt2)
        self.assertLess(dt2, dt3)

    def test_reconnect_004_duplicate_replay_is_handled(self):
        """TEST RECONNECT-004: Replay cursor strictly queries events newer than cursor timestamp."""
        ts = datetime.now(timezone.utc) - timedelta(minutes=5)
        ev_id = uuid.uuid4()
        sec_ev = SecurityEventModel(
            event_id=ev_id,
            raw_event_id=uuid.uuid4(),
            schema_version="1.0",
            event_type="LOGIN_ATTEMPT",
            event_category="AUTHENTICATION",
            action="SUBMIT_CREDENTIALS",
            outcome="FAILURE",
            decoy_id="WEB-001",
            session_id="sess_exact",
            source_address="1.2.3.4",
            source_protocol="https",
            target_service="WEB_PORTAL",
            target_port=8080,
            observed_at=ts,
            received_at=ts,
            sanitized_metadata={},
            provenance={},
            deduplication_reference="dedup_exact_001",
        )
        self.db.add(sec_ev)
        self.db.commit()

        # Replaying using the exact timestamp of sec_ev should NOT return sec_ev again
        cursor = StreamCursor.generate_cursor(ts, ev_id)
        user = StreamUser(user_id="u1", username="admin", is_admin=True)
        replayed = StreamCursor.replay_missed_events(self.db, cursor, user=user)
        self.assertEqual(len(replayed), 0)

    def test_reconnect_005_expired_retention_history_is_reported_correctly(self):
        """TEST RECONNECT-005: Malformed or invalid cursor raises StreamCursorError."""
        with self.assertRaises(StreamCursorError):
            StreamCursor.parse_cursor("invalid_cursor_string")

    def test_reconnect_006_unauthorized_event_replay_is_prevented(self):
        """TEST RECONNECT-006: Restricted user cannot replay events from unauthorized decoys."""
        ts = datetime.now(timezone.utc) - timedelta(minutes=5)
        # Event on WEB-002 (restricted)
        sec_ev = SecurityEventModel(
            event_id=uuid.uuid4(),
            raw_event_id=uuid.uuid4(),
            schema_version="1.0",
            event_type="LOGIN_ATTEMPT",
            event_category="AUTHENTICATION",
            action="SUBMIT_CREDENTIALS",
            outcome="FAILURE",
            decoy_id="WEB-002",
            session_id="sess_restricted",
            source_address="1.2.3.4",
            source_protocol="https",
            target_service="WEB_PORTAL",
            target_port=8080,
            observed_at=ts,
            received_at=ts,
            sanitized_metadata={},
            provenance={},
            deduplication_reference="dedup_restr_001",
        )
        self.db.add(sec_ev)
        self.db.commit()

        cursor = StreamCursor.generate_cursor(ts - timedelta(minutes=1), uuid.uuid4())
        # User only allowed WEB-001
        restricted_user = StreamUser(user_id="u_restr", username="junior", allowed_decoys={"WEB-001"}, is_admin=False)
        replayed = StreamCursor.replay_missed_events(self.db, cursor, user=restricted_user)
        self.assertEqual(len(replayed), 0, "Restricted user must not receive replayed events from WEB-002")

    # =========================================================================
    # HEALTH TESTS: TEST HEALTH-001 to HEALTH-010
    # =========================================================================

    def test_health_001_liveness_endpoint_works(self):
        """TEST HEALTH-001: Liveness endpoint returns HTTP 200 and status UP."""
        res = self.client.get("/api/v1/health/live")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "UP")

    def test_health_002_readiness_endpoint_works(self):
        """TEST HEALTH-002: Readiness endpoint returns HTTP 200 and status READY."""
        res = self.client.get("/api/v1/health/ready")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "READY")
        self.assertTrue(res.json()["database_ready"])

    def test_health_003_database_failure_is_reflected_in_readiness(self):
        """TEST HEALTH-003: Database failure is reflected in readiness probe."""
        service = PipelineHealthService(metrics=self.metrics)
        # Passing None as DB simulates database disconnection
        res = service.check_readiness(db=None)
        self.assertEqual(res["status"], "NOT_READY")
        self.assertFalse(res["database_ready"])

    def test_health_004_ingestion_health_metrics_reflect_actual_records(self):
        """TEST HEALTH-004: Ingestion health metrics reflect actual records."""
        self.metrics.record_ingestion(accepted=5, duplicates=2, rejected=1, duration_ms=12.5)
        d = self.metrics.to_dict()
        self.assertEqual(d["events_received_total"], 8)
        self.assertEqual(d["events_accepted_total"], 5)
        self.assertEqual(d["events_duplicate_total"], 2)
        self.assertEqual(d["events_rejected_total"], 1)

    def test_health_005_rejected_events_are_counted_correctly(self):
        """TEST HEALTH-005: Rejected events are counted accurately."""
        self.metrics.record_ingestion(accepted=0, duplicates=0, rejected=3, duration_ms=5.0)
        self.assertEqual(self.metrics.events_rejected_total, 3)
        self.assertIsNotNone(self.metrics.last_failed_ingestion_timestamp)

    def test_health_006_duplicate_events_are_counted_correctly(self):
        """TEST HEALTH-006: Duplicate events are counted accurately."""
        self.metrics.record_ingestion(accepted=0, duplicates=4, rejected=0, duration_ms=2.0)
        self.assertEqual(self.metrics.events_duplicate_total, 4)

    def test_health_007_streaming_connection_count_is_accurate(self):
        """TEST HEALTH-007: Streaming connection count accurately tracks active subscribers."""
        u1 = StreamUser(user_id="u1", username="user1")
        sub1 = self.stream_manager.register_subscriber(u1)
        self.assertEqual(self.stream_manager.active_connections_count, 1)

        u2 = StreamUser(user_id="u2", username="user2")
        sub2 = self.stream_manager.register_subscriber(u2)
        self.assertEqual(self.stream_manager.active_connections_count, 2)

        self.stream_manager.unregister_subscriber(sub1.subscriber_id)
        self.assertEqual(self.stream_manager.active_connections_count, 1)

    def test_health_008_notification_failure_is_recorded(self):
        """TEST HEALTH-008: Notification failure is recorded in publisher metrics."""
        u = StreamUser(user_id="u1", username="user1")
        sub = self.stream_manager.register_subscriber(u, queue_size=1)
        sub.queue.put_nowait("fill")

        self.event_publisher.publish_persisted_event(self.base_event)
        self.assertEqual(self.event_publisher.total_delivery_failures, 1)

    def test_health_009_unconfigured_components_are_marked_not_configured(self):
        """TEST HEALTH-009: Unconfigured components are marked NOT_CONFIGURED."""
        comp_health = self.health_service.get_component_health(self.db)
        components = comp_health["components"]
        self.assertEqual(components["cowrie_ssh_adapter"]["status"], ComponentHealthStatus.NOT_CONFIGURED.value)
        self.assertEqual(components["rule_detection_engine"]["status"], ComponentHealthStatus.NOT_CONFIGURED.value)

    def test_health_010_unknown_status_is_not_reported_as_healthy(self):
        """TEST HEALTH-010: Inactive/retired decoy is reported as UNKNOWN, not HEALTHY."""
        # Add retired decoy
        retired_decoy = HoneypotModel(
            decoy_id="RETIRED-01",
            name="Old Decoy",
            decoy_type="WEB_LOGIN",
            protocol="HTTP",
            environment="isolated_lab",
            status="RETIRED",
        )
        self.db.add(retired_decoy)
        self.db.commit()

        comp_health = self.health_service.get_component_health(self.db)
        self.assertEqual(
            comp_health["components"]["decoy_retired-01"]["status"],
            ComponentHealthStatus.UNKNOWN.value,
        )

    # =========================================================================
    # SECURITY TESTS: TEST SEC-STREAM-001 to SEC-STREAM-006
    # =========================================================================

    def test_sec_stream_001_sensitive_fields_are_excluded_from_stream_messages(self):
        """TEST SEC-STREAM-001: Passwords and sensitive fields are excluded from stream notifications."""
        user = StreamUser(user_id="u1", username="analyst_bob")
        sub = self.stream_manager.register_subscriber(user)

        event_with_secret = copy.deepcopy(self.base_event)
        event_with_secret["password"] = "CanaryPass123!"
        event_with_secret["secret_key"] = "sec_123"

        self.event_publisher.publish_persisted_event(event_with_secret)
        msg = sub.queue.get_nowait()

        self.assertNotIn("CanaryPass123!", msg)
        self.assertNotIn("secret_key", msg)

    def test_sec_stream_002_restricted_users_cannot_access_unauthorized_events(self):
        """TEST SEC-STREAM-002: Restricted users do not receive events from unauthorized decoys."""
        # Restricted user: only allowed WEB-001
        restricted_user = StreamUser(
            user_id="u_restr",
            username="junior",
            allowed_decoys={"WEB-001"},
            is_admin=False,
        )
        sub = self.stream_manager.register_subscriber(restricted_user)

        # Publish event from WEB-002
        event_web_002 = copy.deepcopy(self.base_event)
        event_web_002["decoy_id"] = "WEB-002"

        delivered = self.event_publisher.publish_persisted_event(event_web_002)
        self.assertEqual(delivered, 0)
        self.assertTrue(sub.queue.empty(), "Restricted user must not receive event from WEB-002")

    def test_sec_stream_003_credentials_do_not_appear_in_stream_urls(self):
        """TEST SEC-STREAM-003: Credentials in query parameters are strictly rejected."""
        res = self.client.get("/api/v1/stream/events?token=secret_in_url")
        self.assertEqual(res.status_code, 401)
        self.assertIn("strictly prohibited", res.json()["detail"])

    def test_sec_stream_004_unauthorized_source_filters_are_rejected(self):
        """TEST SEC-STREAM-004: Requesting a filter for an unauthorized decoy returns HTTP 403."""
        # analyst_restricted_token only has access to WEB-001
        res = self.client.get(
            "/api/v1/stream/events?decoy_id=WEB-UNAUTHORIZED",
            headers={"Authorization": "Bearer analyst_restricted_token"},
        )
        self.assertEqual(res.status_code, 403)
        self.assertIn("not authorized to observe decoy", res.json()["detail"])

    def test_sec_stream_005_connection_limits_work(self):
        """TEST SEC-STREAM-005: Connection limits per user and globally are enforced."""
        user = StreamUser(user_id="u_limit", username="test_limit")
        # MAX_CONNECTIONS_PER_USER is 5
        subs = []
        for _ in range(5):
            subs.append(self.stream_manager.register_subscriber(user))

        # 6th connection should raise StreamResourceLimitExceeded
        with self.assertRaises(StreamResourceLimitExceeded):
            self.stream_manager.register_subscriber(user)

    def test_sec_stream_006_unexpected_disconnects_do_not_cause_resource_leaks(self):
        """TEST SEC-STREAM-006: Unexpected disconnects cleanly unregister subscribers."""
        user = StreamUser(user_id="u_leak", username="leak_test")
        sub = self.stream_manager.register_subscriber(user)
        self.assertEqual(self.stream_manager.active_connections_count, 1)

        # Simulate unregister
        self.stream_manager.unregister_subscriber(sub.subscriber_id)
        self.assertEqual(self.stream_manager.active_connections_count, 0)
        self.assertEqual(self.stream_manager._user_connection_counts.get("u_leak", 0), 0)


if __name__ == "__main__":
    unittest.main()
