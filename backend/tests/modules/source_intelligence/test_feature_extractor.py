"""Unit tests for behavioral feature extraction."""

import unittest
import uuid
from datetime import datetime, timezone, timedelta
from app.db.models.event import SecurityEventModel
from app.modules.source_intelligence.feature_extractor import extract_features_from_records


class TestFeatureExtractor(unittest.TestCase):
    """Verifies statistical and qualitative behavioral feature extraction."""

    def test_empty_records(self):
        feat = extract_features_from_records([], [], [])
        self.assertEqual(feat["interaction_tempo"], 0.0)
        self.assertEqual(feat["burstiness_ratio"], 0.0)
        self.assertEqual(feat["concurrency_level"], 1)
        self.assertEqual(feat["auth_attempt_count"], 0)
        self.assertEqual(feat["distinct_usernames_count"], 0)
        self.assertEqual(feat["path_traversal_probes"], 0)

    def test_tempo_and_burstiness(self):
        t0 = datetime.now(timezone.utc)
        events = [
            SecurityEventModel(
                event_id=uuid.uuid4(),
                raw_event_id=uuid.uuid4(),
                decoy_id="SSH-001",
                session_id="SESS-01",
                source_address="198.51.100.10",
                source_protocol="SSH",
                target_service="SSH",
                target_port=22,
                action="LOGIN",
                observed_at=t0 + timedelta(seconds=i * 10),
                received_at=t0 + timedelta(seconds=i * 10),
                event_category="AUTHENTICATION",
                event_type="SSH_LOGIN_ATTEMPT",
                outcome="FAILURE",
                sanitized_metadata={"username": f"user{i % 3}"},
                provenance={},
                deduplication_reference=f"dedup-{uuid.uuid4()}",
            )
            for i in range(12)
        ]

        feat = extract_features_from_records(events, [], [])
        self.assertGreater(feat["interaction_tempo"], 0.0)
        self.assertEqual(feat["auth_attempt_count"], 12)
        self.assertEqual(feat["auth_failure_count"], 12)
        self.assertEqual(feat["distinct_usernames_count"], 3)

    def test_path_traversal_extraction(self):
        t0 = datetime.now(timezone.utc)
        events = [
            SecurityEventModel(
                event_id=uuid.uuid4(),
                raw_event_id=uuid.uuid4(),
                decoy_id="WEB-001",
                session_id="SESS-01",
                source_address="198.51.100.20",
                source_protocol="HTTP",
                target_service="HTTP",
                target_port=80,
                action="GET",
                observed_at=t0,
                received_at=t0,
                event_category="WEB_REQUEST",
                event_type="HTTP_GET",
                outcome="SUCCESS",
                sanitized_metadata={"path": "/../../etc/passwd"},
                provenance={},
                deduplication_reference=f"dedup-{uuid.uuid4()}",
            ),
            SecurityEventModel(
                event_id=uuid.uuid4(),
                raw_event_id=uuid.uuid4(),
                decoy_id="WEB-001",
                session_id="SESS-01",
                source_address="198.51.100.20",
                source_protocol="HTTP",
                target_service="HTTP",
                target_port=80,
                action="GET",
                observed_at=t0 + timedelta(seconds=5),
                received_at=t0 + timedelta(seconds=5),
                event_category="WEB_REQUEST",
                event_type="HTTP_GET",
                outcome="SUCCESS",
                sanitized_metadata={"path": "/index.html"},
                provenance={},
                deduplication_reference=f"dedup-{uuid.uuid4()}",
            ),
            SecurityEventModel(
                event_id=uuid.uuid4(),
                raw_event_id=uuid.uuid4(),
                decoy_id="WEB-002",
                session_id="SESS-02",
                source_address="198.51.100.20",
                source_protocol="HTTP",
                target_service="HTTP",
                target_port=8080,
                action="POST",
                observed_at=t0 + timedelta(seconds=10),
                received_at=t0 + timedelta(seconds=10),
                event_category="WEB_REQUEST",
                event_type="HTTP_POST",
                outcome="SUCCESS",
                sanitized_metadata={"path": "/cgi-bin/cmd.exe"},
                provenance={},
                deduplication_reference=f"dedup-{uuid.uuid4()}",
            ),
        ]

        feat = extract_features_from_records(events, [], [])
        self.assertEqual(feat["path_traversal_probes"], 2)  # etc/passwd and cmd.exe
        self.assertEqual(feat["distinct_paths_probed"], 3)
        self.assertEqual(feat["distinct_honeypots_targeted"], 2)

    def test_zero_password_persistence_enforced(self):
        """Verifies that passwords in event details are NOT extracted or leaked into feature sets."""
        t0 = datetime.now(timezone.utc)
        event = SecurityEventModel(
            event_id=uuid.uuid4(),
            raw_event_id=uuid.uuid4(),
            decoy_id="SSH-001",
            session_id="SESS-01",
            source_address="198.51.100.30",
            source_protocol="SSH",
            target_service="SSH",
            target_port=22,
            action="LOGIN",
            observed_at=t0,
            received_at=t0,
            event_category="AUTHENTICATION",
            event_type="SSH_LOGIN_ATTEMPT",
            outcome="FAILURE",
            sanitized_metadata={"username": "root", "password": "supersecretpassword123"},
            provenance={},
            deduplication_reference=f"dedup-{uuid.uuid4()}",
        )
        feat = extract_features_from_records([event], [], [])
        feat_str = str(feat)
        self.assertNotIn("supersecretpassword123", feat_str)
        self.assertEqual(feat["distinct_usernames_count"], 1)
