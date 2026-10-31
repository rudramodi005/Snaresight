"""Unit tests for InvestigationTimelineBuilder (Task P21)."""

import unittest
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models.alert import AlertModel, AlertEvidenceModel
from app.db.models.correlation import ActivitySessionModel, ActivitySessionEventModel
from app.db.models.event import SecurityEventModel
from app.db.models.intelligence import AttackDetectionMappingModel
from app.correlation.exceptions import SessionNotFoundError
from app.correlation.timeline import InvestigationTimelineBuilder
from app.correlation.schemas import TimelineEntryType


class TestInvestigationTimeline(unittest.TestCase):
    """Verifies chronological ordering, classification, detection linkage, and ATT&CK mapping inclusion."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.db = self.SessionLocal()

        self.t0 = datetime(2026, 10, 31, 14, 0, 0, tzinfo=timezone.utc)
        self.session_id = "act-sess-timeline-test"

        # Create ActivitySession
        session = ActivitySessionModel(
            session_id=self.session_id,
            decoy_id="WEB-001",
            honeypot_type="WEB_LOGIN",
            explicit_session_id="exp-sess-999",
            correlation_method="EXPLICIT_SESSION_ID",
            correlation_key="WEB-001:WEB_LOGIN:exp-sess-999",
            source_address="198.51.100.88",
            first_observed_at=self.t0,
            last_activity_at=self.t0 + timedelta(minutes=10),
            first_ingested_at=self.t0,
            last_ingested_at=self.t0 + timedelta(minutes=10),
            session_status="ACTIVE",
            event_count=3,
            detection_count=1,
            correlation_policy_version="1.0",
        )
        self.db.add(session)

        # Create SecurityEvents & ActivitySessionEvents
        # Event 1: Normal HTTP GET
        evt1_id = uuid.uuid4()
        sec_evt1 = SecurityEventModel(
            event_id=evt1_id,
            raw_event_id=uuid.uuid4(),
            schema_version="1.0",
            event_type="request",
            event_category="request",
            action="REQUEST",
            outcome="SUCCESS",
            decoy_id="WEB-001",
            session_id="exp-sess-999",
            source_address="198.51.100.88",
            source_protocol="TCP",
            target_service="HTTP",
            target_port=80,
            observed_at=self.t0,
            received_at=self.t0,
            sanitized_metadata={"http_method": "GET", "http_path": "/index.html", "status_code": 200},
            provenance={"source": "test"},
            deduplication_reference=str(uuid.uuid4()),
        )
        assoc1 = ActivitySessionEventModel(
            session_id=self.session_id,
            event_id=evt1_id,
            event_type="request",
            event_category="request",
            action="REQUEST",
            outcome="SUCCESS",
            observed_at=self.t0,
            ingested_at=self.t0,
            association_method="EXPLICIT_SESSION_ID",
            correlation_confidence=100,
            is_late_arrival=False,
        )

        # Event 2: Directory Traversal Probe
        evt2_id = uuid.uuid4()
        t2 = self.t0 + timedelta(minutes=2)
        sec_evt2 = SecurityEventModel(
            event_id=evt2_id,
            raw_event_id=uuid.uuid4(),
            schema_version="1.0",
            event_type="request",
            event_category="request",
            action="REQUEST",
            outcome="SUCCESS",
            decoy_id="WEB-001",
            session_id="exp-sess-999",
            source_address="198.51.100.88",
            source_protocol="TCP",
            target_service="HTTP",
            target_port=80,
            observed_at=t2,
            received_at=t2,
            sanitized_metadata={"http_method": "GET", "http_path": "/../../../etc/passwd", "status_code": 404},
            provenance={"source": "test"},
            deduplication_reference=str(uuid.uuid4()),
        )
        assoc2 = ActivitySessionEventModel(
            session_id=self.session_id,
            event_id=evt2_id,
            event_type="request",
            event_category="request",
            action="REQUEST",
            outcome="SUCCESS",
            observed_at=t2,
            ingested_at=t2,
            association_method="EXPLICIT_SESSION_ID",
            correlation_confidence=100,
            is_late_arrival=False,
        )

        # Event 3: Auth Failure
        evt3_id = uuid.uuid4()
        t3 = self.t0 + timedelta(minutes=4)
        sec_evt3 = SecurityEventModel(
            event_id=evt3_id,
            raw_event_id=uuid.uuid4(),
            schema_version="1.0",
            event_type="login",
            event_category="authentication",
            action="LOGIN",
            outcome="FAILURE",
            decoy_id="WEB-001",
            session_id="exp-sess-999",
            source_address="198.51.100.88",
            source_protocol="TCP",
            target_service="HTTP",
            target_port=80,
            observed_at=t3,
            received_at=t3,
            sanitized_metadata={"http_method": "POST", "http_path": "/login", "status_code": 401},
            provenance={"source": "test"},
            deduplication_reference=str(uuid.uuid4()),
        )
        assoc3 = ActivitySessionEventModel(
            session_id=self.session_id,
            event_id=evt3_id,
            event_type="login",
            event_category="authentication",
            action="LOGIN",
            outcome="FAILURE",
            observed_at=t3,
            ingested_at=t3,
            association_method="EXPLICIT_SESSION_ID",
            correlation_confidence=100,
            is_late_arrival=False,
        )

        self.db.add_all([sec_evt1, assoc1, sec_evt2, assoc2, sec_evt3, assoc3])

        # Create Detection / Alert
        alert_id = uuid.uuid4()
        t_alert = self.t0 + timedelta(minutes=2, seconds=5)
        alert = AlertModel(
            alert_id=alert_id,
            schema_version="1.0",
            detection_rule_id="RULE-DIR-TRAVERSAL",
            detection_rule_version="1.0",
            title="Path Traversal Attempt",
            summary="Directory traversal observed against WEB-001",
            severity="HIGH",
            confidence=95,
            assessment_status="NEW",
            evidence_strength="STRONG",
            source_address="198.51.100.88",
            observed_source_id="SRC-01",
            decoy_id="WEB-001",
            target_service="HTTP",
            first_observed_at=t_alert,
            last_observed_at=t_alert,
            detection_explanation="Directory traversal attempt detected from HTTP request path.",
            recommendations={"action": "Block source IP at firewall"},
        )
        self.db.add(alert)

        # Link alert to event 2 via AlertEvidenceModel
        evidence = AlertEvidenceModel(
            alert_id=alert_id,
            event_id=evt2_id,
            evidence_role="TRIGGERING_OBSERVATION",
        )
        self.db.add(evidence)

        # Create ATT&CK Mapping
        mapping = AttackDetectionMappingModel(
            mapping_id=uuid.uuid4(),
            detection_result_id="dr-01",
            alert_id=alert_id,
            mapping_definition_id="def-dir-trav-01",
            rule_id="RULE-DIR-TRAVERSAL",
            rule_version="1.0",
            technique_id="T1083",
            subtechnique_id=None,
            dataset_version="v14.1",
            mapping_category="DIRECT_OBSERVATION",
            mapping_confidence=95,
            mapping_confidence_level="HIGH",
            confidence_explanation="High confidence due to direct path traversal indicators",
            mapping_rationale="Path traversal patterns match File and Directory Discovery",
            review_status="ACCEPTED",
            assessed_at=t_alert,
        )
        self.db.add(mapping)
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def test_build_timeline_success(self):
        """Timeline correctly assembles events, detections, and ATT&CK mappings."""
        tl = InvestigationTimelineBuilder.build_timeline(self.db, self.session_id)
        self.assertEqual(tl.session_id, self.session_id)
        self.assertEqual(tl.decoy_id, "WEB-001")
        self.assertEqual(tl.source_address, "198.51.100.88")
        # 3 events + 1 detection + 1 ATT&CK mapping = 5 entries
        self.assertEqual(len(tl.entries), 5)
        self.assertEqual(tl.total_entries, 5)

    def test_chronological_ordering(self):
        """Entries must be in strict chronological order."""
        tl = InvestigationTimelineBuilder.build_timeline(self.db, self.session_id)
        timestamps = [e.timestamp for e in tl.entries]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_entry_classifications(self):
        """Verify specialized entry type classifications."""
        tl = InvestigationTimelineBuilder.build_timeline(self.db, self.session_id)
        entry_types = [e.entry_type for e in tl.entries]

        self.assertIn(TimelineEntryType.HTTP_REQUEST, entry_types)
        self.assertIn(TimelineEntryType.DIRECTORY_TRAVERSAL, entry_types)
        self.assertIn(TimelineEntryType.AUTHENTICATION_FAILURE, entry_types)
        self.assertIn(TimelineEntryType.DETECTION_GENERATED, entry_types)
        self.assertIn(TimelineEntryType.ATTACK_MAPPING_GENERATED, entry_types)

    def test_unknown_session_raises_404(self):
        """Querying a non-existent session ID raises SessionNotFoundError."""
        with self.assertRaises(SessionNotFoundError):
            InvestigationTimelineBuilder.build_timeline(self.db, "non-existent-session-id")


if __name__ == "__main__":
    unittest.main()
