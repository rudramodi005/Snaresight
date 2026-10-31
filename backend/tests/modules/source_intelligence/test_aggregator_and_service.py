"""Integration tests for SourceProfileAggregator and SourceIntelligenceService."""

import unittest
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.db.models.honeypot import HoneypotModel
from app.db.models.event import RawEventModel, SecurityEventModel
from app.db.models.correlation import ActivitySessionModel
from app.db.models.alert import AlertModel
from app.db.models.source_profile import SourceProfileModel
from app.modules.source_intelligence.aggregator import SourceProfileAggregator
from app.modules.source_intelligence.service import SourceIntelligenceService
from app.modules.source_intelligence.schemas import UpdateAssociationRequest


class TestAggregatorAndService(unittest.TestCase):
    """Verifies aggregation pipeline, database persistence, and service APIs."""

    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()

        # Seed Honeypot decoy
        self.decoy = HoneypotModel(
            decoy_id="SSH-001",
            name="SSH Bastion Honeypot",
            decoy_type="SSH_SERVER",
            protocol="SSH",
            environment="test_lab",
            status="ACTIVE",
        )
        self.db.add(self.decoy)
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def test_aggregation_idempotency_and_features(self):
        t0 = datetime.now(timezone.utc) - timedelta(hours=2)

        # Seed session
        sess = ActivitySessionModel(
            session_id="SESS-P23-01",
            decoy_id="SSH-001",
            protocol="SSH",
            correlation_key="ck-p23-01",
            source_address="198.51.100.99",
            session_status="CLOSED",
            first_observed_at=t0,
            last_activity_at=t0 + timedelta(minutes=15),
            ended_at=t0 + timedelta(minutes=15),
            first_ingested_at=t0,
            last_ingested_at=t0,
            event_count=5,
            highest_severity="LOW",
        )
        self.db.add(sess)

        # Seed raw event and events
        for i in range(5):
            raw_id = uuid.uuid4()
            raw_ev = RawEventModel(
                raw_event_id=raw_id,
                event_type="SSH_LOGIN_ATTEMPT",
                event_category="AUTHENTICATION",
                decoy_id="SSH-001",
                event_source_id="src-001",
                session_id="SESS-P23-01",
                observed_at=t0 + timedelta(seconds=i * 60),
                received_at=t0 + timedelta(seconds=i * 60),
                sanitized_payload={"username": f"admin{i}"},
                provenance={},
                validation_status="VALID",
            )
            self.db.add(raw_ev)
            self.db.flush()

            ev = SecurityEventModel(
                event_id=uuid.uuid4(),
                raw_event_id=raw_id,
                decoy_id="SSH-001",
                session_id="SESS-P23-01",
                source_address="198.51.100.99",
                source_protocol="SSH",
                target_service="SSH",
                target_port=22,
                action="LOGIN",
                observed_at=t0 + timedelta(seconds=i * 60),
                received_at=t0 + timedelta(seconds=i * 60),
                event_category="AUTHENTICATION",
                event_type="SSH_LOGIN_ATTEMPT",
                outcome="FAILURE",
                sanitized_metadata={"username": f"admin{i}"},
                provenance={},
                deduplication_reference=f"dedup-{uuid.uuid4()}",
            )
            self.db.add(ev)
        self.db.commit()

        aggregator = SourceProfileAggregator(self.db)
        profile = aggregator.aggregate_for_source_ip("198.51.100.99")
        self.db.commit()

        self.assertIsNotNone(profile)
        self.assertEqual(profile.source_ip, "198.51.100.99")
        self.assertEqual(profile.total_sessions, 1)
        self.assertEqual(profile.total_events, 5)
        self.assertEqual(profile.display_label, "Observed Source Profile: 198.51.100.99")
        self.assertEqual(profile.version, 1)

        # Re-aggregate (idempotency check)
        profile_2 = aggregator.aggregate_for_source_ip("198.51.100.99")
        self.db.commit()
        self.assertEqual(profile_2.profile_id, profile.profile_id)
        self.assertEqual(profile_2.version, 2)
        self.assertEqual(profile_2.total_events, 5)

    def test_service_listing_and_filtering(self):
        aggregator = SourceProfileAggregator(self.db)
        t0 = datetime.now(timezone.utc)

        # Seed 2 sessions with different IPs
        s1 = ActivitySessionModel(
            session_id="SESS-IP1",
            decoy_id="SSH-001",
            correlation_key="ck-ip1",
            source_address="203.0.113.1",
            protocol="SSH",
            first_observed_at=t0,
            last_activity_at=t0,
            ended_at=t0,
            first_ingested_at=t0,
            last_ingested_at=t0,
            event_count=1,
            session_status="CLOSED",
        )
        s2 = ActivitySessionModel(
            session_id="SESS-IP2",
            decoy_id="SSH-001",
            correlation_key="ck-ip2",
            source_address="203.0.113.2",
            protocol="SSH",
            first_observed_at=t0,
            last_activity_at=t0,
            ended_at=t0,
            first_ingested_at=t0,
            last_ingested_at=t0,
            event_count=1,
            session_status="CLOSED",
        )
        self.db.add_all([s1, s2])
        self.db.commit()

        aggregator.aggregate_all_sources()

        service = SourceIntelligenceService(self.db)
        listing = service.list_profiles()
        self.assertEqual(listing.total, 2)

        # Search filter
        filtered = service.list_profiles(search="113.1")
        self.assertEqual(filtered.total, 1)
        self.assertEqual(filtered.items[0].source_ip, "203.0.113.1")

    def test_analyst_notes_and_association_reviews(self):
        t0 = datetime.now(timezone.utc)
        sess = ActivitySessionModel(
            session_id="SESS-REV",
            decoy_id="SSH-001",
            correlation_key="ck-rev",
            source_address="192.0.2.77",
            protocol="SSH",
            first_observed_at=t0,
            last_activity_at=t0,
            ended_at=t0,
            first_ingested_at=t0,
            last_ingested_at=t0,
            event_count=2,
            session_status="CLOSED",
        )
        self.db.add(sess)
        self.db.commit()

        aggregator = SourceProfileAggregator(self.db)
        profile = aggregator.aggregate_for_source_ip("192.0.2.77")
        self.db.commit()

        service = SourceIntelligenceService(self.db)

        # 1. Add Note
        note_res = service.add_analyst_note(
            profile_id=profile.profile_id,
            analyst_id="ANALYST-007",
            notes="Observed scanning activity originating from public cloud egress IP.",
        )
        self.assertTrue(note_res["success"])
        self.assertEqual(note_res["analyst_notes_count"], 1)

        # 2. Update Association / Flag Shared Infrastructure
        update_req = UpdateAssociationRequest(
            analyst_id="ANALYST-007",
            is_shared_infrastructure=True,
            priority="HIGH",
            notes="Flagged as shared cloud proxy with high multi-target volume.",
        )
        updated_prof = service.update_association(profile.profile_id, update_req)
        self.assertTrue(updated_prof.is_shared_infrastructure)
        self.assertEqual(updated_prof.profile_priority, "HIGH")

        # 3. Behavior and History Audit
        behavior = service.get_profile_behavior(profile.profile_id)
        self.assertEqual(len(behavior.history), 2)  # Note + Association Review
