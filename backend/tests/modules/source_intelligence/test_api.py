"""Integration tests for Source Intelligence REST API endpoints (Task P23)."""

import unittest
import uuid
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models.honeypot import HoneypotModel
from app.db.models.event import RawEventModel, SecurityEventModel
from app.db.models.correlation import ActivitySessionModel
from app.db.session import get_db
from app.main import app
from app.modules.source_intelligence.aggregator import SourceProfileAggregator


class TestSourceIntelligenceApi(unittest.TestCase):
    """Verifies all REST endpoints under /api/v1/source-profiles."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.db = self.SessionLocal()

        def override_get_db():
            try:
                yield self.db
            finally:
                pass

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

        # Seed initial data
        self.decoy = HoneypotModel(
            decoy_id="WEB-001",
            name="ApexCore Portal Decoy",
            decoy_type="WEB_LOGIN",
            protocol="HTTP",
            environment="isolated_lab",
            status="ACTIVE",
        )
        self.db.add(self.decoy)

        t0 = datetime.now(timezone.utc) - timedelta(hours=1)
        self.session = ActivitySessionModel(
            session_id="SESS-API-01",
            decoy_id="WEB-001",
            protocol="HTTP",
            correlation_key="ck-api-01",
            source_address="198.51.100.42",
            session_status="CLOSED",
            first_observed_at=t0,
            last_activity_at=t0 + timedelta(minutes=10),
            ended_at=t0 + timedelta(minutes=10),
            first_ingested_at=t0,
            last_ingested_at=t0,
            event_count=3,
            highest_severity="MEDIUM",
        )
        self.db.add(self.session)

        for i in range(3):
            raw_id = uuid.uuid4()
            raw_ev = RawEventModel(
                raw_event_id=raw_id,
                event_type="HTTP_LOGIN_ATTEMPT",
                event_category="AUTHENTICATION",
                decoy_id="WEB-001",
                event_source_id="src-001",
                session_id="SESS-API-01",
                observed_at=t0 + timedelta(seconds=i * 30),
                received_at=t0 + timedelta(seconds=i * 30),
                sanitized_payload={"username": f"analyst{i}"},
                provenance={},
                validation_status="VALID",
            )
            self.db.add(raw_ev)
            self.db.flush()

            ev = SecurityEventModel(
                event_id=uuid.uuid4(),
                raw_event_id=raw_id,
                decoy_id="WEB-001",
                session_id="SESS-API-01",
                source_address="198.51.100.42",
                source_protocol="HTTP",
                target_service="HTTP",
                target_port=80,
                action="POST",
                observed_at=t0 + timedelta(seconds=i * 30),
                received_at=t0 + timedelta(seconds=i * 30),
                event_category="AUTHENTICATION",
                event_type="HTTP_LOGIN_ATTEMPT",
                outcome="FAILURE",
                sanitized_metadata={"username": f"analyst{i}"},
                provenance={},
                deduplication_reference=f"dedup-{uuid.uuid4()}",
            )
            self.db.add(ev)
        self.db.commit()

        # Aggregate profile
        agg = SourceProfileAggregator(self.db)
        self.profile = agg.aggregate_for_source_ip("198.51.100.42")
        self.db.commit()

    def tearDown(self):
        app.dependency_overrides.clear()
        self.db.close()
        self.engine.dispose()

    def test_list_profiles_endpoint(self):
        res = self.client.get("/api/v1/source-profiles")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["source_ip"], "198.51.100.42")
        self.assertEqual(data["items"][0]["display_label"], "Observed Source Profile: 198.51.100.42")

    def test_get_profile_by_id(self):
        pid = self.profile.profile_id
        res = self.client.get(f"/api/v1/source-profiles/{pid}")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["profile_id"], pid)
        self.assertEqual(data["total_events"], 3)
        self.assertEqual(data["total_sessions"], 1)

    def test_get_profile_not_found(self):
        res = self.client.get("/api/v1/source-profiles/PROF-NONEXISTENT")
        self.assertEqual(res.status_code, 404)

    def test_get_profile_sessions_and_events(self):
        pid = self.profile.profile_id
        # Sessions
        res_s = self.client.get(f"/api/v1/source-profiles/{pid}/sessions")
        self.assertEqual(res_s.status_code, 200)
        sessions = res_s.json()
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0]["session_id"], "SESS-API-01")

        # Events
        res_e = self.client.get(f"/api/v1/source-profiles/{pid}/events")
        self.assertEqual(res_e.status_code, 200)
        events = res_e.json()
        self.assertEqual(len(events), 3)

    def test_get_profile_behavior(self):
        pid = self.profile.profile_id
        res = self.client.get(f"/api/v1/source-profiles/{pid}/behavior")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["profile_id"], pid)
        self.assertIn("baseline_features", data)
        self.assertEqual(data["baseline_features"]["auth_failure_count"], 3)
        self.assertEqual(data["baseline_features"]["distinct_usernames_count"], 3)

    def test_get_profile_trends(self):
        pid = self.profile.profile_id
        res = self.client.get(f"/api/v1/source-profiles/{pid}/trends")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["profile_id"], pid)
        self.assertIn("windows", data)
        self.assertIn("activity_timeline", data)

    def test_get_similar_profiles(self):
        pid = self.profile.profile_id
        res = self.client.get(f"/api/v1/source-profiles/{pid}/similar")
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(res.json(), list)

    def test_add_analyst_note_endpoint(self):
        pid = self.profile.profile_id
        payload = {
            "analyst_id": "SOC-ANALYST-1",
            "notes": "Verified source matches automated credential test runner footprint.",
        }
        res = self.client.post(f"/api/v1/source-profiles/{pid}/notes", json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["analyst_notes_count"], 1)

    def test_update_association_endpoint(self):
        pid = self.profile.profile_id
        payload = {
            "analyst_id": "SOC-ANALYST-1",
            "is_shared_infrastructure": True,
            "status": "ACTIVE",
            "priority": "HIGH",
            "notes": "Escalated priority due to observed credential spraying.",
        }
        res = self.client.post(f"/api/v1/source-profiles/{pid}/association", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["is_shared_infrastructure"])
        self.assertEqual(data["profile_priority"], "HIGH")

    def test_trigger_aggregation_endpoint(self):
        res = self.client.post("/api/v1/source-profiles/aggregate", json={"force_all": True})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertGreaterEqual(data["aggregated_profiles_count"], 1)
