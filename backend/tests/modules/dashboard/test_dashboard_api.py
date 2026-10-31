"""Unit and integration tests for SnareSight SOC Dashboard APIs and Services (Task P25)."""

import unittest
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.db.models.honeypot import HoneypotModel
from app.db.models.event import RawEventModel, SecurityEventModel
from app.db.models.rule import DetectionRuleModel
from app.db.models.alert import AlertModel, AlertEvidenceModel
from app.db.models.correlation import ActivitySessionModel
from app.db.models.source_profile import SourceProfileModel
from app.db.models.campaign import InvestigationClusterModel
from app.modules.dashboard.service import DashboardService


class TestDashboardBase(unittest.TestCase):
    """Test fixture with an in-memory SQLite database initialized with all declarative models."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.TestingSessionLocal = sessionmaker(
            autocommit=False, autoflush=False, bind=self.engine
        )
        self.db = self.TestingSessionLocal()

        # Override FastAPI get_db dependency
        def override_get_db():
            try:
                yield self.db
            finally:
                pass

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)
        self.engine.dispose()
        app.dependency_overrides.clear()


class TestDashboardOverview(TestDashboardBase):
    """Validates the dashboard overview endpoint, metrics, trend, and empty state behaviors."""

    def test_overview_empty_database(self):
        """Empty database returns 200 OK with zero counts and null trend changes."""
        response = self.client.get("/api/v1/dashboard/overview?range=24h")
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["time_range"], "24h")
        self.assertIn("metrics", data)
        metrics = data["metrics"]
        self.assertEqual(metrics["total_events"]["value"], 0)
        self.assertEqual(metrics["total_alerts"]["value"], 0)
        self.assertIsNone(metrics["total_events"]["change_percentage"])
        self.assertIsNone(metrics["total_alerts"]["change_percentage"])
        self.assertEqual(len(data["activity_trend"]), 24)
        self.assertEqual(len(data["recent_alerts"]), 0)
        self.assertEqual(len(data["recent_investigations"]), 0)
        self.assertEqual(len(data["sensors"]), 0)

    def test_overview_with_telemetry_and_alerts(self):
        """Populated database returns aggregated metrics, distributions, and alerts."""
        now = datetime.now(timezone.utc)

        # 1. Create Honeypot
        hp = HoneypotModel(
            decoy_id="WEB-001",
            name="Production Web Decoy",
            decoy_type="WEB_LOGIN",
            protocol="HTTP",
            environment="isolated_lab",
            status="ACTIVE",
        )
        self.db.add(hp)

        # 2. Create Detection Rule
        rule = DetectionRuleModel(
            rule_id="R-AUTH-001",
            rule_name="Brute Force Authentication",
            rule_version="1.0",
            description="Repeated failed authentications",
            category="AUTHENTICATION",
            enabled=True,
            severity="CRITICAL",
            configuration={},
        )
        self.db.add(rule)
        self.db.commit()

        # 3. Create Raw & Security Events
        raw_id = uuid.uuid4()
        raw_ev = RawEventModel(
            raw_event_id=raw_id,
            schema_version="1.0",
            event_type="LOGIN_ATTEMPT",
            event_category="AUTHENTICATION",
            decoy_id="WEB-001",
            event_source_id="agent-01",
            session_id="SESS-01",
            observed_at=now - timedelta(minutes=5),
            sanitized_payload={"user": "admin"},
            provenance={"source": "test"},
        )
        self.db.add(raw_ev)
        self.db.commit()

        sec_ev_id = uuid.uuid4()
        sec_ev = SecurityEventModel(
            event_id=sec_ev_id,
            raw_event_id=raw_id,
            schema_version="1.0",
            event_type="LOGIN_ATTEMPT",
            event_category="AUTHENTICATION",
            action="LOGIN",
            outcome="FAILURE",
            decoy_id="WEB-001",
            session_id="SESS-01",
            source_address="198.51.100.5",
            source_protocol="TCP",
            target_service="HTTP",
            target_port=8080,
            observed_at=now - timedelta(minutes=5),
            received_at=now - timedelta(minutes=5),
            sanitized_metadata={"user": "admin"},
            provenance={"source": "test"},
            deduplication_reference="DEDUP-001",
        )
        self.db.add(sec_ev)

        # 4. Create Alert
        alert_id = uuid.uuid4()
        alert = AlertModel(
            alert_id=alert_id,
            schema_version="1.0",
            detection_rule_id="R-AUTH-001",
            detection_rule_version="1.0",
            title="Critical Brute Force Login",
            summary="Multiple failed attempts",
            severity="CRITICAL",
            confidence=95,
            assessment_status="NEW",
            evidence_strength="CONCLUSIVE",
            source_address="198.51.100.5",
            observed_source_id="SRC-198-51-100-5",
            decoy_id="WEB-001",
            target_service="HTTP",
            first_observed_at=now - timedelta(minutes=5),
            last_observed_at=now - timedelta(minutes=5),
            generated_at=now - timedelta(minutes=4),
            detection_explanation="Rule matched threshold",
            recommendations=["Block IP"],
        )
        self.db.add(alert)

        # 5. Create Investigation Cluster
        cluster = InvestigationClusterModel(
            cluster_id="GRP-202610-001",
            title="Coordinated Web Probing",
            description="Multi-event probe",
            lifecycle_status="ACTIVE",
            priority="HIGH",
            first_observed_at=now - timedelta(hours=1),
            last_observed_at=now - timedelta(minutes=5),
        )
        self.db.add(cluster)

        # 6. Create Source Profile
        profile = SourceProfileModel(
            profile_id="PROF-198-51-100-5",
            display_label="Profile 198.51.100.5",
            source_ip="198.51.100.5",
            ip_family="IPv4",
            fingerprint="FP-01",
            first_observed_at=now - timedelta(hours=2),
            last_observed_at=now - timedelta(minutes=5),
            total_sessions=1,
            total_events=1,
            profile_priority="HIGH",
        )
        self.db.add(profile)
        self.db.commit()

        response = self.client.get("/api/v1/dashboard/overview?range=24h")
        self.assertEqual(response.status_code, 200)
        data = response.json()

        metrics = data["metrics"]
        self.assertEqual(metrics["total_events"]["value"], 1)
        self.assertEqual(metrics["total_alerts"]["value"], 1)
        self.assertEqual(metrics["critical_alerts"]["value"], 1)
        self.assertEqual(metrics["active_investigations"]["value"], 1)
        self.assertEqual(metrics["observed_source_profiles"]["value"], 1)
        self.assertEqual(metrics["connected_sensors"]["value"], 1)

        # Severity distribution
        crit_entry = next(s for s in data["severity_distribution"] if s["severity"] == "CRITICAL")
        self.assertEqual(crit_entry["count"], 1)
        self.assertEqual(crit_entry["percentage"], 100.0)

        # Detection categories
        auth_cat = next(c for c in data["top_categories"] if "Authentication" in c["category"])
        self.assertEqual(auth_cat["count"], 1)

        # Recent alerts
        self.assertEqual(len(data["recent_alerts"]), 1)
        self.assertEqual(data["recent_alerts"][0]["title"], "Critical Brute Force Login")

        # Sensor freshness
        sensor = data["sensors"][0]
        self.assertEqual(sensor["sensor_id"], "WEB-001")
        self.assertEqual(sensor["health_status"], "ONLINE")
        self.assertEqual(sensor["events_received"], 1)

    def test_time_range_validation(self):
        """Invalid time range values return 422 Unprocessable Entity."""
        res_invalid = self.client.get("/api/v1/dashboard/overview?range=99d")
        self.assertEqual(res_invalid.status_code, 422)

        res_1h = self.client.get("/api/v1/dashboard/overview?range=1h")
        self.assertEqual(res_1h.status_code, 200)
        self.assertEqual(len(res_1h.json()["activity_trend"]), 12)

        res_7d = self.client.get("/api/v1/dashboard/overview?range=7d")
        self.assertEqual(res_7d.status_code, 200)

        res_30d = self.client.get("/api/v1/dashboard/overview?range=30d")
        self.assertEqual(res_30d.status_code, 200)
        self.assertEqual(len(res_30d.json()["activity_trend"]), 30)


class TestDashboardSearchAndNotifications(TestDashboardBase):
    """Validates global multi-entity search and in-app notifications."""

    def test_global_search_returns_categorized_entities(self):
        """Search query matches alerts and clusters by text."""
        now = datetime.now(timezone.utc)
        hp = HoneypotModel(decoy_id="TEL-01", name="Telnet Sensor", decoy_type="TELNET", protocol="TCP", environment="isolated_lab", status="ACTIVE")
        self.db.add(hp)
        self.db.commit()

        # Add an alert
        alert = AlertModel(
            alert_id=uuid.uuid4(),
            schema_version="1.0",
            detection_rule_id="R-TELNET-01",
            detection_rule_version="1.0",
            title="Suspicious Mirai Probe Detected",
            summary="Mirai command scan",
            severity="HIGH",
            confidence=85,
            assessment_status="NEW",
            evidence_strength="CONCLUSIVE",
            source_address="203.0.113.195",
            observed_source_id="SRC-203",
            decoy_id="TEL-01",
            target_service="TELNET",
            first_observed_at=now,
            last_observed_at=now,
            generated_at=now,
            detection_explanation="Mirai signatures",
            recommendations=[],
        )
        self.db.add(alert)
        self.db.commit()

        res = self.client.get("/api/v1/dashboard/search?q=Mirai")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertGreaterEqual(data["total_results"], 1)
        alert_results = data["results_by_category"]["ALERTS"]
        self.assertEqual(len(alert_results), 1)
        self.assertIn("Mirai", alert_results[0]["title"])
        self.assertIn("/alerts?alert_id=", alert_results[0]["navigation_url"])

    def test_notifications_synthesis(self):
        """High and critical severity alerts automatically generate in-app notifications."""
        now = datetime.now(timezone.utc)
        hp = HoneypotModel(decoy_id="SSH-01", name="SSH Sensor", decoy_type="SSH", protocol="TCP", environment="isolated_lab", status="ACTIVE")
        self.db.add(hp)
        self.db.commit()

        alert = AlertModel(
            alert_id=uuid.uuid4(),
            schema_version="1.0",
            detection_rule_id="R-SSH-01",
            detection_rule_version="1.0",
            title="Root Credential Guessing",
            summary="Brute force",
            severity="CRITICAL",
            confidence=90,
            assessment_status="NEW",
            evidence_strength="CONCLUSIVE",
            source_address="198.51.100.99",
            observed_source_id="SRC-198",
            decoy_id="SSH-01",
            target_service="SSH",
            first_observed_at=now,
            last_observed_at=now,
            generated_at=now,
            detection_explanation="Test",
            recommendations=[],
        )
        self.db.add(alert)
        self.db.commit()

        res = self.client.get("/api/v1/dashboard/notifications")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertGreaterEqual(data["total_count"], 1)
        self.assertEqual(data["items"][0]["severity"], "CRITICAL")
        self.assertEqual(data["items"][0]["category"], "ALERT")

    def test_alert_detail_and_list_endpoints(self):
        """Endpoints for /dashboard/alerts and /dashboard/alerts/{alert_id} return forensic data."""
        now = datetime.now(timezone.utc)
        hp = HoneypotModel(decoy_id="WEB-01", name="Web", decoy_type="WEB", protocol="HTTP", environment="isolated_lab", status="ACTIVE")
        self.db.add(hp)
        self.db.commit()

        alert_id = uuid.uuid4()
        alert = AlertModel(
            alert_id=alert_id,
            schema_version="1.0",
            detection_rule_id="R-WEB-01",
            detection_rule_version="1.0",
            title="SQL Injection Exploit Probe",
            summary="Exploit detected",
            severity="HIGH",
            confidence=80,
            assessment_status="NEW",
            evidence_strength="CONCLUSIVE",
            source_address="198.51.100.22",
            observed_source_id="SRC-22",
            decoy_id="WEB-01",
            target_service="HTTP",
            first_observed_at=now,
            last_observed_at=now,
            generated_at=now,
            detection_explanation="Detected UNION SELECT payload in HTTP query",
            recommendations=["Deploy WAF pattern"],
        )
        self.db.add(alert)
        self.db.commit()

        # Test list
        res_list = self.client.get("/api/v1/dashboard/alerts?severity=HIGH")
        self.assertEqual(res_list.status_code, 200)
        self.assertEqual(res_list.json()["total"], 1)

        # Test detail
        res_detail = self.client.get(f"/api/v1/dashboard/alerts/{alert_id}")
        self.assertEqual(res_detail.status_code, 200)
        detail = res_detail.json()
        self.assertEqual(detail["title"], "SQL Injection Exploit Probe")
        self.assertEqual(detail["detection_explanation"], "Detected UNION SELECT payload in HTTP query")
        self.assertEqual(detail["recommendations"], ["Deploy WAF pattern"])


if __name__ == "__main__":
    unittest.main()

