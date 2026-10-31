"""Automated unit test suite for SOC Analytics, Reporting & Executive Overview (Task P30)."""

import uuid
from datetime import datetime, timezone, timedelta
import unittest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.db.models.honeypot import HoneypotModel
from app.db.models.event import SecurityEventModel, RawEventModel
from app.db.models.alert import AlertModel, AlertEvidenceModel
from app.db.models.rule import DetectionRuleModel
from app.db.models.correlation import ActivitySessionModel
from app.db.models.sequence import BehavioralSequenceModel
from app.db.models.source_profile import SourceProfileModel
from app.db.models.campaign import InvestigationClusterModel
from app.db.models.intelligence import AttackTechniqueModel, AttackTacticModel, AttackDetectionMappingModel
from app.db.models.report import SecurityReportModel
from app.main import app


class TestAnalyticsApiBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        cls.TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=cls.engine)
        Base.metadata.create_all(bind=cls.engine)

        def override_get_db():
            db = cls.TestingSessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=cls.engine)

    def _clean_tables(self):
        for model in [
            SecurityReportModel,
            AttackDetectionMappingModel,
            AttackTechniqueModel,
            AttackTacticModel,
            InvestigationClusterModel,
            SourceProfileModel,
            ActivitySessionModel,
            AlertEvidenceModel,
            AlertModel,
            SecurityEventModel,
            RawEventModel,
            DetectionRuleModel,
            HoneypotModel,
        ]:
            try:
                self.db.query(model).delete()
            except Exception:
                pass
        self.db.commit()

    def setUp(self):
        self.db: Session = self.TestingSessionLocal()
        self._clean_tables()
        self._seed_telemetry()

    def tearDown(self):
        self.db.rollback()
        self._clean_tables()
        self.db.close()

    def _seed_telemetry(self):
        now = datetime.now(timezone.utc)
        
        # 1. Sensor
        h_id = uuid.uuid4()
        self.sensor_id = "cowrie-ssh-01"
        hp = HoneypotModel(
            id=h_id,
            decoy_id="cowrie-ssh-01",
            name="cowrie-ssh-dmz-01",
            decoy_type="COWRIE",
            protocol="SSH",
            environment="isolated_lab",
            status="ACTIVE",
            created_at=now - timedelta(days=2),
        )
        self.db.add(hp)

        # 2. Detection Rule
        rule = DetectionRuleModel(
            id=uuid.uuid4(),
            rule_id="AUTH-001",
            rule_name="SSH Brute Force Guessing",
            rule_version="1.0",
            description="Brute force login detection",
            category="CREDENTIAL_ACCESS",
            severity="HIGH",
            enabled=True,
            configuration={"threshold": 5, "window_seconds": 300},
            created_at=now - timedelta(days=5),
        )
        self.db.add(rule)
        self.db.commit()

        # 3. Events
        evt_ids = []
        for i in range(5):
            e_id = uuid.uuid4()
            raw_id = uuid.uuid4()
            evt_ids.append(e_id)

            raw_ev = RawEventModel(
                id=uuid.uuid4(),
                raw_event_id=raw_id,
                schema_version="1.0",
                event_type="authentication_attempt",
                event_category="AUTHENTICATION",
                decoy_id="cowrie-ssh-01",
                event_source_id="src-01",
                session_id=f"sess-{i}",
                observed_at=now - timedelta(minutes=10 + i * 5),
                sanitized_payload={"username": f"root{i}"},
                provenance={"adapter": "cowrie"},
                validation_status="VALID",
                created_at=now,
            )
            self.db.add(raw_ev)

            ev = SecurityEventModel(
                id=uuid.uuid4(),
                event_id=e_id,
                raw_event_id=raw_id,
                schema_version="1.0",
                event_type="authentication_attempt",
                event_category="AUTHENTICATION",
                action="login",
                outcome="FAILURE",
                decoy_id="cowrie-ssh-01",
                session_id=f"sess-{i}",
                source_address="198.51.100.22",
                source_port=44120 + i,
                source_protocol="SSH",
                target_service="ssh",
                target_port=22,
                observed_at=now - timedelta(minutes=10 + i * 5),
                received_at=now - timedelta(minutes=10 + i * 5),
                sanitized_metadata={"username": f"root{i}"},
                provenance={"adapter": "cowrie"},
                deduplication_reference=f"dedup-{e_id}",
                created_at=now,
            )
            self.db.add(ev)

        # 4. Alert & Evidence
        a_id = uuid.uuid4()
        self.alert_id = str(a_id)
        alt = AlertModel(
            id=uuid.uuid4(),
            alert_id=a_id,
            schema_version="1.0",
            detection_rule_id="AUTH-001",
            detection_rule_version="1.0",
            title="SSH Brute Force",
            summary="Repeated failed authentications observed",
            severity="HIGH",
            confidence=85,
            evidence_strength="STRONG",
            source_address="198.51.100.22",
            observed_source_id="src-ip-198-51-100-22",
            decoy_id="cowrie-ssh-01",
            target_service="ssh",
            first_observed_at=now - timedelta(minutes=35),
            last_observed_at=now - timedelta(minutes=10),
            generated_at=now - timedelta(minutes=15),
            assessment_status="INVESTIGATING",
            detection_explanation="Rule matched 5 attempts",
            recommendations={"action": "isolate"},
            priority_score=78.5,
            priority_level="P2_HIGH",
            created_at=now,
        )
        self.db.add(alt)
        self.db.commit()

        for eid in evt_ids[:2]:
            ev_link = AlertEvidenceModel(
                id=uuid.uuid4(),
                alert_id=a_id,
                event_id=eid,
                evidence_role="TRIGGERING_OBSERVATION",
            )
            self.db.add(ev_link)

        # 5. Activity Session
        sess = ActivitySessionModel(
            id=uuid.uuid4(),
            session_id="sess-001",
            decoy_id="cowrie-ssh-01",
            honeypot_type="COWRIE",
            correlation_method="CONTEXTUAL_FALLBACK",
            correlation_key="198.51.100.22:22",
            source_address="198.51.100.22",
            target_service="ssh",
            protocol="TCP",
            first_observed_at=now - timedelta(minutes=35),
            last_activity_at=now - timedelta(minutes=10),
            first_ingested_at=now - timedelta(minutes=35),
            last_ingested_at=now - timedelta(minutes=10),
            session_status="ACTIVE",
            event_count=5,
            detection_count=1,
            highest_severity="HIGH",
            created_at=now,
        )
        self.db.add(sess)

        # 6. Source Profile
        prof = SourceProfileModel(
            id=uuid.uuid4(),
            profile_id="prof-001",
            display_label="Profile 198.51.100.22",
            source_ip="198.51.100.22",
            fingerprint="fp-001",
            first_observed_at=now - timedelta(days=3),
            last_observed_at=now - timedelta(minutes=10),
            total_sessions=3,
            total_events=15,
            total_alerts=2,
            profile_priority="HIGH",
            profile_status="ACTIVE",
            created_at=now,
        )
        self.db.add(prof)

        # 7. Investigation Cluster
        cluster = InvestigationClusterModel(
            id=uuid.uuid4(),
            cluster_id="cluster-001",
            title="Campaign-Alpha-SSH-Spray",
            description="Coordinated password guessing against SSH decoy",
            lifecycle_status="ACTIVE",
            priority="HIGH",
            review_status="UNREVIEWED",
            analyst_owner="analyst_soc_user",
            first_observed_at=now - timedelta(hours=2),
            last_observed_at=now - timedelta(minutes=10),
            created_at=now - timedelta(hours=2),
        )
        self.db.add(cluster)

        # 8. MITRE ATT&CK Objects
        tactic = AttackTacticModel(
            stix_id="x-mitre-tactic--001",
            tactic_id="TA0006",
            tactic_name="Credential Access",
            short_name="credential-access",
            dataset_version="v14.1",
            is_deprecated=False,
            is_revoked=False,
            created_at=now,
        )
        self.db.add(tactic)

        tech = AttackTechniqueModel(
            stix_id="attack-pattern--001",
            technique_id="T1110",
            technique_name="Brute Force",
            tactic_id="TA0006",
            tactic_name="Credential Access",
            framework_version="v14.1",
            tactics=["TA0006"],
            platforms=["Linux", "Windows"],
            is_subtechnique=False,
            is_deprecated=False,
            is_revoked=False,
            created_at=now,
        )
        self.db.add(tech)

        mapping = AttackDetectionMappingModel(
            id=uuid.uuid4(),
            detection_result_id=str(uuid.uuid4()),
            alert_id=a_id,
            rule_id="AUTH-001",
            rule_version="1.0",
            technique_id="T1110",
            dataset_version="v14.1",
            mapping_definition_id="MAP-DEF-001",
            mapping_definition_version="1.0",
            mapping_category="DIRECTLY_SUPPORTED",
            mapping_confidence=85,
            mapping_confidence_level="HIGH",
            confidence_explanation="Direct credential guessing telemetry",
            mapping_rationale="SSH brute force matches T1110",
            review_status="PENDING",
            assessed_at=now,
            created_at=now,
        )
        self.db.add(mapping)
        self.db.commit()


class TestAnalyticsEndpoints(TestAnalyticsApiBase):

    def test_overview_aggregation_and_comparison(self):
        """GET /api/v1/analytics/overview returns KPI counts and valid comparisons."""
        res = self.client.get("/api/v1/analytics/overview?time_range=24h")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["time_range"], "24h")
        self.assertEqual(data["total_events"], 5)
        self.assertEqual(data["total_alerts"], 1)
        self.assertEqual(data["high_alerts"], 1)
        self.assertEqual(data["critical_alerts"], 0)
        self.assertEqual(data["active_sessions"], 1)
        self.assertEqual(data["suspicious_sessions"], 1)
        self.assertEqual(data["active_investigations"], 1)
        self.assertEqual(data["reporting_sensors"], 1)
        self.assertIn("comparison", data)
        self.assertIn("events", data["comparison"])

    def test_events_timeline(self):
        """GET /api/v1/analytics/events/timeline returns grouped discrete buckets."""
        res = self.client.get("/api/v1/analytics/events/timeline?time_range=24h")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["total_events"], 5)
        self.assertGreater(len(data["buckets"]), 0)
        bucket_sum = sum(b["total_count"] for b in data["buckets"])
        self.assertEqual(bucket_sum, 5)

    def test_alerts_timeline(self):
        """GET /api/v1/analytics/alerts/timeline returns grouped alert counts."""
        res = self.client.get("/api/v1/analytics/alerts/timeline?time_range=24h")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["total_alerts"], 1)
        bucket_sum = sum(b["total_count"] for b in data["buckets"])
        self.assertEqual(bucket_sum, 1)

    def test_event_alert_overview(self):
        """GET /api/v1/analytics/event-alert-overview computes density ratio."""
        res = self.client.get("/api/v1/analytics/event-alert-overview?time_range=24h")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["total_events"], 5)
        self.assertEqual(data["total_alerts"], 1)
        self.assertEqual(data["events_supporting_alerts"], 2)
        self.assertEqual(data["event_to_alert_ratio"], 5.0)
        self.assertIn("Correlation Notice", data["explanation_notice"])

    def test_detection_analytics(self):
        """GET /api/v1/analytics/detections returns top rules, categories, and inactive rules."""
        res = self.client.get("/api/v1/analytics/detections")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["total_active_rules"], 1)
        self.assertEqual(data["rules_with_triggers"], 1)
        self.assertEqual(data["rules_without_triggers"], 0)
        self.assertEqual(len(data["top_rules"]), 1)
        self.assertEqual(data["top_rules"][0]["rule_id"], "AUTH-001")
        self.assertEqual(data["top_rules"][0]["trigger_count"], 1)

    def test_severity_and_confidence_separation(self):
        """GET /api/v1/analytics/severity and /confidence evaluate metrics independently."""
        sev_res = self.client.get("/api/v1/analytics/severity")
        self.assertEqual(sev_res.status_code, 200)
        sev_data = sev_res.json()
        self.assertEqual(sev_data["total_alerts"], 1)

        conf_res = self.client.get("/api/v1/analytics/confidence")
        self.assertEqual(conf_res.status_code, 200)
        conf_data = conf_res.json()
        self.assertEqual(conf_data["total_assessments"], 1)
        self.assertEqual(conf_data["average_confidence"], 85.0)

    def test_session_and_source_analytics(self):
        """GET /api/v1/analytics/sessions and /sources return behavioral distributions."""
        s_res = self.client.get("/api/v1/analytics/sessions")
        self.assertEqual(s_res.status_code, 200)
        s_data = s_res.json()
        self.assertEqual(s_data["total_sessions"], 1)
        self.assertEqual(s_data["suspicious_sessions"], 1)

        src_res = self.client.get("/api/v1/analytics/sources")
        self.assertEqual(src_res.status_code, 200)
        src_data = src_res.json()
        self.assertEqual(src_data["total_profiles"], 1)
        self.assertEqual(src_data["recurring_profiles"], 1)
        self.assertIn("Attribution Safeguard", src_data["privacy_and_identity_caveat"])

    def test_investigations_and_attack_coverage(self):
        """GET /api/v1/analytics/investigations and /attack-coverage."""
        inv_res = self.client.get("/api/v1/analytics/investigations")
        self.assertEqual(inv_res.status_code, 200)
        inv_data = inv_res.json()
        self.assertEqual(inv_data["total_clusters"], 1)
        self.assertEqual(inv_data["active_investigations"], 1)

        att_res = self.client.get("/api/v1/analytics/attack-coverage")
        self.assertEqual(att_res.status_code, 200)
        att_data = att_res.json()
        self.assertEqual(att_data["total_catalogue_techniques"], 1)
        self.assertEqual(att_data["mapped_techniques_count"], 1)
        self.assertEqual(att_data["supported_by_alerts_count"], 1)

    def test_sensor_and_pipeline_health(self):
        """GET /api/v1/analytics/sensors and /pipeline-health."""
        s_res = self.client.get("/api/v1/analytics/sensors")
        self.assertEqual(s_res.status_code, 200)
        s_data = s_res.json()
        self.assertEqual(s_data["total_sensors"], 1)
        self.assertEqual(s_data["reporting_sensors"], 1)

        p_res = self.client.get("/api/v1/analytics/pipeline-health")
        self.assertEqual(p_res.status_code, 200)
        p_data = p_res.json()
        self.assertEqual(p_data["pipeline_state"], "HEALTHY")

    def test_executive_summary_narrative(self):
        """GET /api/v1/analytics/executive-summary produces factual deterministic text."""
        res = self.client.get("/api/v1/analytics/executive-summary?time_range=24h")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("5 security events", data["observed_activity_narrative"])
        self.assertIn("1 actionable alerts", data["observed_activity_narrative"])
        self.assertIn("CREDENTIAL_ACCESS", data["alert_trends_narrative"])
        self.assertGreater(len(data["operational_limitations"]), 0)


class TestSecurityReporting(TestAnalyticsApiBase):

    def test_generate_and_download_pdf_report(self):
        """POST /api/v1/reports/generate (PDF) builds valid binary PDF artifact."""
        payload = {
            "report_title": "Quarterly Executive Threat Intelligence",
            "report_type": "EXECUTIVE_SUMMARY",
            "time_range": "24h",
            "file_format": "PDF",
            "analyst_id": "analyst_lead",
        }
        gen_res = self.client.post("/api/v1/reports/generate", json=payload)
        self.assertEqual(gen_res.status_code, 200)
        data = gen_res.json()
        self.assertEqual(data["file_format"], "PDF")
        self.assertEqual(data["status"], "COMPLETED")
        self.assertGreater(data["file_size_bytes"], 100)

        # Download PDF
        report_id = data["report_id"]
        down_res = self.client.get(f"/api/v1/reports/{report_id}/download")
        self.assertEqual(down_res.status_code, 200)
        self.assertEqual(down_res.headers["content-type"], "application/pdf")
        self.assertTrue(down_res.content.startswith(b"%PDF-"))

    def test_generate_and_download_csv_report(self):
        """POST /api/v1/reports/generate (CSV) builds formatted text with redaction."""
        payload = {
            "report_title": "Forensic Telemetry CSV Export",
            "report_type": "INCIDENT_TRIAGE",
            "time_range": "24h",
            "file_format": "CSV",
            "analyst_id": "analyst_secops",
        }
        gen_res = self.client.post("/api/v1/reports/generate", json=payload)
        self.assertEqual(gen_res.status_code, 200)
        data = gen_res.json()
        self.assertEqual(data["file_format"], "CSV")

        # Download CSV
        report_id = data["report_id"]
        down_res = self.client.get(f"/api/v1/reports/{report_id}/download")
        self.assertEqual(down_res.status_code, 200)
        self.assertEqual(down_res.headers["content-type"], "text/csv; charset=utf-8")
        csv_text = down_res.content.decode("utf-8")
        self.assertIn("# SnareSight Security Operations Report", csv_text)
        self.assertIn("AUTH-001", csv_text)

    def test_report_metadata_and_404(self):
        """GET /api/v1/reports/{id} returns metadata or 404 for unknown report."""
        res_404 = self.client.get(f"/api/v1/reports/{uuid.uuid4()}")
        self.assertEqual(res_404.status_code, 404)
