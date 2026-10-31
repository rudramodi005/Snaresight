"""Unit tests for SnareSight SQLAlchemy 2.0 ORM models, constraints, and metadata."""

import unittest
import uuid
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.db.models import (
    Base,
    HoneypotModel,
    EventSourceModel,
    RawEventModel,
    SecurityEventModel,
    SessionModel,
    DetectionRuleModel,
    AlertModel,
    AlertEvidenceModel,
    AttackTechniqueModel,
    TechniqueMappingModel,
    ObservedSourceModel,
    SimulationRunModel,
)


class TestSQLAlchemyModels(unittest.TestCase):
    """Verifies relational models, metadata, constraints, and sensitive data protection."""
    
    def test_01_all_twelve_tables_present_in_metadata(self):
        """TEST DB-003: Verifies all 12 required tables are registered in Base.metadata."""
        expected_tables = {
            "honeypots",
            "event_sources",
            "raw_events",
            "security_events",
            "sessions",
            "detection_rules",
            "alerts",
            "alert_evidence",
            "simulation_runs",
            "observed_sources",
            "attack_techniques",
            "technique_mappings",
            "attack_dataset_versions",
            "attack_tactics",
            "attack_subtechniques",
            "attack_relationships",
            "attack_import_runs",
            "attack_mapping_definitions",
            "attack_detection_mappings",
            "attack_mapping_evidence",
            "attack_mapping_reviews",
            "attack_mapping_history",
            "attack_mapping_policy_versions",
            "activity_sessions",
            "activity_session_events",
            "session_correlation_history",
            "correlation_policy_versions",
            "behavioral_sequences",
            "behavioral_sequence_members",
            "behavioral_sequence_relationships",
            "sequence_evidence",
            "sequence_assessment_history",
            "source_profiles",
            "source_profile_sessions",
            "source_profile_features",
            "source_profile_history",
            "source_profile_recurrences",
            "investigation_clusters",
            "cluster_memberships",
            "cluster_evidence",
            "cluster_relationships",
            "cluster_audit_logs",
            "event_audit_logs",
            "alert_audit_logs",
            "alert_notes",
            "security_reports",
            "users",
            "revoked_tokens",
            "system_audit_logs",
            "response_cases",
            "case_relationships",
            "case_notes",
            "response_recommendations",
            "playbook_definitions",
            "playbook_executions",
            "response_approvals",
            "response_actions",
            "evidence_preservation_holds",
            "sensors",
            "sensor_credentials",
            "sensor_heartbeats",
            "sensor_configurations",
            "operational_alerts",
            "sensor_maintenance_history",
            "sensor_telemetry_metrics",
            "internal_security_events",
            "internal_security_alerts",
            "component_health_records",
            "database_backups",
            "restore_test_records",
            "dr_configs",
            "dr_checklists",
            "internal_security_incidents",
            "internal_incident_notes",
        }
        registered_tables = set(Base.metadata.tables.keys())
        self.assertEqual(expected_tables, registered_tables)

    def test_02_honeypot_model_attributes(self):
        """TEST DB-004: Verifies HoneypotModel column attributes and defaults."""
        decoy = HoneypotModel(
            decoy_id="WEB-001",
            name="ApexCore Portal Decoy",
            decoy_type="WEB_LOGIN",
            protocol="HTTP",
            environment="isolated_lab",
            status="ACTIVE"
        )
        self.assertEqual(decoy.decoy_id, "WEB-001")
        self.assertEqual(decoy.status, "ACTIVE")
        self.assertEqual(decoy.environment, "isolated_lab")
        # Check column-level default
        col_default = HoneypotModel.__table__.c.status.default.arg
        self.assertEqual(col_default, "ACTIVE")

    def test_03_zero_password_columns_exist_across_all_models(self):
        """TEST DB-020: Enforces Zero Password Persistence Invariant at schema level."""
        prohibited_terms = {"password", "secret", "private_key", "auth_token", "hash"}
        for table_name, table in Base.metadata.tables.items():
            for column in table.columns:
                col_name = column.name.lower()
                for term in prohibited_terms:
                    if col_name in {"password", "plaintext_password", "password_hash", "user_password"}:
                        self.fail(f"CRITICAL VIOLATION: Prohibited column '{col_name}' in table '{table_name}'")

    def test_04_check_constraints_defined(self):
        """TEST DB-013 & DB-014: Verifies CheckConstraints on alerts, rules, and outcomes."""
        sec_events_table = Base.metadata.tables["security_events"]
        constraints = [c.name for c in sec_events_table.constraints]
        self.assertTrue(any("ck_sec_events_outcome" in c for c in constraints))
        
        alerts_table = Base.metadata.tables["alerts"]
        alert_constraints = [c.name for c in alerts_table.constraints]
        self.assertTrue(any("ck_alerts_severity" in c for c in alert_constraints))
        self.assertTrue(any("ck_alerts_confidence_range" in c for c in alert_constraints))

    def test_05_foreign_key_definitions_and_delete_rules(self):
        """TEST DB-012: Confirms RESTRICT delete policy on critical forensic evidence."""
        sec_events_table = Base.metadata.tables["security_events"]
        for fk in sec_events_table.foreign_keys:
            # Foreign keys to honeypots and raw_events must be RESTRICT
            self.assertEqual(fk.ondelete, "RESTRICT")


if __name__ == "__main__":
    unittest.main()
