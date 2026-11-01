"""Comprehensive baseline demonstration data seeder for SnareSight.

Ensures every subsystem in SnareSight (Sensors, Security Events, Alerts,
Sequences, Investigations, Source Intelligence, MITRE Mappings, Response Cases,
and Platform Health) is richly populated with realistic demonstration data by default.
"""

import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session

from app.db.models.sensor import (
    SensorModel,
    SensorCredentialModel,
    SensorHeartbeatModel,
    SensorConfigurationModel,
    SensorTelemetryMetricModel,
)
from app.db.models.honeypot import HoneypotModel, EventSourceModel
from app.modules.demo.schemas import ScenarioType, DatasetSize, ScenarioRunRequest
from app.modules.demo.service import demo_service
from app.modules.correlation.sequence_engine import default_sequence_engine
from app.db.models.correlation import ActivitySessionModel
from app.modules.campaign_intelligence.clustering_engine import ClusteringEngine
from app.modules.source_intelligence.service import SourceIntelligenceService


def seed_default_sensors(db: Session) -> None:
    """Seeds managed sensor inventory, decoys, heartbeats, and telemetry reliability metrics."""
    now = datetime.now(timezone.utc)
    
    sensors_def = [
        {
            "sensor_id": "WEB-001",
            "name": "DMZ Web Application Deception Decoy",
            "sensor_type": "WEB_LOGIN_DECOY",
            "protocol": "HTTP",
            "lab_zone": "zone_dmz",
            "events_received": 1420,
            "events_persisted": 1418,
            "latency_ms": 12.4,
        },
        {
            "sensor_id": "SSH-001",
            "name": "Corporate Bastion Cowrie SSH Decoy",
            "sensor_type": "COWRIE_SSH",
            "protocol": "SSH",
            "lab_zone": "zone_corp",
            "events_received": 890,
            "events_persisted": 890,
            "latency_ms": 18.2,
        },
        {
            "sensor_id": "DB-001",
            "name": "Synthetic PostgreSQL Database Canary Decoy",
            "sensor_type": "DB_POSTGRES_DECOY",
            "protocol": "TCP",
            "lab_zone": "zone_db",
            "events_received": 340,
            "events_persisted": 339,
            "latency_ms": 8.7,
        },
        {
            "sensor_id": "API-001",
            "name": "Microservice REST Gateway Decoy",
            "sensor_type": "API_GATEWAY_DECOY",
            "protocol": "HTTP",
            "lab_zone": "zone_cloud",
            "events_received": 620,
            "events_persisted": 620,
            "latency_ms": 14.1,
        },
    ]

    for s_info in sensors_def:
        sid = s_info["sensor_id"]
        
        # 1. Ensure HoneypotModel exists
        hp = db.query(HoneypotModel).filter(HoneypotModel.decoy_id == sid).first()
        if not hp:
            hp = HoneypotModel(
                decoy_id=sid,
                name=s_info["name"],
                decoy_type=s_info["sensor_type"],
                protocol=s_info["protocol"],
                environment="isolated_lab",
                status="ACTIVE",
            )
            db.add(hp)
            db.flush()

        # 2. Ensure SensorModel exists
        sm = db.query(SensorModel).filter(SensorModel.sensor_id == sid).first()
        if not sm:
            sm = SensorModel(
                sensor_id=sid,
                name=s_info["name"],
                sensor_type=s_info["sensor_type"],
                sensor_version="1.2.0",
                deployment_environment="isolated_lab",
                lab_zone=s_info["lab_zone"],
                operational_status="ACTIVE",
                health_status="HEALTHY",
                heartbeat_interval_seconds=60,
                missed_heartbeat_count=0,
                last_heartbeat_at=now,
                last_telemetry_at=now,
                current_config_version="1.0.0",
                supported_telemetry_types=["HTTP_REQUEST", "AUTH_ATTEMPT", "TCP_INTERACTION"],
                admin_notes="Baseline enterprise deception sensor deployed for lab monitoring.",
            )
            db.add(sm)
            db.flush()

            # Heartbeat record
            hb = SensorHeartbeatModel(
                sensor_id=sid,
                timestamp=now,
                status="HEALTHY",
                latency_ms=s_info["latency_ms"],
                metrics_payload={
                    "cpu_percent": 4.2,
                    "memory_mb": 128.5,
                    "active_connections": 3,
                    "agent_version": "1.2.0",
                },
            )
            db.add(hb)

            # Versioned Configuration
            cfg = SensorConfigurationModel(
                sensor_id=sid,
                version="1.0.0",
                config_payload={
                    "capture_payloads": True,
                    "rate_limit_per_minute": 1000,
                    "tls_enabled": True,
                    "forwarding_target": "http://snaresight-backend:8000/api/v1/ingestion",
                },
                is_current=True,
                change_reason="Initial baseline configuration",
                updated_by="system",
            )
            db.add(cfg)

            # Telemetry Metrics
            metric = SensorTelemetryMetricModel(
                sensor_id=sid,
                window_start=now - timedelta(hours=1),
                window_end=now,
                events_received=s_info["events_received"],
                events_validated=s_info["events_received"],
                events_rejected=s_info["events_received"] - s_info["events_persisted"],
                events_persisted=s_info["events_persisted"],
                duplicate_events=0,
                average_latency_ms=s_info["latency_ms"],
            )
            db.add(metric)

    # Ensure EventSourceModel
    src = db.query(EventSourceModel).filter(EventSourceModel.source_id == "collector-web-01").first()
    if not src:
        src = EventSourceModel(
            source_id="collector-web-01",
            source_type="COLLECTOR_FORWARDER",
            source_name="Central Ingestion Forwarder (Cluster A)",
            environment="isolated_lab",
            schema_version="1.0",
            status="ONLINE",
        )
        db.add(src)

    db.commit()


def seed_complete_demo_data(db: Session) -> None:
    """Orchestrates comprehensive multi-scenario telemetry seeding across the platform."""
    # 1. Seed Sensors and Decoys
    seed_default_sensors(db)

    # 2. Run Demonstrations (A, B, C, D, E, F) to generate complete real cross-subsystem telemetry
    scenarios_to_run = [
        ScenarioType.SCENARIO_A,
        ScenarioType.SCENARIO_B,
        ScenarioType.SCENARIO_C,
        ScenarioType.SCENARIO_D,
        ScenarioType.SCENARIO_E,
        ScenarioType.SCENARIO_F,
    ]

    for sc in scenarios_to_run:
        try:
            req = ScenarioRunRequest(
                scenario_type=sc,
                size=DatasetSize.SMALL,
                seed=42,
                target_decoy_id="WEB-001",
            )
            demo_service.run_scenario(db=db, request=req, current_username="soc_lead")
        except Exception as e:
            print(f"[Demo Seeder] Scenario {sc.value} notice: {e}")

    # 3. Correlate all sessions into Behavioral Sequences (Attack Chains)
    try:
        sessions = db.query(ActivitySessionModel).all()
        for sess in sessions:
            default_sequence_engine.evaluate_session(db=db, session_id=sess.session_id)
    except Exception as e:
        print(f"[Demo Seeder] Sequence evaluation notice: {e}")

    # 4. Correlate sequences into Campaign Investigation Clusters
    try:
        cluster_engine = ClusteringEngine(db)
        cluster_engine.run_clustering(force_all=True)
    except Exception as e:
        print(f"[Demo Seeder] Campaign clustering notice: {e}")

    # 5. Aggregate all source IP behavioral features into Source Intelligence Profiles
    try:
        source_service = SourceIntelligenceService(db)
        source_service.trigger_aggregation()
    except Exception as e:
        print(f"[Demo Seeder] Source intelligence aggregation notice: {e}")

