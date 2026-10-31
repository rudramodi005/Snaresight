"""End-to-End Live Validation Script for SnareSight Task P15."""

import sys
import uuid
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models.honeypot import HoneypotModel, EventSourceModel
from app.db.models.event import SecurityEventModel
from app.streaming.authorization import StreamUser
from app.streaming.stream_manager import StreamManager
from app.streaming.event_publisher import EventPublisher
from app.streaming.stream_cursor import StreamCursor
from app.monitoring.metrics import PipelineMetricsCollector
from app.monitoring.service import PipelineHealthService
from app.ingestion.schemas import EventProcessingStatus
from app.ingestion.processor import EventProcessor

def run_validation():
    print("=== Running SnareSight P15 Live E2E Streaming & Health Validation ===")
    
    # 1. Setup in-memory DB
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    
    # 2. Add Honeypot and Collector Source
    decoy = HoneypotModel(
        decoy_id="WEB-001",
        name="ApexCore Portal Decoy",
        decoy_type="WEB_LOGIN",
        protocol="HTTP",
        environment="isolated_lab",
        status="ACTIVE"
    )
    db.add(decoy)
    source = EventSourceModel(
        source_id="collector-web-01",
        source_type="HTTP_INGESTION",
        source_name="Web Login Collector",
        environment="isolated_lab",
        status="ONLINE",
    )
    db.add(source)
    db.commit()
    print("[+] Seeded honeypot decoy WEB-001 and collector source collector-web-01")
    
    # 3. Setup Streaming & Monitoring components
    from app.streaming.event_publisher import event_publisher
    from app.streaming.stream_manager import stream_manager
    from app.monitoring.metrics import metrics_collector
    from app.monitoring.service import health_service
    
    # 4. Connect SSE Subscriber
    user = StreamUser(user_id="analyst_alice", username="alice", is_admin=True)
    subscriber = stream_manager.register_subscriber(user=user, filter_decoy_id="WEB-001")
    print(f"[+] Connected SSE Subscriber: {subscriber.subscriber_id} for user {user.username}")
    
    # 5. Ingest Raw Event
    sess_id = f"decoy_sess_{uuid.uuid4().hex}"
    raw_payload = {
        "schema_version": "1.0",
        "raw_event_id": str(uuid.uuid4()),
        "event_type": "login_attempt",
        "event_category": "authentication",
        "action": "submit_credentials",
        "outcome": "failure",
        "decoy_id": "WEB-001",
        "session_id": sess_id,
        "source_address": "198.51.100.22",
        "target_service": "web_portal",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "service_metadata": {"username": "admin", "password_length": 12},
        "provenance": {"source_type": "controlled_test", "environment": "isolated_lab"}
    }
    
    res = EventProcessor.process_single_event(db, raw_payload, source_id="collector-web-01")
    print(f"[+] Processed Event: Status={res.status}, EventID={res.normalized_event_id}, Error={res.error}")
    assert res.status == EventProcessingStatus.ACCEPTED
    
    # 6. Verify Subscriber Queue Receipt
    assert not subscriber.queue.empty(), "Subscriber queue should have received post-commit event"
    raw_frame = subscriber.queue.get_nowait()
    print(f"[+] Received SSE Frame:\n{raw_frame.strip()}")
    assert "event: security_event" in raw_frame.lower()
    assert "data: " in raw_frame
    
    # 7. Disconnect and Reconnect using Cursor
    stream_manager.unregister_subscriber(subscriber.subscriber_id)
    print(f"[+] Disconnected subscriber {subscriber.subscriber_id}")
    
    observed_dt = datetime.fromisoformat(raw_payload["observed_at"])
    cursor_str = StreamCursor.generate_cursor(observed_dt, res.normalized_event_id)
    print(f"[+] Formatted Cursor for Reconnect: {cursor_str}")
    
    # Ingest a second event
    sess_id2 = f"decoy_sess_{uuid.uuid4().hex}"
    raw_payload2 = dict(raw_payload)
    raw_payload2["raw_event_id"] = str(uuid.uuid4())
    raw_payload2["session_id"] = sess_id2
    raw_payload2["observed_at"] = datetime.now(timezone.utc).isoformat()
    raw_payload2["service_metadata"] = {"username": "root", "password_length": 8}
    res2 = EventProcessor.process_single_event(db, raw_payload2, source_id="collector-web-01")
    print(f"[+] Processed Second Event: EventID={res2.normalized_event_id}")
    
    # Replay missed events using cursor
    replayed = StreamCursor.replay_missed_events(db, last_event_id=cursor_str, user=user)
    print(f"[+] Replayed {len(replayed)} missed events after cursor")
    assert len(replayed) == 1
    assert str(replayed[0]["event_id"]) == str(res2.normalized_event_id)
    
    # 8. Check Health & Metrics
    pipeline_health = health_service.get_pipeline_health(db=db)
    print(f"[+] Pipeline Health Overall Status: {pipeline_health['overall_status']}")
    print(f"[+] Pipeline Metrics: {pipeline_health['metrics']}")
    print(f"[+] Streaming Metrics: {pipeline_health['streaming']}")
    
    print("\n>>> LIVE E2E VALIDATION SUCCESSFUL! <<<")

if __name__ == "__main__":
    run_validation()
