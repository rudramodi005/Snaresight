"""Pipeline health and operational diagnostics service for SnareSight."""

import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.monitoring.status import ComponentHealthStatus, PipelineOverallStatus
from app.monitoring.metrics import PipelineMetricsCollector, metrics_collector
from app.streaming.stream_manager import StreamManager, stream_manager
from app.streaming.event_publisher import EventPublisher, event_publisher
from app.db.models.honeypot import HoneypotModel


class PipelineHealthService:
    """Evaluates and exposes factual operational health for backend components."""

    def __init__(
        self,
        metrics: Optional[PipelineMetricsCollector] = None,
        streams: Optional[StreamManager] = None,
        publisher: Optional[EventPublisher] = None,
    ) -> None:
        self.metrics = metrics or metrics_collector
        self.streams = streams or stream_manager
        self.publisher = publisher or event_publisher

    def check_liveness(self) -> Dict[str, Any]:
        """Lightweight liveness probe confirming process responsiveness."""
        return {
            "status": "UP",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "uptime_seconds": int(time.time() - self.metrics.start_time),
        }

    def check_readiness(self, db: Optional[Session] = None) -> Dict[str, Any]:
        """Readiness probe verifying critical persistent dependencies (PostgreSQL)."""
        db_ready = False
        latency_ms = 0.0

        if db is not None:
            t0 = time.perf_counter()
            try:
                # Test query execution
                db.execute(text("SELECT 1"))
                latency_ms = (time.perf_counter() - t0) * 1000.0
                db_ready = True
                self.metrics.record_database_check(success=True, latency_ms=latency_ms)
            except Exception:
                db_ready = False
                self.metrics.record_database_check(success=False, latency_ms=0.0)

        overall_ready = db_ready

        return {
            "status": "READY" if overall_ready else "NOT_READY",
            "database_ready": db_ready,
            "database_latency_ms": round(latency_ms, 2),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def get_pipeline_health(self, db: Optional[Session] = None) -> Dict[str, Any]:
        """Provides an operational overview of ingestion, storage, and streaming health."""
        readiness = self.check_readiness(db)
        db_ready = readiness["database_ready"]

        # Derive aggregate status
        if not db_ready:
            overall = PipelineOverallStatus.DOWN
        elif self.metrics.database_connection_errors_total > 5 or self.publisher.total_delivery_failures > 10:
            overall = PipelineOverallStatus.DEGRADED
        else:
            overall = PipelineOverallStatus.OPERATIONAL

        return {
            "overall_status": overall.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metrics": self.metrics.to_dict(),
            "streaming": {
                "active_connections": self.streams.active_connections_count,
                "messages_published": self.publisher.total_published,
                "messages_delivered": self.publisher.total_delivered,
                "delivery_failures": self.publisher.total_delivery_failures,
                "slow_clients_disconnected": self.streams.slow_clients_disconnected_count,
            },
        }

    def get_component_health(self, db: Optional[Session] = None) -> Dict[str, Any]:
        """Detailed health breakdown for individual platform components."""
        now_iso = datetime.now(timezone.utc).isoformat()
        components: Dict[str, Dict[str, Any]] = {}

        # 1. Ingestion Pipeline
        components["ingestion"] = {
            "status": ComponentHealthStatus.HEALTHY.value,
            "description": "Validation, sanitization, and normalization pipeline",
            "last_ingestion": self.metrics.last_successful_ingestion_timestamp,
            "last_checked": now_iso,
        }

        # 2. Database
        db_res = self.check_readiness(db)
        components["database"] = {
            "status": ComponentHealthStatus.HEALTHY.value if db_res["database_ready"] else ComponentHealthStatus.UNAVAILABLE.value,
            "latency_ms": db_res["database_latency_ms"],
            "last_checked": now_iso,
        }

        # 3. Real-Time Streaming
        components["streaming"] = {
            "status": ComponentHealthStatus.HEALTHY.value,
            "active_clients": self.streams.active_connections_count,
            "last_checked": now_iso,
        }

        # 4. Decoys & Honeypots
        if db is not None:
            try:
                decoys = db.query(HoneypotModel).all()
                for d in decoys:
                    status_val = ComponentHealthStatus.HEALTHY.value if d.status == "ACTIVE" else ComponentHealthStatus.UNKNOWN.value
                    components[f"decoy_{d.decoy_id.lower()}"] = {
                        "status": status_val,
                        "decoy_id": d.decoy_id,
                        "decoy_type": d.decoy_type,
                        "environment": d.environment,
                        "last_checked": now_iso,
                    }
            except Exception:
                pass

        # 5. Planned integrations not yet operational
        components["cowrie_ssh_adapter"] = {
            "status": ComponentHealthStatus.NOT_CONFIGURED.value,
            "description": "Optional SSH/Telnet decoy adapter (Scheduled for future phase)",
            "last_checked": now_iso,
        }
        components["rule_detection_engine"] = {
            "status": ComponentHealthStatus.NOT_CONFIGURED.value,
            "description": "Rule-based detection engine (Phase 4 — P16)",
            "last_checked": now_iso,
        }

        return {
            "timestamp": now_iso,
            "components": components,
        }


# Default singleton health service
health_service = PipelineHealthService()

