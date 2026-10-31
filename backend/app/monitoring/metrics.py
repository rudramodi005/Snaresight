"""Centralized operational metrics collection for the SnareSight event pipeline."""

import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional


class PipelineMetricsCollector:
    """Thread-safe operational telemetry metrics accumulator."""

    def __init__(self) -> None:
        self.start_time: float = time.time()
        
        # Ingestion metrics
        self.events_received_total: int = 0
        self.events_accepted_total: int = 0
        self.events_rejected_total: int = 0
        self.events_duplicate_total: int = 0
        self.events_normalized_total: int = 0
        self.ingestion_failures_total: int = 0
        self.normalization_failures_total: int = 0
        
        # Database metrics
        self.database_queries_total: int = 0
        self.database_connection_errors_total: int = 0
        self.last_database_latency_ms: float = 0.0
        
        # Streaming metrics
        self.stream_messages_published_total: int = 0
        self.stream_messages_delivered_total: int = 0
        self.stream_delivery_failures_total: int = 0
        
        # Timestamps
        self.last_successful_ingestion_timestamp: Optional[str] = None
        self.last_failed_ingestion_timestamp: Optional[str] = None
        self.last_successful_database_check: Optional[str] = None

    def record_ingestion(self, accepted: int, duplicates: int, rejected: int, duration_ms: float) -> None:
        """Records batch ingestion outcomes."""
        total = accepted + duplicates + rejected
        self.events_received_total += total
        self.events_accepted_total += accepted
        self.events_duplicate_total += duplicates
        self.events_rejected_total += rejected
        self.events_normalized_total += accepted

        now_iso = datetime.now(timezone.utc).isoformat()
        if accepted > 0:
            self.last_successful_ingestion_timestamp = now_iso
        if rejected > 0:
            self.last_failed_ingestion_timestamp = now_iso

    def record_database_check(self, success: bool, latency_ms: float) -> None:
        """Records database health test outcomes."""
        self.database_queries_total += 1
        self.last_database_latency_ms = round(latency_ms, 2)
        if success:
            self.last_successful_database_check = datetime.now(timezone.utc).isoformat()
        else:
            self.database_connection_errors_total += 1

    def to_dict(self) -> Dict[str, Any]:
        """Returns structured dictionary of live metrics."""
        uptime_seconds = int(time.time() - self.start_time)
        return {
            "uptime_seconds": uptime_seconds,
            "events_received_total": self.events_received_total,
            "events_accepted_total": self.events_accepted_total,
            "events_rejected_total": self.events_rejected_total,
            "events_duplicate_total": self.events_duplicate_total,
            "events_normalized_total": self.events_normalized_total,
            "ingestion_failures_total": self.ingestion_failures_total,
            "normalization_failures_total": self.normalization_failures_total,
            "database_connection_errors_total": self.database_connection_errors_total,
            "last_database_latency_ms": self.last_database_latency_ms,
            "last_successful_ingestion_timestamp": self.last_successful_ingestion_timestamp,
            "last_failed_ingestion_timestamp": self.last_failed_ingestion_timestamp,
            "last_successful_database_check": self.last_successful_database_check,
        }


# Default singleton metrics collector
metrics_collector = PipelineMetricsCollector()

