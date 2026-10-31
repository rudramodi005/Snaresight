"""Ingestion service coordinating batch submissions, file imports, and pipeline observability."""

import time
from datetime import datetime, timezone
from typing import Any
from sqlalchemy.orm import Session
from app.ingestion.schemas import (
    EventBatchRequest,
    EventBatchResponse,
    EventProcessingResult,
    EventProcessingStatus,
    PipelineStatusResponse,
)
from app.ingestion.processor import EventProcessor
from app.ingestion.importer import JsonlTelemetryImporter


class IngestionService:
    """Manages telemetry ingestion workflows and maintains real-time pipeline metrics."""

    def __init__(self):
        # Operational observability metrics
        self._total_received = 0
        self._total_accepted = 0
        self._total_duplicate = 0
        self._total_rejected = 0
        self._total_batches = 0
        self._total_duration_ms = 0.0
        self._last_successful_ingestion: str | None = None
        self._last_rejection_timestamp: str | None = None

    def process_batch(self, request: EventBatchRequest, db: Session | None = None) -> EventBatchResponse:
        """Processes an authenticated batch of raw security events."""
        start_time = time.perf_counter()
        results: list[EventProcessingResult] = []
        accepted = 0
        duplicates = 0
        rejected = 0
        
        for event in request.events:
            result = EventProcessor.process_single_event(db, event, request.source_id)
            results.append(result)
            
            if result.status == EventProcessingStatus.ACCEPTED:
                accepted += 1
            elif result.status == EventProcessingStatus.DUPLICATE:
                duplicates += 1
            else:
                rejected += 1

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        
        # Update metrics
        self._total_received += len(request.events)
        self._total_accepted += accepted
        self._total_duplicate += duplicates
        self._total_rejected += rejected
        self._total_batches += 1
        self._total_duration_ms += duration_ms
        
        try:
            from app.monitoring.metrics import metrics_collector
            metrics_collector.record_ingestion(accepted, duplicates, rejected, duration_ms)
        except Exception:
            pass
        
        now_str = datetime.now(timezone.utc).isoformat()
        if accepted > 0:
            self._last_successful_ingestion = now_str
        if rejected > 0:
            self._last_rejection_timestamp = now_str

        return EventBatchResponse(
            batch_id=request.batch_id,
            source_id=request.source_id,
            total_received=len(request.events),
            accepted_count=accepted,
            duplicate_count=duplicates,
            rejected_count=rejected,
            processing_duration_ms=round(duration_ms, 2),
            results=results,
        )

    def import_jsonl_file(self, file_path_str: str, source_id: str, db: Session | None = None) -> dict[str, Any]:
        """Imports events from a sanitized JSONL file."""
        return JsonlTelemetryImporter.import_file(db, file_path_str, source_id)

    def get_pipeline_status(self) -> PipelineStatusResponse:
        """Returns live observability metrics for the ingestion pipeline."""
        avg_duration = (
            round(self._total_duration_ms / self._total_batches, 2)
            if self._total_batches > 0
            else 0.0
        )
        return PipelineStatusResponse(
            pipeline_state="operational",
            total_received_events=self._total_received,
            total_accepted_events=self._total_accepted,
            total_duplicate_events=self._total_duplicate,
            total_rejected_events=self._total_rejected,
            total_batches_processed=self._total_batches,
            avg_processing_duration_ms=avg_duration,
            last_successful_ingestion=self._last_successful_ingestion,
            last_rejection_timestamp=self._last_rejection_timestamp,
        )


# Global service instance
ingestion_service = IngestionService()

