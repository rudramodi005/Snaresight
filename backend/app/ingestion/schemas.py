"""Pydantic schemas for the SnareSight ingestion API and batch pipeline contracts."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field
from app.ingestion.errors import IngestionErrorCode, RejectionDiagnostic


class EventProcessingStatus(str, Enum):
    """Lifecycle outcome for an ingested event."""
    
    ACCEPTED = "ACCEPTED"
    DUPLICATE = "DUPLICATE"
    REJECTED = "REJECTED"
    FAILED = "FAILED"


class EventBatchRequest(BaseModel):
    """Batch submission payload received from authorized collectors."""
    
    source_id: str = Field(..., max_length=64, description="Registered telemetry source identifier")
    schema_version: str = Field("1.0", description="Contract version")
    batch_id: str = Field(default_factory=lambda: str(uuid4()), description="Client or collector batch trace ID")
    events: list[dict[str, Any]] = Field(..., min_length=1, max_length=500, description="List of raw event objects")


class EventProcessingResult(BaseModel):
    """Outcome for an individual event within a batch."""
    
    raw_event_id: Optional[str] = Field(None, description="Event ID if extractable from payload")
    status: EventProcessingStatus
    deduplication_reference: Optional[str] = None
    normalized_event_id: Optional[str] = None
    error: Optional[RejectionDiagnostic] = None


class EventBatchResponse(BaseModel):
    """Summary response returned to collector after batch processing."""
    
    batch_id: str
    source_id: str
    total_received: int
    accepted_count: int
    duplicate_count: int
    rejected_count: int
    processing_duration_ms: float
    processed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    results: list[EventProcessingResult]


class PipelineStatusResponse(BaseModel):
    """Observability status report for the ingestion pipeline."""
    
    pipeline_state: str = "operational"
    total_received_events: int
    total_accepted_events: int
    total_duplicate_events: int
    total_rejected_events: int
    total_batches_processed: int
    avg_processing_duration_ms: float
    last_successful_ingestion: Optional[str] = None
    last_rejection_timestamp: Optional[str] = None

