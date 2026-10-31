"""FastAPI API routes for authenticated telemetry ingestion."""

import os
from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.ingestion.schemas import EventBatchRequest, EventBatchResponse, PipelineStatusResponse
from app.services.ingestion_service import ingestion_service

router = APIRouter(prefix="/ingestion", tags=["Telemetry Ingestion"])

# Configured ingestion collector API key
INGESTION_API_KEY = os.getenv("INGESTION_API_KEY", "snare-collector-key-dev-2026")


def verify_collector_auth(x_api_key: str = Header(None, alias="X-API-Key")) -> str:
    """Enforces authentication on ingestion endpoints."""
    if not x_api_key or x_api_key != INGESTION_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized telemetry source: invalid or missing X-API-Key header",
        )
    return x_api_key


@router.post(
    "/events/batch",
    response_model=EventBatchResponse,
    status_code=status.HTTP_200_OK,
    summary="Submit a batch of raw security events",
)
async def submit_event_batch(
    request: EventBatchRequest,
    api_key: str = Depends(verify_collector_auth),
    db: Session = Depends(get_db),
) -> EventBatchResponse:
    """Ingests, validates, sanitizes, normalizes, and persists a batch of honeypot events."""
    if len(request.events) > 500:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Batch size exceeds maximum limit of 500 events",
        )
    return ingestion_service.process_batch(request, db=db)


@router.get(
    "/status",
    response_model=PipelineStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve pipeline observability status",
)
async def get_ingestion_status(
    api_key: str = Depends(verify_collector_auth),
) -> PipelineStatusResponse:
    """Returns real-time processing metrics for the ingestion pipeline."""
    return ingestion_service.get_pipeline_status()

