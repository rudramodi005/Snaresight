"""Health and operational telemetry endpoint."""

from fastapi import APIRouter
from app.config import settings
from app.services.event_logger import event_logger
from app.services.session_manager import session_manager

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check():
    """Returns minimal operational status without leaking internal system information."""
    return {
        "status": "healthy",
        "decoy_id": settings.DECOY_ID,
        "decoy_name": settings.DECOY_NAME,
        "version": "0.1.0",
        "events_logged": event_logger.total_events_logged,
        "active_sessions": session_manager.active_session_count(),
    }

