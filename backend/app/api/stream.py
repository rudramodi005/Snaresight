"""FastAPI route handlers for real-time Server-Sent Events (SSE) streaming."""

from typing import Optional
from fastapi import APIRouter, Depends, Header, Query, Request, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.streaming.authorization import StreamAuthorizer
from app.streaming.stream_manager import stream_manager
from app.streaming.event_publisher import event_publisher
from app.streaming.event_stream import sse_event_stream
from app.streaming.exceptions import (
    StreamAuthenticationError,
    StreamAuthorizationError,
    StreamResourceLimitExceeded,
)

router = APIRouter(prefix="/stream", tags=["Real-Time Streaming"])


@router.get(
    "/events",
    summary="Establish an authenticated real-time security event stream",
    response_description="Server-Sent Events event stream",
)
async def stream_security_events(
    request: Request,
    event_type: Optional[str] = Query(None, description="Filter by canonical event type (e.g. LOGIN_ATTEMPT)"),
    event_category: Optional[str] = Query(None, description="Filter by event category (e.g. AUTHENTICATION)"),
    decoy_id: Optional[str] = Query(None, description="Filter by decoy asset identifier (e.g. WEB-001)"),
    provenance: Optional[str] = Query(None, description="Filter by collection provenance"),
    limit: Optional[int] = Query(None, description="Optional maximum message limit before closing connection"),
    last_event_id: Optional[str] = Header(None, alias="Last-Event-ID", description="Event cursor for reconnection replay"),
    db: Session = Depends(get_db),
):
    """Subscribes an authenticated client to real-time security event notifications via SSE."""
    # 1. Authenticate request (cookie or Authorization header)
    try:
        user = StreamAuthorizer.authenticate_request(request)
    except StreamAuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        )

    # 2. Validate filter authorization
    try:
        StreamAuthorizer.validate_filter_permissions(user, requested_decoy=decoy_id)
    except StreamAuthorizationError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )

    # 3. Register client subject to connection resource limits
    try:
        subscriber = stream_manager.register_subscriber(
            user=user,
            filter_event_type=event_type,
            filter_event_category=event_category,
            filter_decoy_id=decoy_id,
            filter_provenance=provenance,
        )
    except StreamResourceLimitExceeded as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
        )

    # 4. Return SSE Streaming Response with cache-control and event-stream headers
    return StreamingResponse(
        sse_event_stream(
            subscriber=subscriber,
            request=request,
            last_event_id=last_event_id,
            db=db,
            manager=stream_manager,
            max_messages=limit,
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get(
    "/status",
    summary="Retrieve streaming service operational statistics",
    status_code=status.HTTP_200_OK,
)
async def get_stream_status():
    """Returns real-time connection and distribution statistics for the streaming engine."""
    return {
        "active_connections": stream_manager.active_connections_count,
        "max_concurrent_clients": stream_manager.MAX_CONCURRENT_CLIENTS,
        "total_messages_published": event_publisher.total_published,
        "total_messages_delivered": event_publisher.total_delivered,
        "total_delivery_failures": event_publisher.total_delivery_failures,
        "slow_clients_disconnected": stream_manager.slow_clients_disconnected_count,
    }
