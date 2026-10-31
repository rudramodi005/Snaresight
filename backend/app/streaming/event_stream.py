"""Async generator driving the Server-Sent Events (SSE) HTTP connection lifecycle."""

import asyncio
from typing import AsyncGenerator, Optional
from sqlalchemy.orm import Session
from fastapi import Request

from app.streaming.event_subscriber import EventSubscriber
from app.streaming.stream_manager import StreamManager, stream_manager
from app.streaming.stream_cursor import StreamCursor
from app.streaming.heartbeat import HeartbeatManager


async def sse_event_stream(
    subscriber: EventSubscriber,
    request: Request,
    last_event_id: Optional[str] = None,
    db: Optional[Session] = None,
    manager: Optional[StreamManager] = None,
    heartbeat_interval_seconds: int = 15,
    max_messages: Optional[int] = None,
) -> AsyncGenerator[str, None]:
    """Generates SSE frames, manages keepalives, and unregisters client on disconnect."""
    mgr = manager or stream_manager
    yielded_count = 0

    try:
        # 1. Connection confirmation frame
        yield ": connected to snaresight live event stream\n\n"
        yielded_count += 1
        if max_messages and yielded_count >= max_messages:
            return

        # 2. Replay missed events if client reconnected with Last-Event-ID
        if last_event_id and db is not None:
            try:
                missed_events = StreamCursor.replay_missed_events(
                    db=db,
                    last_event_id=last_event_id,
                    user=subscriber.user,
                )
                for ev in missed_events:
                    if subscriber.matches_filter(ev):
                        cur_id = ev.get("cursor_id", "")
                        import json
                        data_json = json.dumps(ev)
                        yield f"id: {cur_id}\nevent: security_event\ndata: {data_json}\n\n"
                        yielded_count += 1
                        if max_messages and yielded_count >= max_messages:
                            return
            except Exception:
                # If cursor is invalid or expired, notify client to refresh
                yield "event: cursor_reset\ndata: {\"reason\": \"cursor_expired_or_invalid\"}\n\n"
                yielded_count += 1
                if max_messages and yielded_count >= max_messages:
                    return

        # 3. Stream loop
        while subscriber.is_active:
            # Check if client disconnected at HTTP level
            if await request.is_disconnected():
                break

            try:
                # Wait for next event or heartbeat timeout
                message = await asyncio.wait_for(
                    subscriber.queue.get(), timeout=heartbeat_interval_seconds
                )
                yield message
                subscriber.queue.task_done()
                yielded_count += 1
                if max_messages and yielded_count >= max_messages:
                    break
            except asyncio.TimeoutError:
                # Heartbeat keepalive
                yield HeartbeatManager.format_heartbeat_frame()
                yielded_count += 1
                if max_messages and yielded_count >= max_messages:
                    break

    except asyncio.CancelledError:
        pass
    finally:
        mgr.unregister_subscriber(subscriber.subscriber_id)
