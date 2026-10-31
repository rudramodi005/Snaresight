# Server-Sent Events (SSE) Protocol and Lifecycle Specification

## 1. Protocol Specification

SnareSight SSE delivers asynchronous notifications conforming to the W3C Server-Sent Events standard (`text/event-stream`).

### Endpoint
- **URL**: `GET /api/v1/stream/events`
- **Content-Type**: `text/event-stream; charset=utf-8`
- **Cache-Control**: `no-cache, no-transform`
- **Connection**: `keep-alive`

### Message Frame Anatomy
Every security event dispatched on the SSE bus follows standard frame formatting:

```
id: 2026-10-31T12:00:00.000000+00:00:f47ac10b-58cc-4372-a567-0e02b2c3d479
event: SECURITY_EVENT
data: {"event_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479", "event_type": "LOGIN_ATTEMPT", "decoy_id": "WEB-001", ...}

```

### Heartbeat / Keepalive Frames
To maintain intermediate stateful firewalls, proxies, and load balancers without creating synthetic telemetry, comment frames are emitted every 15 seconds during quiet periods:

```
: ping 2026-10-31T12:00:15.000000+00:00

```

## 2. Subscriber Lifecycle

1. **Connection Handshake**:
   - Client initiates HTTP GET to `/api/v1/stream/events`.
   - Credentials validated from `Authorization: Bearer <token>` or session cookies.
   - Resource limits enforced (rejection with HTTP 429 if limit exceeded).
   - If `Last-Event-ID` header is present, missed events are replayed from database before switching to real-time events.

2. **Active Streaming**:
   - Client receives events as they are committed to PostgreSQL.
   - If client queue exceeds 100 unread messages, client is dropped (`slow_consumer`).

3. **Termination & Clean Teardown**:
   - When client closes socket or times out, FastAPI async generator terminates.
   - `StreamManager.unregister_subscriber()` frees queue, decrements active subscriber counters, and updates operational metrics.

