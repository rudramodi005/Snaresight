# SnareSight Real-Time Streaming and Pipeline Health Test Plan

## 1. Test Objectives & Scope
The test suite validates the reliability, security, and operational readiness of the real-time event streaming and health monitoring components implemented in Task P15.

## 2. Test Matrix

### A. Server-Sent Events (SSE) Tests: TEST SSE-001 to SSE-015
- **SSE-001**: SSE endpoint accepts valid client connection.
- **SSE-002**: Unauthenticated requests are rejected.
- **SSE-003**: Events are broadcast post-commit only.
- **SSE-004**: Rollback/failed DB transaction emits 0 stream events.
- **SSE-005**: Delivery failure never rolls back DB transaction.
- **SSE-006**: Frame syntax matches W3C SSE standard (`id`, `event`, `data`).
- **SSE-007**: Event ID is correctly assigned in message envelope.
- **SSE-008**: Heartbeat comment frames (`: ping`) generated periodically.
- **SSE-009**: Disconnection detected and client unregistered.
- **SSE-010**: Connection resources cleaned up on disconnect.
- **SSE-011**: Multiple subscribers receive broadcasts concurrently.
- **SSE-012**: Filtering by `event_type`, `category`, and `decoy_id` applied.
- **SSE-013**: One subscriber failing queue does not affect other subscribers.
- **SSE-014**: Subscriber queue limits (100 messages) enforced.
- **SSE-015**: Slow clients evicted without blocking server ingestion.

### B. Reconnection & Replay Tests: TEST RECONNECT-001 to RECONNECT-006
- **RECONNECT-001**: Client reconnects with valid cursor.
- **RECONNECT-002**: Missed events replayed from `SecurityEventModel`.
- **RECONNECT-003**: Invalid cursor rejected cleanly (HTTP 400).
- **RECONNECT-004**: Monotonic order preserved during replay.
- **RECONNECT-005**: High-water mark correctly identified.
- **RECONNECT-006**: Client catches up to real-time stream seamlessly.

### C. Pipeline Health Tests: TEST HEALTH-001 to HEALTH-010
- **HEALTH-001**: `/health/live` returns HTTP 200 and `UP`.
- **HEALTH-002**: `/health/ready` returns HTTP 200 and `READY`.
- **HEALTH-003**: Database outage reflected as HTTP 503 in `/health/ready`.
- **HEALTH-004**: Ingestion counters reflect actual processed records.
- **HEALTH-005**: Rejected records counted accurately.
- **HEALTH-006**: Duplicate records counted accurately.
- **HEALTH-007**: Active connection counters track subscribers accurately.
- **HEALTH-008**: Notification failure recorded in publisher metrics.
- **HEALTH-009**: Unconfigured modules marked `NOT_CONFIGURED`.
- **HEALTH-010**: Inactive decoys reported as `UNKNOWN`, not `HEALTHY`.

### D. Security Tests: TEST SEC-STREAM-001 to SEC-STREAM-006
- **SEC-STREAM-001**: Passwords and secrets permanently scrubbed from streams.
- **SEC-STREAM-002**: Restricted users cannot receive events from unauthorized decoys.
- **SEC-STREAM-003**: Credentials in URL query parameters strictly rejected.
- **SEC-STREAM-004**: Requesting unauthorized decoy filter returns HTTP 403.
- **SEC-STREAM-005**: Global and per-user connection limits enforced (HTTP 429).
- **SEC-STREAM-006**: Closed streams release all memory and resources immediately.

