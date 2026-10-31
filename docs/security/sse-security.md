# SnareSight: Server-Sent Events (SSE) Security Architecture

**Phase:** 7 — Security Hardening and Defensive Response  
**Task:** P31 / 40  
**Status:** `COMPLETED AND VERIFIED`

---

## 1. Authentication & Stream Authorization

1. **Authentication Requirement**:
   - Subscriptions to `GET /api/v1/stream/events` require valid authentication via HttpOnly session cookies or `Authorization: Bearer <token>` headers.
   - Credentials submitted via URL query parameters (`?token=...`) are explicitly rejected to prevent token leakage in web server access logs.
2. **JWT Integration**:
   - `StreamAuthorizer` decodes the JWT token, verifies signature and expiry, and maps the user's role and allowed decoys to a `StreamUser` context.
   - Revoked tokens are rejected with `HTTP 401 Unauthorized`.
3. **Decoy-Level Access Filtering**:
   - Analysts with restricted decoy permissions (e.g. assigned solely to `WEB-001`) are prohibited from subscribing to event streams from unassigned decoys (`HTTP 403 Forbidden`).

---

## 2. Resource Bounding & Connection Management

1. **Connection Limits**:
   - The streaming manager enforces a maximum limit on active concurrent SSE connections (`MAX_CONCURRENT_CLIENTS = 100`).
   - Excess connection requests are rejected with `HTTP 429 Too Many Requests`.
2. **Bounded Buffer Queues**:
   - Each active subscriber holds a bounded in-memory `asyncio.Queue` (capacity: 250 events).
   - If a slow client fails to consume events fast enough, oldest events are discarded to prevent backend memory exhaustion.
3. **Heartbeats & Disconnect Cleanup**:
   - Keepalive comment heartbeats (`: keepalive\n\n`) are dispatched every 15 seconds.
   - When a client disconnects, queue listeners terminate cleanly, decrementing the active connection counter.

