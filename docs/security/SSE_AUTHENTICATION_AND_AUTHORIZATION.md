# SSE Authentication and Role-Based Authorization

## 1. Authentication Policies

Streaming endpoints provide access to live honeypot telemetry and must adhere to strict authentication controls.

### Approved Authentication Vectors
1. **Authorization Header**: `Authorization: Bearer <token>`
2. **Secure Session Cookies**: `session_token` or `access_token` cookies with `HttpOnly; Secure; SameSite=Strict`.

### Strictly Prohibited Vectors
- **Query Parameter Tokens (`?token=...`, `?key=...`)**:
  - Strictly rejected with HTTP 401 Unauthorized.
  - Reason: Query parameters are logged in web server access logs, browser history, reverse proxy access logs, and referrer headers, leading to credential leakage.

## 2. Authorization and Source-Level Filtering

1. **Role-Based Telemetry Access**:
   - `StreamUser` contains user ID, role, and authorized decoy IDs (`allowed_decoys`).
   - Platform administrators have access to all decoys.
   - Restricted users are only permitted to observe decoy IDs assigned to their profile.

2. **Filter Authorization Enforcement**:
   - If a client requests `GET /api/v1/stream/events?decoy_id=WEB-002`, `StreamAuthorizer` verifies that `WEB-002` exists in the user's `allowed_decoys`.
   - Unauthorized filter requests are immediately rejected with HTTP 403 Forbidden.

3. **In-Flight Filtering**:
   - Even when listening to a broad stream, `EventSubscriber.matches()` validates that incoming events match the subscriber's permitted decoy IDs before putting the event onto the client's queue.

