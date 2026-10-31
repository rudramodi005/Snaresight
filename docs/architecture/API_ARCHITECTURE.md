# SnareSight: API Architecture & Endpoint Contracts
**Document ID:** ARCH-006  
**Status:** Approved API Contract Specification  

---

## 1. Architectural Principles

* **RESTful JSON API:** Standardized semantic HTTP status codes (`200 OK`, `201 Created`, `400 Bad Request`, `401 Unauthorized`, `403 Forbidden`, `422 Unprocessable Entity`, `500 Internal Error`).
* **Versioned Base Path:** All operational endpoints reside under `/api/v1/`.
* **Stateless Authentication:** Bearer JWT tokens in `Authorization: Bearer <token>` header for user endpoints; Pre-shared cryptographic ingestion tokens for telemetry endpoints.
* **Strict Validation:** Request and response schemas enforced via Pydantic models.

---

## 2. API Endpoint Groups

### A. Authentication & User Access (`/api/v1/auth`)
* `POST /api/v1/auth/login`
  * **Request:** `{ "username": "admin", "password": "..." }`
  * **Response:** `{ "access_token": "ey...", "token_type": "bearer", "expires_in": 3600 }`
* `GET /api/v1/auth/me`
  * **Response:** `{ "id": "uuid", "username": "admin", "role": "Analyst" }`

### B. Telemetry Ingestion (`/api/v1/ingest`)
* `POST /api/v1/ingest/events`
  * **Auth:** Ingestion Bearer Token (`X-Decoy-Token`)
  * **Request:**
    ```json
    {
      "decoy_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "provenance": "live_honeypot",
      "event_timestamp": "2026-10-31T14:00:00Z",
      "event_type": "WEB_LOGIN_ATTEMPT",
      "source_ip": "192.168.1.100",
      "http_method": "POST",
      "target_uri": "/admin/login",
      "user_agent": "Mozilla/5.0...",
      "payload": {
        "username": "root",
        "password_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      }
    }
    ```
  * **Response:** `202 Accepted` `{ "status": "queued", "event_id": "uuid" }`

### C. Honeypot Management (`/api/v1/honeypots`)
* `GET /api/v1/honeypots` — List all registered decoys and status (`ONLINE`, `DEGRADED`, `OFFLINE`).
* `GET /api/v1/honeypots/{id}` — Retrieve detailed decoy metadata and metrics.
* `POST /api/v1/honeypots` — Register new decoy profile (Admin only).

### D. Events & Telemetry Explorer (`/api/v1/events`)
* `GET /api/v1/events` — Paginated event list with filters (`source_ip`, `event_type`, `provenance`, `date_range`).
* `GET /api/v1/events/{id}` — Retrieve single event with raw payload and forensic metadata.

### E. Alerts & Detections (`/api/v1/alerts`)
* `GET /api/v1/alerts` — Query alerts filtered by `severity` (`LOW`, `MED`, `HIGH`, `CRIT`) and `status` (`NEW`, `TRIAGED`, `RESOLVED`).
* `PATCH /api/v1/alerts/{id}/status` — Update triage state.

### F. Attack-Chain Graphs (`/api/v1/attack-chains`)
* `GET /api/v1/attack-chains` — List multi-stage correlated chains.
* `GET /api/v1/attack-chains/{id}/graph` — Returns nodes and edges formatted for React Flow graph visualization.

### G. MITRE ATT&CK Matrix (`/api/v1/intelligence/mitre`)
* `GET /api/v1/intelligence/mitre/techniques` — List all indexed ATT&CK techniques with observation hit counters.
* `GET /api/v1/intelligence/mitre/coverage` — Return heatmap matrix data showing observed vs unobserved techniques.

### H. Case Investigations (`/api/v1/investigations`)
* `POST /api/v1/investigations` — Open new case from alert list.
* `POST /api/v1/investigations/{id}/notes` — Append analyst investigation note.
* `GET /api/v1/investigations/{id}/report` — Generate structured incident report.

### I. Real-Time Streaming (`/api/v1/events/stream`)
* `GET /api/v1/events/stream` (SSE)
  * Streams live notifications (`event: "ALERT"`, `event: "HEARTBEAT"`, `event: "NEW_EVENT"`).

