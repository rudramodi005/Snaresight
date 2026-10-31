# SnareSight Activity Session REST API Reference

> **OPERATIONAL CAUTION & SCOPE BOUNDARY**  
> REST API endpoints under `/api/v1/sessions` provide access to single-decoy activity sessions, statistics, and timelines.  
> Attack campaign endpoints and actor profile APIs are reserved for Tasks P22 and P23.

---

## 1. Endpoints Overview

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/sessions` | List paginated, filtered activity sessions |
| `GET` | `/api/v1/sessions/statistics` | Retrieve operational metrics across all sessions |
| `GET` | `/api/v1/sessions/{session_id}` | Retrieve session details and metadata |
| `GET` | `/api/v1/sessions/{session_id}/timeline` | Retrieve chronological investigation timeline |
| `GET` | `/api/v1/sessions/{session_id}/events` | List all security events associated with session |
| `GET` | `/api/v1/sessions/{session_id}/detections` | List security alerts triggered during session |
| `GET` | `/api/v1/sessions/{session_id}/mitre-mappings` | List ATT&CK mappings associated with session alerts |

---

## 2. Endpoint Details

### 2.1 List Sessions
- **URL:** `GET /api/v1/sessions`
- **Query Parameters:**
  - `page` (int, default `1`): Page number.
  - `page_size` (int, default `20`, max `100`): Items per page.
  - `decoy_id` (string, optional): Filter by decoy ID (e.g. `WEB-001`).
  - `honeypot_type` (string, optional): Filter by type (`SSH_DAEMON`, `WEB_LOGIN`).
  - `source_address` (string, optional): Filter by source IP.
  - `status` (string, optional): Filter by status (`ACTIVE`, `IDLE`, `CLOSED`, `TIMED_OUT`).
  - `min_events` (int, optional): Minimum correlated events.
  - `has_detections` (bool, optional): Filter sessions with alerts.

**Example Response (200 OK):**
```json
{
  "total": 1,
  "page": 1,
  "page_size": 20,
  "total_pages": 1,
  "items": [
    {
      "session_id": "act-sess-abc12345",
      "decoy_id": "WEB-001",
      "honeypot_type": "WEB_LOGIN",
      "explicit_session_id": "web-tok-123",
      "connection_id": null,
      "correlation_method": "EXPLICIT_SESSION_ID",
      "source_address": "198.51.100.90",
      "source_port": 51234,
      "target_service": "HTTP",
      "protocol": "TCP",
      "first_observed_at": "2026-10-31T15:00:00Z",
      "last_activity_at": "2026-10-31T15:05:00Z",
      "ended_at": null,
      "first_ingested_at": "2026-10-31T15:00:00Z",
      "last_ingested_at": "2026-10-31T15:05:00Z",
      "session_status": "ACTIVE",
      "event_count": 2,
      "detection_count": 1,
      "highest_severity": "MEDIUM",
      "duration_seconds": 300.0,
      "correlation_policy_version": "1.0",
      "metadata_summary": {},
      "created_at": "2026-10-31T15:00:01Z",
      "updated_at": "2026-10-31T15:05:02Z"
    }
  ]
}
```

---

### 2.2 Session Statistics
- **URL:** `GET /api/v1/sessions/statistics`

**Example Response (200 OK):**
```json
{
  "total_sessions": 45,
  "active_sessions": 3,
  "idle_sessions": 2,
  "closed_sessions": 30,
  "timed_out_sessions": 10,
  "sessions_with_detections": 12,
  "total_events_correlated": 420,
  "average_events_per_session": 9.33,
  "by_honeypot": {
    "WEB-001": 25,
    "SSH-001": 20
  },
  "by_protocol": {
    "TCP": 45
  },
  "by_correlation_method": {
    "EXPLICIT_SESSION_ID": 30,
    "EXPLICIT_CONNECTION_ID": 10,
    "CONTEXTUAL_FALLBACK": 4,
    "STANDALONE": 1
  }
}
```

---

### 2.3 Session Timeline
- **URL:** `GET /api/v1/sessions/{session_id}/timeline`
- **Query Parameters:**
  - `limit` (int, default `200`, max `500`): Maximum timeline entries.

**Example Response (200 OK):**
```json
{
  "session_id": "act-sess-abc12345",
  "decoy_id": "WEB-001",
  "source_address": "198.51.100.90",
  "total_entries": 3,
  "first_observed_at": "2026-10-31T15:00:00Z",
  "last_activity_at": "2026-10-31T15:05:00Z",
  "session_status": "ACTIVE",
  "entries": [
    {
      "entry_id": "tl-evt-1",
      "session_id": "act-sess-abc12345",
      "source_record_id": "0df62706-...",
      "timestamp": "2026-10-31T15:00:00Z",
      "ingestion_timestamp": "2026-10-31T15:00:01Z",
      "entry_type": "HTTP_REQUEST",
      "title": "HTTP Request: GET /api/v1/status",
      "description": "Observed GET request with status 200",
      "component": "WEB_LOGIN",
      "category": "request",
      "severity": null,
      "is_detection": false,
      "is_late_arrival": false,
      "related_detection_id": null,
      "related_technique_id": null,
      "related_mapping_id": null,
      "mapping_status": null,
      "metadata": { "status_code": 200 }
    },
    {
      "entry_id": "tl-det-b83c...",
      "session_id": "act-sess-abc12345",
      "source_record_id": "b83c07e0-...",
      "timestamp": "2026-10-31T15:00:00Z",
      "ingestion_timestamp": "2026-10-31T15:00:02Z",
      "entry_type": "DETECTION_GENERATED",
      "title": "Detection: Suspicious Request",
      "description": "Suspicious HTTP probe observed",
      "component": "DETECTION_ENGINE",
      "category": "DETECTION",
      "severity": "MEDIUM",
      "is_detection": true,
      "is_late_arrival": false,
      "related_detection_id": "b83c07e0-...",
      "metadata": { "rule_id": "RULE-PROBE-01", "confidence": 80 }
    },
    {
      "entry_id": "tl-map-4f2a...",
      "session_id": "act-sess-abc12345",
      "source_record_id": "4f2a1b9c-...",
      "timestamp": "2026-10-31T15:00:00Z",
      "ingestion_timestamp": "2026-10-31T15:00:03Z",
      "entry_type": "ATTACK_MAPPING_GENERATED",
      "title": "ATT&CK Technique: T1190",
      "description": "Exploitation of public-facing application",
      "component": "MITRE_MAPPING_ENGINE",
      "category": "INTELLIGENCE",
      "severity": null,
      "is_detection": true,
      "is_late_arrival": false,
      "related_detection_id": "b83c07e0-...",
      "related_technique_id": "T1190",
      "related_mapping_id": "4f2a1b9c-...",
      "mapping_status": "ACCEPTED",
      "metadata": { "technique_id": "T1190", "mapping_confidence": 90 }
    }
  ]
}
```

