# SnareSight: Honeypot Event Schema Specification
**Document ID:** ARCH-DEC-002  
**Schema Version:** `1.0`  
**Phase:** 2 — Lab Isolation and Honeypot  
**Status:** Approved Event Telemetry Contract  

---

## 1. Canonical JSONL Event Structure

Every interaction with the web decoy generates a single-line JSON record adhering to this schema:

```json
{
  "schema_version": "1.0",
  "event_id": "d1cf98ec-7a32-4d2a-89a1-098e9182371b",
  "event_type": "login_attempt",
  "observed_at": "2026-10-31T10:31:21.502847+00:00",
  "decoy_id": "WEB-DECOY-01",
  "session_id": "decoy_sess_83bac30e441348728e1e2fec35a3294e",
  "source": {
    "ip_address": "127.0.0.1",
    "user_agent_summary": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
  },
  "request": {
    "method": "POST",
    "path": "/login"
  },
  "interaction": {
    "username_fingerprint": "8b23f051e941a8bc",
    "username_length": 25,
    "password_present": true,
    "password_length_category": "medium (8-16)",
    "status_code": 401,
    "simulated_outcome": "auth_rejected",
    "notes": "Standard probe"
  },
  "provenance": {
    "source_type": "live_honeypot",
    "environment": "isolated_lab"
  }
}
```

---

## 2. Event Types & Triggers

| Event Type | Trigger Condition | Status Code | Simulated Outcome |
| :--- | :--- | :---: | :--- |
| **`decoy_page_visited`** | HTTP GET `/` or `/login` | `200` | `portal_rendered` |
| **`login_attempt`** | HTTP POST `/login` | `401` | `auth_rejected` |
| **`simulated_decoy_access`**| HTTP POST `/login` with demo trigger user | `200` | `simulated_access_granted` |
| **`invalid_request`** | 404 URL probe or oversized payload (> 32 KB) | `404` / `400` | `not_found_logged` / `oversized_payload_rejected` |
| **`session_terminated`** | HTTP GET `/logout` | `302` | `session_closed` |

