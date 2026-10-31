# REST API Reference: SOC Alert Management

All endpoints are hosted under `/api/v1/alerts` and documented in OpenAPI `/docs`.

---

## 1. Endpoints Overview

| Method | Endpoint | Description | Status Code |
|:---|:---|:---|:---:|
| `GET` | `/api/v1/alerts` | Filtered, sorted, paginated alert queue | 200 OK |
| `GET` | `/api/v1/alerts/summary` | Real-time aggregate metric chips & status counts | 200 OK |
| `GET` | `/api/v1/alerts/suppression/history` | Suppression audit trail | 200 OK |
| `GET` | `/api/v1/alerts/{alert_id}` | Full explainable alert detail & scoring | 200 OK |
| `GET` | `/api/v1/alerts/{alert_id}/evidence` | Supporting events with Explorer URLs | 200 OK |
| `GET` | `/api/v1/alerts/{alert_id}/relationships`| Correlated sessions, profiles, sequences, MITRE | 200 OK |
| `GET` | `/api/v1/alerts/{alert_id}/history` | Chronological audit trail | 200 OK |
| `GET` | `/api/v1/alerts/{alert_id}/notes` | Append-only analyst notes | 200 OK |
| `POST` | `/api/v1/alerts/{alert_id}/acknowledge` | Acknowledge alert | 200 OK |
| `POST` | `/api/v1/alerts/{alert_id}/assign` | Assign / reassign analyst | 200 OK |
| `POST` | `/api/v1/alerts/{alert_id}/investigate` | Start investigation | 200 OK |
| `POST` | `/api/v1/alerts/{alert_id}/escalate` | Escalate with reason and role | 200 OK |
| `POST` | `/api/v1/alerts/{alert_id}/resolve` | Resolve with category and reason | 200 OK |
| `POST` | `/api/v1/alerts/{alert_id}/close` | Close with final disposition | 200 OK |
| `POST` | `/api/v1/alerts/{alert_id}/notes` | Append analyst note | 201 Created |
| `POST` | `/api/v1/alerts/{alert_id}/triage-decision` | Record structured triage decision | 200 OK |

---

## 2. Request & Response Examples

### `GET /api/v1/alerts/summary`
```json
{
  "total_matching": 42,
  "new_alerts": 8,
  "acknowledged_alerts": 12,
  "investigating_alerts": 10,
  "escalated_alerts": 4,
  "resolved_alerts": 6,
  "closed_alerts": 2,
  "unassigned_alerts": 6,
  "requiring_attention": 12,
  "severity_breakdown": {
    "CRITICAL": 5,
    "HIGH": 14,
    "MEDIUM": 15,
    "LOW": 6,
    "INFO": 2
  },
  "priority_breakdown": {
    "P1_CRITICAL": 8,
    "P2_HIGH": 16,
    "P3_MEDIUM": 14,
    "P4_LOW": 4
  },
  "last_refreshed_at": "2026-10-31T20:55:00.000000Z"
}
```

### `POST /api/v1/alerts/{alert_id}/escalate`
**Request Payload:**
```json
{
  "analyst_id": "analyst_bob",
  "reason": "Repeated credential stuffing across multiple honeypots; potential botnet coordination.",
  "escalation_role": "INCIDENT_RESPONSE_LEAD"
}
```

### `POST /api/v1/alerts/{alert_id}/triage-decision`
**Request Payload:**
```json
{
  "analyst_id": "analyst_alice",
  "decision": "TRUE_POSITIVE",
  "justification": "Confirmed password guessing burst against web login decoy exceeding rule threshold."
}
```

