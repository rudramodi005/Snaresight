# SnareSight Behavioral Sequence REST API Reference

> **OPERATIONAL CAUTION & SCOPE BOUNDARY**  
> REST API endpoints under `/api/v1/sequences` provide access to multi-session behavioral candidate sequences.  
> They do not attribute activity to human identities or perform automated blocking.

---

## 1. Endpoints Overview

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/sequences` | List paginated, filtered behavioral sequences |
| `GET` | `/api/v1/sequences/statistics` | Retrieve operational metrics across all sequences |
| `GET` | `/api/v1/sequences/{sequence_id}` | Retrieve sequence details with members and relationships |
| `GET` | `/api/v1/sequences/{sequence_id}/timeline` | Retrieve chronological multi-session timeline |
| `GET` | `/api/v1/sequences/{sequence_id}/evidence` | List field-level evidence traces |
| `GET` | `/api/v1/sequences/{sequence_id}/sessions` | List referenced ActivitySession records |
| `GET` | `/api/v1/sequences/{sequence_id}/detections` | List referenced Alert detection findings |
| `GET` | `/api/v1/sequences/{sequence_id}/mitre` | List referenced ATT&CK technique mappings |
| `POST` | `/api/v1/sequences/{sequence_id}/assessment` | Record authorized analyst review assessment |
| `POST` | `/api/v1/sequences/{sequence_id}/status` | Transition sequence lifecycle status |

---

## 2. Selected Payload Examples

### 2.1 List Sequences
- **URL:** `GET /api/v1/sequences?status=NEW&page=1&page_size=20`

**Response (200 OK):**
```json
{
  "total": 1,
  "page": 1,
  "page_size": 20,
  "total_pages": 1,
  "items": [
    {
      "sequence_id": "seq-20261031-a8f192b0",
      "title": "Multi-Stage ATT&CK Technique Progression",
      "sequence_pattern": "MULTI_TECHNIQUE_PROGRESSION",
      "description": "Automated behavioral candidate grouping across 2 sessions.",
      "lifecycle_status": "NEW",
      "first_observed_at": "2026-10-31T10:00:00Z",
      "last_observed_at": "2026-10-31T12:00:00Z",
      "session_count": 2,
      "event_count": 6,
      "detection_count": 2,
      "correlation_confidence": 85,
      "sequence_relevance": 95,
      "aggregate_severity": "HIGH",
      "analyst_review_status": "UNREVIEWED",
      "primary_source_address": "198.51.100.30",
      "primary_decoy_id": "WEB-001",
      "correlation_policy_version": "1.0",
      "metadata_summary": {},
      "created_at": "2026-10-31T12:05:00Z",
      "updated_at": null
    }
  ]
}
```

---

### 2.2 Record Analyst Assessment
- **URL:** `POST /api/v1/sequences/{sequence_id}/assessment`
- **Request Body:**
```json
{
  "assessment_action": "CONFIRM",
  "review_notes": "Analyst verified multi-session progression against public web decoy."
}
```

**Response (200 OK):**
```json
{
  "sequence_id": "seq-20261031-a8f192b0",
  "title": "Multi-Stage ATT&CK Technique Progression",
  "lifecycle_status": "REVIEWED",
  "analyst_review_status": "CONFIRMED_PROGRESSION",
  "correlation_confidence": 85,
  "sequence_relevance": 95,
  "aggregate_severity": "HIGH",
  "updated_at": "2026-10-31T14:30:00Z"
}
```

