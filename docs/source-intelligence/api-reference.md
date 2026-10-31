# Source Intelligence API Reference

All endpoints are mounted under `/api/v1/source-profiles` and documented in the OpenAPI specification at `/docs`.

---

## 1. List Profiles
`GET /api/v1/source-profiles`

Retrieves a paginated list of Observed Source Profiles with multi-attribute filtering.

### Query Parameters
- `search` (string, optional): Search by `profile_id`, `display_label`, or `source_ip`.
- `priority` (string, optional): Filter by `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `INSUFFICIENT_DATA`.
- `status` (string, optional): Filter by `ACTIVE`, `DORMANT`, `ARCHIVED`.
- `sort_by` (string, default: `last_observed_at`): Sort field.
- `sort_order` (string, default: `desc`): `asc` or `desc`.
- `page` (integer, default: 1): Page number ($\ge 1$).
- `page_size` (integer, default: 20): Page size ($1 \le n \le 100$).

---

## 2. Get Profile Detail
`GET /api/v1/source-profiles/{profile_id}`

Retrieves an Observed Source Profile by identifier.

### Response
```json
{
  "profile_id": "PROF-9E8B2A1C0F451D8E",
  "display_label": "Observed Source Profile: 198.51.100.42",
  "source_ip": "198.51.100.42",
  "ip_family": "IPv4",
  "fingerprint": "a3f4e198b2c451d8e09f87c1234567890abcdef1234567890abcdef123456789",
  "first_observed_at": "2026-10-31T12:00:00Z",
  "last_observed_at": "2026-10-31T13:45:00Z",
  "total_sessions": 3,
  "total_events": 48,
  "total_alerts": 2,
  "distinct_categories": 2,
  "distinct_honeypots": 2,
  "protocol_distribution": { "SSH": 40, "HTTP": 8 },
  "behavioral_summary": { ... },
  "profile_priority": "HIGH",
  "profile_status": "ACTIVE",
  "is_shared_infrastructure": false,
  "analyst_notes_count": 1,
  "version": 2,
  "last_aggregated_at": "2026-10-31T13:45:00Z",
  "created_at": "2026-10-31T12:05:00Z",
  "updated_at": "2026-10-31T13:45:00Z"
}
```

---

## 3. Profile Associated Sessions
`GET /api/v1/source-profiles/{profile_id}/sessions`

Retrieves correlated activity sessions linked to this profile.

---

## 4. Profile Telemetry Events
`GET /api/v1/source-profiles/{profile_id}/events`

Retrieves raw and normalized security events associated with this source IP.

---

## 5. Profile Detection Alerts
`GET /api/v1/source-profiles/{profile_id}/alerts`

Retrieves detection alerts generated against this observed source profile.

---

## 6. Profile Behavioral Baselines
`GET /api/v1/source-profiles/{profile_id}/behavior`

Retrieves detailed behavioral metrics, feature baselines across windows, detected recurrences, and audit history.

---

## 7. Profile Trends
`GET /api/v1/source-profiles/{profile_id}/trends`

Retrieves multi-window metrics (`1H`, `24H`, `7D`, `30D`, `ALL_TIME`) and activity timeline points for charting.

---

## 8. Similar Profiles
`GET /api/v1/source-profiles/{profile_id}/similar`

Discovers behaviorally similar profiles with similarity percentages and contributing factor breakdowns.

### Query Parameters
- `limit` (integer, default: 5): Max similar profiles to return.
- `min_similarity` (float, default: 30.0): Cutoff percentage.

---

## 9. Add Analyst Note
`POST /api/v1/source-profiles/{profile_id}/notes`

Appends an analyst observation note and increments the profile's note counter.

### Request Body
```json
{
  "analyst_id": "SOC-ANALYST-1",
  "notes": "Verified source matches automated credential test runner footprint."
}
```

---

## 10. Update Profile Association & Flags
`POST /api/v1/source-profiles/{profile_id}/association`

Updates shared infrastructure flags, status overrides, or priority overrides with an audit trail.

### Request Body
```json
{
  "analyst_id": "SOC-ANALYST-1",
  "is_shared_infrastructure": true,
  "status": "ACTIVE",
  "priority": "HIGH",
  "notes": "Flagged as shared corporate egress proxy."
}
```

---

## 11. Trigger On-Demand Aggregation
`POST /api/v1/source-profiles/aggregate`

Triggers incremental profile aggregation across all active sources or a specific profile.

### Request Body
```json
{
  "profile_id": "PROF-9E8B2A1C0F451D8E",
  "force_all": true
}
```

