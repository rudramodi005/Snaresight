# Security Events REST API Reference

Base Path: `/api/v1/events`

All endpoints enforce authentication (Bearer JWT token) and role-based permissions (`viewer`, `analyst`, or `admin`).

---

## 1. List Normalized Security Events
- **Method:** `GET`
- **Path:** `/api/v1/events`
- **Query Parameters:**
  - `start_time` (datetime, optional): Start timestamp (ISO UTC).
  - `end_time` (datetime, optional): End timestamp (ISO UTC).
  - `category` (string, optional): `AUTHENTICATION`, `RECONNAISSANCE`, `EXPLOITATION`, `COMMAND_EXECUTION`, `NETWORK_PROBE`.
  - `event_type` (string, optional): Canonical event type.
  - `sensor_id` (string, optional): Decoy sensor identifier.
  - `protocol` (string, optional): Network protocol.
  - `source_address` (string, optional): Inbound IP address.
  - `session_id` (string, optional): Correlated session ID.
  - `detection_status` (string, optional): `DETECTED` or `NORMAL`.
  - `outcome` (string, optional): `SUCCESS`, `FAILURE`, `BLOCKED`, `ERROR`.
  - `severity` (string, optional): Associated alert severity.
  - `search` (string, optional): Free text search term.
  - `sort_by` (string, default `"observed_at"`): Column to sort by.
  - `sort_order` (string, default `"desc"`): `asc` or `desc`.
  - `page` (integer, default `1`, min `1`).
  - `page_size` (integer, default `25`, min `1`, max `100`).
- **Response:** `200 OK` (`PaginatedSecurityEventsResponse`)

---

## 2. Get Events Aggregate Summary
- **Method:** `GET`
- **Path:** `/api/v1/events/summary`
- **Query Parameters:**
  - `start_time` (datetime, optional)
  - `end_time` (datetime, optional)
- **Response:** `200 OK` (`SecurityEventSummaryResponse`)

---

## 3. Fast Event Search
- **Method:** `GET`
- **Path:** `/api/v1/events/search`
- **Query Parameters:**
  - `q` (string, min_length 1): Query string.
  - `limit` (integer, default `25`, max `100`).
- **Response:** `200 OK` (`PaginatedSecurityEventsResponse`)

---

## 4. Compare Security Events
- **Method:** `POST`
- **Path:** `/api/v1/events/compare`
- **Request Body:**
```json
{
  "event_ids": [
    "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    "4a2deb4d-1c2d-3ef4-8baa-1a0d7b3dcb1a"
  ]
}
```
- **Response:** `200 OK` (`EventComparisonResponse`)

---

## 5. Get Forensic Event Detail
- **Method:** `GET`
- **Path:** `/api/v1/events/{event_id}`
- **Response:** `200 OK` (`EventDetailResponse`)
- **Error:** `404 Not Found` if event ID is invalid.

---

## 6. Get Event Relationships
- **Method:** `GET`
- **Path:** `/api/v1/events/{event_id}/relationships`
- **Response:** `200 OK` (Array of `EventRelationshipItem`)

---

## 7. Get Chronological Timeline
- **Method:** `GET`
- **Path:** `/api/v1/events/{event_id}/timeline`
- **Query Parameters:**
  - `window_minutes` (integer, default `60`, min `5`, max `1440`).
- **Response:** `200 OK` (`EventTimelineResponse`)

---

## 8. Add Analyst Note
- **Method:** `POST`
- **Path:** `/api/v1/events/{event_id}/notes`
- **Request Body:**
```json
{
  "note": "Observed automated brute force burst from Tor exit gateway",
  "analyst_id": "soc_lead"
}
```
- **Response:** `201 Created` (`EventAuditLogItem`)

---

## 9. Update Review Status
- **Method:** `POST`
- **Path:** `/api/v1/events/{event_id}/review`
- **Request Body:**
```json
{
  "review_status": "ESCALATED",
  "note": "Escalated for attack chain correlation",
  "analyst_id": "soc_lead"
}
```
- **Response:** `200 OK` (`EventAuditLogItem`)

---

## 10. Associate with Investigation
- **Method:** `POST`
- **Path:** `/api/v1/events/{event_id}/investigations/{cluster_id}`
- **Request Body:**
```json
{
  "cluster_id": "CAMP-API-01",
  "reason": "Correlated probe signature matches ongoing campaign cluster",
  "analyst_id": "soc_lead"
}
```
- **Response:** `200 OK`

