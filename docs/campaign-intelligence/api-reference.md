# Campaign Intelligence REST API Reference

Base Path: `/api/v1/investigations`

All endpoints require authentication (Bearer JWT token) and appropriate RBAC role scopes (`investigator`, `analyst`, or `admin`).

---

## 1. List Clusters
- **Method:** `GET`
- **Path:** `/api/v1/investigations/clusters`
- **Query Parameters:**
  - `status` (string, optional): Filter by `lifecycle_status` (`CANDIDATE`, `UNDER_REVIEW`, `ACTIVE`, `MONITORING`, `CLOSED`, `DISMISSED`, `MERGED`, `SPLIT`)
  - `priority` (string, optional): Filter by `priority` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
  - `confidence_level` (string, optional): Filter by confidence level
  - `assigned_to` (string, optional): Filter by assigned analyst
  - `search` (string, optional): Substring search across title, code, description, and notes
  - `limit` (integer, default `50`, max `200`)
  - `offset` (integer, default `0`)
- **Response:** `200 OK`
```json
{
  "total": 1,
  "limit": 50,
  "offset": 0,
  "items": [
    {
      "id": "CLUST-202610-01",
      "cluster_code": "GRP-202610-001",
      "title": "Coordinated SSH/Telnet Reconnaissance Cluster",
      "lifecycle_status": "ACTIVE",
      "confidence_score": 0.85,
      "confidence_level": "HIGH",
      "priority": "HIGH",
      "first_seen_at": "2026-10-31T10:00:00Z",
      "last_seen_at": "2026-10-31T14:30:00Z",
      "entity_counts": {"sessions": 4, "alerts": 2, "source_profiles": 1},
      "shared_indicators": {"ips": ["198.51.100.10"], "ports": [2222, 2323]},
      "mitre_tactics": ["TA0043", "TA0001"],
      "mitre_techniques": ["T1595", "T1110"],
      "assigned_to": "analyst1",
      "created_at": "2026-10-31T10:05:00Z",
      "updated_at": "2026-10-31T14:30:00Z"
    }
  ]
}
```

---

## 2. Get Cluster Details
- **Method:** `GET`
- **Path:** `/api/v1/investigations/clusters/{cluster_id}`
- **Response:** `200 OK` (Full cluster object including populated `memberships`, `evidence`, and `relationships`)
- **Error:** `404 Not Found` if cluster ID does not exist.

---

## 3. Create Investigation Cluster
- **Method:** `POST`
- **Path:** `/api/v1/investigations/clusters`
- **Request Body:**
```json
{
  "title": "Manual SSH Brute Force Investigation",
  "description": "Analyst-curated investigation grouping for distributed SSH attacks",
  "priority": "HIGH",
  "assigned_to": "analyst1",
  "analyst_notes": "Identified correlation via rare User-Agent signature",
  "initial_entity_ids": [
    {"entity_type": "SESSION", "entity_id": "SESS-1001", "association_reason": "Primary anchor session"}
  ]
}
```
- **Response:** `201 Created`

---

## 4. Update Cluster Lifecycle Status
- **Method:** `PATCH`
- **Path:** `/api/v1/investigations/clusters/{cluster_id}/status`
- **Request Body:**
```json
{
  "target_status": "ACTIVE",
  "notes": "Reviewed and confirmed correlated activity",
  "assigned_to": "analyst2"
}
```
- **Response:** `200 OK`
- **Error:** `400 Bad Request` if state transition is invalid.

---

## 5. Add Cluster Membership
- **Method:** `POST`
- **Path:** `/api/v1/investigations/clusters/{cluster_id}/members`
- **Request Body:**
```json
{
  "entity_type": "SOURCE_PROFILE",
  "entity_id": "PROF-198-51-100-10",
  "association_reason": "Matching source context profile",
  "confidence_score": 0.8
}
```
- **Response:** `201 Created`

---

## 6. Remove Cluster Membership
- **Method:** `DELETE`
- **Path:** `/api/v1/investigations/clusters/{cluster_id}/members/{membership_id}`
- **Response:** `200 OK`

---

## 7. Attach Evidence
- **Method:** `POST`
- **Path:** `/api/v1/investigations/clusters/{cluster_id}/evidence`
- **Request Body:**
```json
{
  "evidence_type": "USER_AGENT",
  "evidence_value": "Mozilla/5.0 (Custom Scanner 1.2)",
  "description": "Distinctive User-Agent string present across all HTTP sessions",
  "relevance_score": 0.85,
  "raw_data": {"header_name": "User-Agent"}
}
```
- **Response:** `201 Created`

---

## 8. Merge Clusters
- **Method:** `POST`
- **Path:** `/api/v1/investigations/clusters/{target_cluster_id}/merge`
- **Request Body:**
```json
{
  "source_cluster_id": "CLUST-202610-02",
  "reason": "Duplicate campaign cluster identified by shared SSH keys"
}
```
- **Response:** `200 OK`

---

## 9. Split Cluster
- **Method:** `POST`
- **Path:** `/api/v1/investigations/clusters/{cluster_id}/split`
- **Request Body:**
```json
{
  "new_cluster_title": "Independent Telnet Probing",
  "reason": "Separating unrelated Telnet scanning from SSH targeted campaign",
  "entity_ids_to_extract": ["SESS-1004", "SESS-1005"]
}
```
- **Response:** `201 Created` (Returns new cluster representation)

---

## 10. Get Unified Investigation Timeline
- **Method:** `GET`
- **Path:** `/api/v1/investigations/clusters/{cluster_id}/timeline`
- **Response:** `200 OK` (Array of chronological timeline entries)

---

## 11. Run Clustering Engine Discovery
- **Method:** `POST`
- **Path:** `/api/v1/investigations/discover`
- **Request Body:**
```json
{
  "lookback_hours": 24,
  "min_confidence": 0.4
}
```
- **Response:** `200 OK` (Summary of evaluated candidates and newly created or updated clusters)

