# SnareSight: Complete API Reference Specification

**Document Version:** 1.0.0  
**Phase:** 8 — Testing, Demonstration & Project Handover  
**Date:** October 2026  
**Base URL:** `http://127.0.0.1:8000/api/v1`  
**Authentication Schemes:**
* **Bearer JWT:** `Authorization: Bearer <TOKEN>` (Analyst / Admin users)
* **Sensor Key:** `X-Sensor-Key: <SENSOR_TOKEN>` (Honeypot telemetry ingestion and heartbeats)

---

## 1. Authentication & User Management (`/api/v1/auth`)

### 1.1 Login & Obtain JWT Token
* **Method & Path:** `POST /api/v1/auth/login`
* **Access:** Public (Rate-limited: 5 attempts/minute)
* **Request Body (JSON):**
  ```json
  {
    "username": "analyst@snaresight.local",
    "password": "SecurePassword123!"
  }
  ```
* **Responses:**
  * `200 OK`:
    ```json
    {
      "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "token_type": "bearer",
      "expires_in": 28800,
      "user": {
        "id": "usr-101",
        "username": "analyst@snaresight.local",
        "role": "analyst"
      }
    }
    ```
  * `401 Unauthorized`: Invalid credentials or inactive account.

### 1.2 Get Current User Profile
* **Method & Path:** `GET /api/v1/auth/me`
* **Access:** Bearer JWT (Any authenticated role)
* **Response:** `200 OK` with user details and permissions.

### 1.3 User Administration
* **`GET /api/v1/auth/users`**: List all system users (Admin role required).
* **`POST /api/v1/auth/users`**: Provision a new user account with assigned role (`admin`, `analyst`, `auditor`).
* **`POST /api/v1/auth/change-password`**: Securely update current user password.
* **`POST /api/v1/auth/logout`**: Invalidate active session and emit audit logout event.

---

## 2. Sensor Telemetry Ingestion & Health (`/api/v1/ingestion`, `/api/v1/sensors`)

### 2.1 Batch Event Ingestion
* **Method & Path:** `POST /api/v1/ingestion/events/batch`
* **Access:** `X-Sensor-Key` header or Bearer JWT
* **Request Body (JSON):**
  ```json
  {
    "sensor_id": "sensor-web-01",
    "batch_size": 1,
    "events": [
      {
        "event_id": "evt-uuid-001",
        "timestamp": "2026-10-31T20:15:00Z",
        "source_ip": "192.168.56.105",
        "source_port": 49210,
        "destination_port": 8080,
        "protocol": "TCP",
        "honeypot_type": "web_login",
        "event_category": "AUTHENTICATION",
        "raw_payload": "username=admin&password=REDACTED",
        "metadata": {
          "http_method": "POST",
          "url_path": "/api/login",
          "user_agent": "Mozilla/5.0 (Hydra-Scanner)"
        }
      }
    ]
  }
  ```
* **Responses:**
  * `201 Created`: `{"status": "INGESTED", "count": 1, "processed_ids": ["evt-uuid-001"]}`
  * `422 Unprocessable Entity`: Invalid schema or missing required provenance fields.

### 2.2 Sensor Heartbeat & Health Check
* **Method & Path:** `POST /api/v1/sensors/heartbeat`
* **Access:** `X-Sensor-Key`
* **Request Body:**
  ```json
  {
    "sensor_id": "sensor-web-01",
    "status": "HEALTHY",
    "cpu_usage_pct": 4.2,
    "memory_usage_mb": 185.0,
    "queue_depth": 0
  }
  ```
* **Response:** `200 OK` with heartbeat acknowledgment.

### 2.3 Sensor Management Endpoints
* **`GET /api/v1/sensors`**: List all registered decoy sensors with current status (`HEALTHY`, `DEGRADED`, `OFFLINE`).
* **`POST /api/v1/sensors`**: Register a new honeypot decoy sensor and issue access credentials.
* **`POST /api/v1/sensors/{sensor_id}/credentials/rotate`**: Rotate `X-Sensor-Key` token.
* **`POST /api/v1/sensors/evaluate-health`**: Trigger instantaneous sweep of sensor heartbeat timestamps.

---

## 3. Alerts & Triage Management (`/api/v1/alerts`)

### 3.1 List & Filter Alerts
* **Method & Path:** `GET /api/v1/alerts`
* **Access:** Bearer JWT (Analyst or Admin)
* **Query Parameters:**
  * `status`: Optional filter (`NEW`, `TRIAGED`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`).
  * `severity_min`: Integer 0–100.
  * `limit`: Page size (default: 50).
  * `offset`: Pagination offset (default: 0).
* **Response `200 OK`:** Array of alert objects containing title, rule ID, source IP, severity, and confidence.

### 3.2 Alert Triage Decision
* **Method & Path:** `POST /api/v1/alerts/{alert_id}/triage-decision`
* **Request Body:**
  ```json
  {
    "status": "INVESTIGATING",
    "rationale": "High repetition brute force targeting SSH and Web decoys simultaneously.",
    "assigned_analyst": "analyst@snaresight.local"
  }
  ```
* **Response `200 OK`**: Updated alert entity with audit log record.

### 3.3 Alert Operations
* **`POST /api/v1/alerts/{alert_id}/acknowledge`**: Analyst acknowledges awareness.
* **`POST /api/v1/alerts/{alert_id}/escalate`**: Escalate alert to higher severity or trigger incident case creation.
* **`GET /api/v1/alerts/{alert_id}/evidence`**: Returns raw telemetry events linked to the alert.
* **`GET /api/v1/alerts/{alert_id}/history`**: Complete state transition audit trail.

---

## 4. Sessions, Correlation & Attack Chains (`/api/v1/sessions`, `/api/v1/sequences`, `/api/v1/investigations`)

### 4.1 Correlated Sessions
* **`GET /api/v1/sessions`**: Query intruder sessions grouped by source IP and temporal window.
* **`GET /api/v1/sessions/{session_id}`**: Detailed session overview with event counts, duration, and target decoys.
* **`GET /api/v1/sessions/{session_id}/timeline`**: Chronological order of events within the session.

### 4.2 Attack Chain Sequences
* **`GET /api/v1/sequences`**: Query reconstructed multi-stage attack chains.
* **`GET /api/v1/sequences/{sequence_id}`**: Directed acyclic graph representation of attack phases (nodes, edges, progression).
* **`GET /api/v1/sequences/{sequence_id}/mitre`**: Aggregate MITRE ATT&CK techniques observed in the sequence.

### 4.3 Incident Investigations & Clusters
* **`GET /api/v1/investigations`**: List active multi-source investigation clusters.
* **`POST /api/v1/investigations/cluster`**: Programmatically group correlated sessions into an investigative case.
* **`POST /api/v1/investigations/{cluster_id}/merge`**: Merge two related clusters into a single unified incident narrative.

---

## 5. MITRE ATT&CK Framework Integration (`/api/v1/attack`, `/api/v1/mitre`)

### 5.1 ATT&CK Matrix & Coverage
* **`GET /api/v1/attack/matrix`**: Hierarchical MITRE Enterprise matrix populated with observed detection counts.
* **`GET /api/v1/attack/coverage`**: Summary of covered Tactics (Reconnaissance, Credential Access, Discovery, Execution).
* **`GET /api/v1/attack/techniques/{technique_id}`**: Technique specification, mapped detection rules, and observed frequencies.
* **`GET /api/v1/attack/techniques/{technique_id}/evidence`**: Forensic events verifying the technique.

### 5.2 Mapping Review & Validation
* **`POST /api/v1/attack/mappings/{mapping_id}/review`**: Analyst reviews and validates or disputes an automated rule-to-technique mapping.
* **`POST /api/v1/attack/mappings/{mapping_id}/approve`**: Formal approval of an ATT&CK mapping association.

---

## 6. Threat Actor Profiling & Campaigns (`/api/v1/source-profiles`, `/api/v1/campaigns`)

### 6.1 Source IP Profiles
* **`GET /api/v1/source-profiles`**: Paginated directory of tracked source IPs, calculated threat scores, and targeted decoys.
* **`GET /api/v1/source-profiles/{profile_id}`**: Detailed behavioral profile: first seen, last seen, total sessions, observed tools.
* **`GET /api/v1/source-profiles/{profile_id}/similar`**: Heuristic clustering identifying related IP addresses with matching behavioral fingerprints.

### 6.2 Campaign Intelligence
* **`GET /api/v1/campaigns`**: Multi-IP coordinated campaign clusters.
* **`GET /api/v1/campaigns/{campaign_id}`**: Campaign timeline, participating IPs, and targeted decoy services.

---

## 7. Defensive Response & Incident Cases (`/api/v1/response`)

### 7.1 Incident Case Management
* **`GET /api/v1/response/cases`**: Query incident cases with status, priority, and assigned analyst.
* **`POST /api/v1/response/cases`**: Create a new formal incident case from an alert or session.
* **`PATCH /api/v1/response/cases/{case_id}`**: Update case status (`OPEN`, `INVESTIGATING`, `CONTAINED`, `CLOSED`).
* **`POST /api/v1/response/cases/{case_id}/holds`**: Apply a Legal/Forensic Retention Hold, protecting evidence from automated pruning.

### 7.2 Containment Actions & Firewall Scripts
* **`POST /api/v1/response/cases/{case_id}/actions`**: Generate containment artifacts:
  ```json
  {
    "action_type": "FIREWALL_BLOCK",
    "target_ip": "192.168.56.105",
    "format": "iptables",
    "reason": "Brute force attack on SSH honeypot"
  }
  ```
* **Response `201 Created`**:
  ```json
  {
    "action_id": "act-502",
    "command": "sudo iptables -A INPUT -s 192.168.56.105 -j DROP",
    "status": "RECOMMENDED"
  }
  ```

---

## 8. SOC Analytics & Reporting (`/api/v1/analytics`, `/api/v1/reports`)

### 8.1 Executive & Operational Metrics
* **`GET /api/v1/analytics/overview`**: Global SOC metrics: total alerts, MTTD, MTTR, active sessions.
* **`GET /api/v1/analytics/events/timeline`**: Event ingestion rate over time (1h, 24h, 7d intervals).
* **`GET /api/v1/analytics/pipeline-health`**: Telemetry pipeline lag, ingestion throughput, and dropped packet count.

### 8.2 Security Report Generation
* **`POST /api/v1/reports/generate`**: Generate PDF/Markdown/JSON executive security reports:
  ```json
  {
    "report_type": "EXECUTIVE_SUMMARY",
    "time_range": "LAST_30_DAYS",
    "format": "JSON"
  }
  ```
* **`GET /api/v1/reports/{report_id}/download`**: Retrieve compiled report file.

---

## 9. Operational Resilience & Self-Healing (`/api/v1/resilience`)

* **`GET /api/v1/resilience/health/live`**: Kubernetes-compatible liveness probe (`{"status": "UP"}`).
* **`GET /api/v1/resilience/health/ready`**: Readiness probe checking database connectivity and schema integrity.
* **`GET /api/v1/resilience/health/diagnostics`**: Deep internal diagnostics (DB query latency, queue depth, disk usage).
* **`POST /api/v1/resilience/backups`**: Trigger instantaneous database snapshot backup.
* **`POST /api/v1/resilience/backups/{backup_id}/restore-test`**: Perform isolated, dry-run schema and checksum validation without touching production data.

---

## 10. Demonstration Lab Harness (`/api/v1/demo`)

* **`GET /api/v1/demo/scenarios`**: List the 6 synthetic attack scenarios (SCN-A through SCN-F).
* **`POST /api/v1/demo/scenarios/run`**: Execute a deterministic synthetic attack scenario:
  ```json
  {"scenario_id": "SCN-A"}
  ```
* **`GET /api/v1/demo/evaluation`**: Returns detection quality metrics (Precision, Recall, F1-Score) across synthetic runs.
* **`POST /api/v1/demo/cleanup`**: Purges synthetic demonstration data while strictly respecting `retention_hold = True`.

---

## 11. Real-Time Streaming (`/api/v1/stream`)

* **`GET /api/v1/stream/events`**: Unidirectional Server-Sent Events (SSE) stream.
* **Protocol:** `text/event-stream`
* **Event Types Broadcast:**
  * `alert_created`: Emitted when a detection rule triggers a new alert.
  * `sensor_status`: Emitted when a sensor changes health state or misses heartbeats.
  * `pipeline_metric`: Periodic throughput and latency telemetry.

