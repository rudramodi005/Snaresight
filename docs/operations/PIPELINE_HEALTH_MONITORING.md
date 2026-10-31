# SnareSight Pipeline Health Monitoring

## 1. Operational Endpoints

SnareSight provides dedicated operational and diagnostic endpoints following Kubernetes and cloud-native observability standards:

### 1. Liveness Probe (`GET /api/v1/health/live`)
- **Purpose**: Verify that the SnareSight backend process is running and its event loop is unblocked.
- **Payload**:
  ```json
  {
    "status": "UP",
    "timestamp": "2026-10-31T12:00:00.000000+00:00",
    "uptime_seconds": 3600.5
  }
  ```
- **HTTP Code**: 200 OK.

### 2. Readiness Probe (`GET /api/v1/health/ready`)
- **Purpose**: Verify that downstream persistent dependencies (PostgreSQL database connectivity) are operational before routing traffic.
- **Probe Operation**: Executes `SELECT 1` against the database session.
- **Payload**:
  ```json
  {
    "status": "READY",
    "database": "UP",
    "timestamp": "2026-10-31T12:00:00.000000+00:00"
  }
  ```
- **HTTP Codes**: 200 OK (if healthy), 503 Service Unavailable (if database check fails).

### 3. Pipeline Health & Metrics (`GET /api/v1/health/pipeline`)
- **Purpose**: Return operational metrics reflecting ingestion rate, deduplication counts, normalization statistics, and streaming metrics.
- **Payload**:
  ```json
  {
    "status": "HEALTHY",
    "metrics": {
      "ingestion_total": 1250,
      "ingestion_rejected": 15,
      "duplicates_detected": 40,
      "events_normalized": 1195,
      "events_persisted": 1195,
      "stream_events_published": 1195,
      "stream_active_subscribers": 3,
      "stream_queue_drops": 0
    },
    "timestamp": "2026-10-31T12:00:00.000000+00:00"
  }
  ```

### 4. Component-Level Health (`GET /api/v1/health/components`)
- **Purpose**: Granular operational status breakdown for each architectural subsystem:
  - Database connectivity
  - Event ingestion engine
  - Deduplication engine
  - Streaming broker
  - Registered honeypot decoys (queried from `HoneypotModel`)
  - Retention manager
  - Future modules (Rule engine, alert manager, SOC dashboard marked `NOT_CONFIGURED`).

