# SnareSight: Sensor Operational Health & Pipeline Freshness

**Phase:** 6 — Security Operations Center (SOC) Dashboard  
**Task:** P30 / 40  
**Status:** `COMPLETED AND VERIFIED`

---

## 1. Sensor Health Classification

The sensor health endpoint (`GET /api/v1/analytics/sensors`) audits all configured honeypots and assigns operational health states based on real event telemetry timestamps:

- **ONLINE**: Decoy sensor has ingested normalized events within the past **10 minutes**.
- **STALE**: Decoy sensor is active in the database, but has recorded no events in the past 10 minutes to **1 hour**.
- **INACTIVE**: Decoy sensor has recorded no telemetry for over **1 hour**, or is administratively disabled.

For each sensor, the system reports:
- Decoy Identifier (`decoy_id`)
- Human-Readable Name
- Supported Network Protocol
- Environment / Deployment Zone
- Total Events Ingested in Current Window
- Last Observed Event Timestamp

---

## 2. Ingestion Pipeline Metrics

The pipeline health endpoint (`GET /api/v1/analytics/pipeline-health`) tracks the end-to-end performance and deduplication fidelity of the ingestion engine:

- **Events Ingested**: Total raw events received across all honeypots.
- **Events Deduplicated**: Events suppressed by deduplication algorithms (saving database bandwidth and preventing alert storms).
- **Throughput Rate**: Computed event processing rate (events per second/minute).
- **Active SSE Streams**: Number of concurrent real-time analysts and monitoring clients listening to the event bus.
- **Pipeline Status**: `HEALTHY` when event flow is fresh, or `STALE` if ingestion latency exceeds threshold parameters.

