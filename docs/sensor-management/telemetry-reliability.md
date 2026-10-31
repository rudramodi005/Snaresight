# Telemetry Delivery & Ingestion Reliability

## 1. Reliability Architecture

Honeypot telemetry delivery must be guaranteed without allowing honeypot sensors to connect directly to persistent application databases. 

In SnareSight:
- Sensors write events locally to bounded disk buffers (`data/events.jsonl`).
- Forwarder agents stream batches via authenticated HTTP (`POST /api/v1/ingestion/events/batch`).
- Events are validated, deduplicated, and persisted through transaction boundaries in PostgreSQL.

---

## 2. Telemetry Reliability Metrics

The platform records windowed metrics in `sensor_telemetry_metrics` tracking:
- **`events_received`**: Total count of telemetry records presented to the gateway.
- **`events_validated`**: Events satisfying schema constraints, timestamp bounds, and sensitive data checks.
- **`events_rejected`**: Events failing schema validation, unauthorized fields, or unparseable formats.
- **`events_persisted`**: Events successfully written to `raw_events` and `security_events`.
- **`duplicate_events`**: Events identified as duplicates via deterministic SHA-256 fingerprinting.
- **`average_latency_ms`**: Ingestion turnaround time from receipt to commit.

$$\text{Ingestion Reliability Rate} = \frac{\text{events\_persisted}}{\text{events\_received}} \times 100\%$$

---

## 3. Bounded Buffering & Failure Semantics

1. **Bounded Buffers:** Local honeypot storage is bounded (e.g., maximum 50MB or 100,000 events with log rotation).
2. **Exponential Backoff:** If the central API gateway is unreachable, forwarders retry with jittered exponential backoff:
   $$T_{\text{wait}} = \min(60, 2^{\text{attempt}} \pm \text{jitter})$$
3. **Idempotency Guarantee:** If a network timeout occurs during batch transmission, resending the batch produces **zero duplicate records** in PostgreSQL because every event fingerprint is unique and indexed.
4. **Error Logging:** Delivery failures write to `operational_alerts` under category `TELEMETRY_INGESTION_FAILURE` rather than silently dropping data.

