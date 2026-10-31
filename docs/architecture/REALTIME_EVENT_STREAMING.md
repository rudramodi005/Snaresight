# SnareSight Real-Time Event Streaming Architecture

## 1. Overview & Architectural Principles

SnareSight's real-time event streaming subsystem provides low-latency, read-only event telemetry dissemination to security analysts, Security Operations Center (SOC) dashboards, and automated incident responders.

```
       +-------------------------------------------------------+
       |             Honeypot Decoys & Collectors              |
       +-------------------------------------------------------+
                                   | HTTP POST /ingest
                                   v
       +-------------------------------------------------------+
       |             Event Ingestion & Validation              |
       |  (Schema Validation, Normalization, Deduplication)    |
       +-------------------------------------------------------+
                                   |
                                   v
       +-------------------------------------------------------+
       |             PostgreSQL Persistent Storage             |
       |      (COMMIT TRANSACTION: RawEvent & SecurityEvent)   |
       +-------------------------------------------------------+
                                   |
                   Strictly Post-Commit Notification
                                   |
                                   v
       +-------------------------------------------------------+
       |              EventPublisher (Broadcast)               |
       +-------------------------------------------------------+
                                   |
                 Filtering & Sanitization per Subscriber
                                   |
                                   v
       +-------------------------------------------------------+
       |          StreamManager & Client Subscriptions         |
       |          (Bounded Queues, Connection Limiter)         |
       +-------------------------------------------------------+
                                   |
                          text/event-stream
                                   v
       +-------------------------------------------------------+
       |           Connected SOC Analysts / Dashboard          |
       +-------------------------------------------------------+
```

### Core Invariants

1. **Transactional Integrity Over Stream Immediacy**:
   - Streaming is strictly downstream of database persistence.
   - An event is **never** broadcast to the streaming bus until its PostgreSQL transaction has committed (`db.commit()`).
   - If a database commit fails, no SSE notification is ever dispatched.
   - If stream notification delivery fails (e.g., disconnected client or full subscriber queue), the database transaction is **never rolled back**.

2. **Zero Password Persistence Invariant**:
   - Telemetry emitted to streams is scrubbed by `EventPublisher.publish_persisted_event()`.
   - Credential fields (`password`, `secret_key`, authorization tokens) are permanently suppressed.

3. **Stateless Reconnection via Storage**:
   - Memory buffers are ephemeral and bounded.
   - Historical replays are served directly by querying `SecurityEventModel` via monotonic cursors (`observed_at:event_id`), completely removing dependency on volatile message caches.

4. **Resource Boundedness**:
   - Hard limits on global concurrent connections (50), per-user concurrent connections (5), and subscriber queue depth (100).
   - Slow or stalling consumers are evicted to protect server responsiveness.

