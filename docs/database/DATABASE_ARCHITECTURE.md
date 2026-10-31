# SnareSight — Database Architecture & Data Tier Design

**Document ID:** `SNARESIGHT-DB-ARCH-001`  
**Phase:** 3 — Event Pipeline and Database  
**Classification:** Confidential — Internal Cybersecurity Engineering  
**Authority:** Principal Database Architect & Backend Architect  

---

## 1. Architectural Principles

The SnareSight persistence tier is designed to handle high-throughput honeypot telemetry ingestion, provide millisecond-latency queries for SOC dashboard analysts, and maintain referential integrity without persisting dangerous plaintext credentials.

```
+-----------------------------------------------------------------------------+
|                            APPLICATION TIER                                 |
|      FastAPI Backend / Event Ingestion Pipeline / Detection Engine          |
+--------------------------------------+--------------------------------------+
                                       | SQLAlchemy 2.0 ORM (Async / Sync)
                                       v
+-----------------------------------------------------------------------------+
|                            DATABASE BOUNDARY                                |
|                       PostgreSQL 16 (Local Loopback)                        |
|                                                                             |
|  +---------------------+   +---------------------+   +-------------------+  |
|  |     honeypots       |   |    event_sources    |   |  simulation_runs  |  |
|  +----------+----------+   +----------+----------+   +---------+---------+  |
|             |                         |                        |            |
|             +------------+ +----------+                        |            |
|                          | |                                   |            |
|                          v v                                   v            |
|                  +-----------------+                 +-------------------+  |
|                  |   raw_events    |                 |     sessions      |  |
|                  +--------+--------+                 +---------+---------+  |
|                           | (1:1)                              |            |
|                           v                                    |            |
|                  +-----------------+                           |            |
|                  | security_events | <-------------------------+            |
|                  +--------+--------+                                        |
|                           | (N:M via junction)                              |
|                           v                                                 |
|                  +-----------------+                 +-------------------+  |
|                  | alert_evidence  | <-------------- |  security_alerts  |  |
|                  +-----------------+                 +---------+---------+  |
|                                                                | (N:1)      |
|                                                                v            |
|                                                      +-------------------+  |
|                                                      |   attack_chains   |  |
|                                                      +-------------------+  |
+-----------------------------------------------------------------------------+
```

---

## 2. Ingestion & Persistence Separation

1. **Decoupled Ingestion:** Telemetry collection does not write directly to normalized tables. Telemetry is first staged in `raw_events` to preserve evidentiary provenance, then normalized into `security_events`.
2. **Deterministic Foreign Keys:** Every `security_event` maintains an immutable `raw_event_id` foreign key referencing its raw observation record.
3. **Many-to-Many Alert Evidence:** The `alert_evidence` table creates an auditable bridge between high-level detection findings (`security_alerts`) and supporting granular telemetry (`security_events`).
4. **Preservation of Decoy Independence:** Honeypot decoys interact with the platform solely via append-only JSONL files or HTTP ingestion APIs; honeypots never possess database credentials or direct socket connections.

