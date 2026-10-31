# SnareSight — Database Indexing & Query Optimization Strategy

**Document ID:** `SNARESIGHT-DB-INDEX-001`  
**Phase:** 3 — Event Pipeline and Database  
**Classification:** Confidential — Internal Cybersecurity Engineering  
**Authority:** Principal Database Architect & Performance Engineer  

---

## 1. Indexing Principles & SOC Query Patterns

In a deception SOC platform, query performance must balance two competing demands:
1. **High Ingestion Write-Throughput:** Bulk event streaming without excessive index update overhead.
2. **Sub-Second Dashboard Telemetry:** Rapid filtering by time range, source IP, decoy service, and severity.

```
+--------------------------------------------------------------------------+
| High-Priority Dashboard Queries                                          |
| 1. Realtime Event Stream: SELECT ... ORDER BY observed_at DESC LIMIT 50  |
| 2. Source Profiling: SELECT ... WHERE source_address = ?                 |
| 3. Decoy Activity: SELECT ... WHERE decoy_id = ? AND observed_at >= ?    |
| 4. Alert Triage: SELECT ... WHERE severity = 'HIGH' AND status = 'NEW'   |
| 5. JSONB Traversal: SELECT ... WHERE sanitized_metadata @> '{"auth":...}'|
+--------------------------------------------------------------------------+
```

---

## 2. Comprehensive Index Specifications

### 2.1 Indexes on `security_events`
| Index Name | Target Column(s) | Index Type | Target Query Optimization |
| :--- | :--- | :--- | :--- |
| `idx_sec_events_observed_at` | `(observed_at DESC)` | B-Tree | Chronological live event feeds and time-window sliding detections. |
| `idx_sec_events_source_time` | `(source_address, observed_at DESC)` | Composite B-Tree | Source IP actor timeline reconstruction and brute-force tracking. |
| `idx_sec_events_decoy_time` | `(decoy_id, observed_at DESC)` | Composite B-Tree | Decoy-specific activity filtering in SOC UI. |
| `idx_sec_events_session_id` | `(session_id)` | B-Tree | Correlating multi-stage interactions within a single visitor session. |
| `idx_sec_events_dedup_ref` | `(deduplication_reference)` | **UNIQUE B-Tree** | Enforces pipeline idempotency (`ON CONFLICT DO NOTHING`). |
| `idx_sec_events_metadata_gin`| `(sanitized_metadata)` | **GIN (`jsonb_path_ops`)** | Accelerated JSONB sub-key lookups (`username_fingerprint`, HTTP paths). |

### 2.2 Indexes on `raw_events`
| Index Name | Target Column(s) | Index Type | Target Query Optimization |
| :--- | :--- | :--- | :--- |
| `idx_raw_events_raw_id` | `(raw_event_id)` | **UNIQUE B-Tree** | Instant primary key lookup from normalized event foreign key. |
| `idx_raw_events_observed_at` | `(observed_at DESC)` | B-Tree | Forensic raw log range queries and audit verifications. |
| `idx_raw_events_session_id` | `(session_id)` | B-Tree | Raw evidentiary extraction for forensic export. |

### 2.3 Indexes on `alerts`
| Index Name | Target Column(s) | Index Type | Target Query Optimization |
| :--- | :--- | :--- | :--- |
| `idx_alerts_severity_status` | `(severity, assessment_status)` | Composite B-Tree | SOC triage queue filtering (`CRITICAL` & `NEW` alerts). |
| `idx_alerts_generated_at` | `(generated_at DESC)` | B-Tree | Chronological alert stream on SOC main overview. |
| `idx_alerts_source_address` | `(source_address)` | B-Tree | Top attacking sources aggregation. |
| `idx_alerts_decoy_id` | `(decoy_id)` | B-Tree | Decoy targeting risk aggregation. |

### 2.4 Indexes on `sessions`
| Index Name | Target Column(s) | Index Type | Target Query Optimization |
| :--- | :--- | :--- | :--- |
| `idx_sessions_started_at` | `(started_at DESC)` | B-Tree | Recent visitor session discovery. |
| `idx_sessions_source_addr` | `(source_address)` | B-Tree | Grouping all sessions originating from a specific IP. |

---

## 3. Maintenance & Future Partitioning Roadmap

1. **Index Bloat Prevention:** Autovacuum settings tuned for high-write tables (`autovacuum_vacuum_scale_factor = 0.05`).
2. **Table Partitioning Roadmap:** When telemetry volume exceeds 1,000,000 events/month, `security_events` will be partitioned using PostgreSQL native declarative range partitioning on `observed_at`:
   ```sql
   -- Future Partitioning Pattern (Phase 4):
   CREATE TABLE security_events_p2026_10 PARTITION OF security_events
       FOR VALUES FROM ('2026-10-01 00:00:00+00') TO ('2026-11-01 00:00:00+00');
   ```

