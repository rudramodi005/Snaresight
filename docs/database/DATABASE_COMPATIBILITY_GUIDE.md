# SnareSight — Future PostgreSQL Database Compatibility Guide

**Document ID:** `SNARESIGHT-PG-GUIDE-001`  
**Classification:** Confidential — Internal Cybersecurity Engineering  
**Authority:** Principal Database Architect & Data Systems Specialist  

---

## 1. Architectural Scope & Boundary

This document outlines the relational mapping and architectural compatibility design for the upcoming **Phase 3, Task P12 (Configure PostgreSQL and Database Migrations)**.

> **STRICT EXECUTION LIMITATION:** This guide serves as an architectural design contract. No PostgreSQL instances shall be started, no tables created, and no Alembic migrations executed during Task P11.

---

## 2. Relational Mapping Strategy

To achieve high-throughput ingestion (>1,000 events/sec) while supporting flexible honeypot expansions, SnareSight adopts a **Hybrid Relational-Document Pattern**:
- **Structured Relational Columns:** High-cardinality indexing fields, foreign keys, timestamps, and detection query filters.
- **Controlled JSONB Columns:** Service-specific interaction details, dynamic evidence conditions, and inert payload parameters.

```
+--------------------------------------------------------------------------+
|                        Table: normalized_events                          |
+--------------------------------------------------------------------------+
| event_id            | UUID (PK)                | Indexed (B-Tree)        |
| raw_event_id        | UUID (FK -> raw_events)  | Indexed (B-Tree)        |
| observed_at         | TIMESTAMPTZ              | Partition Key & B-Tree  |
| event_type          | VARCHAR(32)              | Indexed (B-Tree)        |
| event_category      | VARCHAR(32)              | Indexed (B-Tree)        |
| outcome             | VARCHAR(16)              | Indexed (B-Tree)        |
| source_address      | INET / VARCHAR(45)       | Indexed (B-Tree)        |
| decoy_id            | VARCHAR(32)              | Indexed (B-Tree)        |
| session_id          | VARCHAR(64)              | Indexed (B-Tree)        |
| deduplication_hash  | CHAR(64)                 | UNIQUE Index (B-Tree)   |
| details             | JSONB                    | Indexed (GIN)           |
+--------------------------------------------------------------------------+
```

---

## 3. Data Storage Placement Breakdown

| Data Group | Recommended Storage Mechanism | Technical & Performance Rationale |
| :--- | :--- | :--- |
| **Identifiers** (`event_id`, `session_id`, `decoy_id`) | Native `UUID` and `VARCHAR(64)` columns | Fast primary key indexing and high-performance joins. |
| **Timestamps** (`observed_at`, `normalized_at`) | Native `TIMESTAMPTZ` (UTC) | Guarantees timezone-aware temporal ordering and range partitioning. |
| **Classification** (`category`, `action`, `outcome`) | Constrained `VARCHAR` / `ENUM` | Efficient query filtering by detection rules and dashboard aggregation. |
| **Network Endpoints** (`source_address`, `target_port`) | Native `INET` / `INTEGER` | Enables subnet CIDR queries (`<<=`) and port-based analytics. |
| **Service Details** (`details.auth`, `details.http`) | Native `JSONB` | Supports decoy-specific variations (Web vs SSH) without schema migrations. |
| **Detection Evidence** (`triggering_conditions`) | Native `JSONB` | Flexible condition storage across heterogeneous detection rules. |
| **Attack Chains & Cases** (`attack_chains`, `cases`) | Separate Relational Tables | Normalizes many-to-one workflow relationships. |
| **Alert-Event Links** (`alert_events_map`) | Dedicated Junction Table | Clean Many-to-Many association enabling fast evidence retrieval. |
| **Plaintext Passwords & Tokens** | **EXCLUDED ENTIRELY** | Zero storage; strictly prevented by schema validation. |

---

## 4. Key Relational Entities (Target P12 Schema)

### Entity 1: `raw_events`
- `raw_event_id`: UUID, PRIMARY KEY.
- `schema_version`: VARCHAR(8), NOT NULL.
- `decoy_id`: VARCHAR(32), NOT NULL.
- `observed_at`: TIMESTAMPTZ, NOT NULL.
- `received_at`: TIMESTAMPTZ, NOT NULL.
- `source_address`: VARCHAR(45), NOT NULL.
- `session_id`: VARCHAR(64), NOT NULL.
- `raw_payload`: JSONB, NOT NULL (sanitized raw event object).

### Entity 2: `normalized_events`
- `event_id`: UUID, PRIMARY KEY.
- `raw_event_id`: UUID, FOREIGN KEY REFERENCES `raw_events(raw_event_id)` ON DELETE RESTRICT.
- `observed_at`: TIMESTAMPTZ, NOT NULL.
- `normalized_at`: TIMESTAMPTZ, NOT NULL.
- `event_category`: VARCHAR(32), NOT NULL.
- `event_type`: VARCHAR(32), NOT NULL.
- `outcome`: VARCHAR(16), NOT NULL.
- `source_address`: VARCHAR(45), NOT NULL.
- `decoy_id`: VARCHAR(32), NOT NULL.
- `session_id`: VARCHAR(64), NOT NULL.
- `deduplication_reference`: CHAR(64), UNIQUE NOT NULL.
- `details`: JSONB, NOT NULL.

### Entity 3: `security_alerts`
- `alert_id`: UUID, PRIMARY KEY.
- `alert_type`: VARCHAR(64), NOT NULL.
- `title`: VARCHAR(128), NOT NULL.
- `severity`: VARCHAR(16), NOT NULL (CHECK IN: INFO, LOW, MEDIUM, HIGH, CRITICAL).
- `confidence`: SMALLINT, NOT NULL (CHECK: 0-100).
- `assessment_status`: VARCHAR(32), NOT NULL DEFAULT 'NEW'.
- `evidence_strength`: VARCHAR(32), NOT NULL.
- `source_address`: VARCHAR(45), NOT NULL.
- `decoy_id`: VARCHAR(32), NOT NULL.
- `first_observed_at`: TIMESTAMPTZ, NOT NULL.
- `last_observed_at`: TIMESTAMPTZ, NOT NULL.
- `generated_at`: TIMESTAMPTZ, NOT NULL.
- `mitre_technique_id`: VARCHAR(16), NULLABLE.
- `mitre_tactic_id`: VARCHAR(16), NULLABLE.
- `attack_chain_id`: UUID, NULLABLE REFERENCES `attack_chains(attack_chain_id)`.
- `evidence`: JSONB, NOT NULL.
- `recommendations`: JSONB, NOT NULL.

### Entity 4: `alert_events_map` (Junction Table)
- `alert_id`: UUID, FOREIGN KEY REFERENCES `security_alerts(alert_id)` ON DELETE CASCADE.
- `event_id`: UUID, FOREIGN KEY REFERENCES `normalized_events(event_id)` ON DELETE CASCADE.
- PRIMARY KEY (`alert_id`, `event_id`).

---

## 5. Idempotency & Ingestion Upsert

To guarantee that duplicate events submitted by collectors or network retransmissions do not corrupt counts:
- `deduplication_reference` (computed as `SHA-256(decoy_id + observed_at + session_id + payload_hash)`) carries a `UNIQUE` constraint.
- The future P13 ingestion pipeline will execute an idempotent upsert:
  ```sql
  INSERT INTO normalized_events (...)
  VALUES (...)
  ON CONFLICT (deduplication_reference) DO NOTHING;
  ```

---

## 6. Partitioning & Retention Recommendations

1. **Range Partitioning by Month:** `normalized_events` should be partitioned by range on `observed_at` (e.g. `normalized_events_2026_10`), allowing old monthly partitions to be detached and archived atomically.
2. **Indexing Strategy:**
   - B-Tree on `(observed_at DESC)` for chronological dashboard streaming.
   - B-Tree on `(source_address, observed_at DESC)` for source IP activity profiling.
   - GIN index on `details` using `jsonb_path_ops` for fast attribute queries.

