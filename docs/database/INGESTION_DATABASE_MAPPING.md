# Ingestion Database Mapping Guide

**Document ID:** DB-MAP-001  
**Classification:** Technical Implementation Reference  
**Scope:** SnareSight Phase 3 — Event Pipeline & Database (P13)  
**Status:** IMPLEMENTED  

---

## 1. Field-Level Transformation Mappings

The table below details exact source-to-target field mappings between the Raw Honeypot Telemetry (P11 schema) and the database persistence models implemented in `backend/app/db/models/`.

| Raw Payload JSON Path | Raw Events Column (`raw_events`) | Security Events Column (`security_events`) | Transformation / Validation Rule |
| :--- | :--- | :--- | :--- |
| `$.raw_event_id` (or `$.event_id`) | `raw_event_id` | `raw_event_id` | UUIDv4 format validation; auto-fallback to `event_id` for P09 legacy logs |
| `n/a` (Generated) | *none* | `event_id` | Newly generated UUIDv4 for normalized record |
| `$.timestamp` | `timestamp` | `timestamp` | Strict ISO-8601 UTC parse; max clock skew 300s |
| `$.schema_version` | `schema_version` | *none* | Must match supported versions (`["1.0"]`) |
| `$.source.source_id` | `source_id` | `metadata.source_id` | Validated against `SourceRegistryValidator` |
| `$.source.decoy_id` | `decoy_id` | `target_service` | Mapped to target service (`web_decoy`) |
| `$.data_provenance` | `data_provenance` | `data_provenance` | Preserved verbatim; never modified |
| `$.event_type` | `event_type` | `event_type` | Normalized to generic dot-notation (`web.auth.login`) |
| `$.interaction.method` + `path` | `interaction_data.method` | `action` | Derived (`attempted_login`, `viewed_page`, `probed_path`) |
| `$.interaction.success` / status | `interaction_data` | `outcome` | Derived (`success`, `failure`, `blocked`, `observed`) |
| Computed risk profile | *none* | `severity` | Evaluated against honeypot rule heuristics |
| `$.client.ip` | `client_ip` | `source_ip` | IPv4/IPv6 address validation |
| `$.client.port` | `client_port` | `source_port` | Port boundary check (1 to 65535) |
| `$.session_id` | `session_id` | `session_id` | Alphanumeric validation (3 to 64 chars) |
| SHA-256 Digest | *none* | `event_hash` | Idempotency fingerprint (UNIQUE) |
| `$.interaction` (Sanitized) | `interaction_data` | `metadata` | Password-inspected JSONB object |

---

## 2. Backward Compatibility for Legacy P09 Telemetry

During testing and deployment, the ingestion engine handles differences between initial P09 decoy logs and P11 schema definitions:
1. **Primary ID Field:** If `raw_event_id` is missing but `event_id` is present, `EventProcessor` automatically mirrors `event_id` into `raw_event_id`.
2. **Decoy Identifiers:** P09 utilized decoy identifier `WEB-DECOY-01`, while P11 registered `WEB-001`. The `SourceRegistryValidator` maintains an authorized alias table recognizing both tokens.
3. **Missing Client Ports:** If the raw telemetry omits the TCP client port, the ingestion pipeline safely defaults to `None` without triggering schema validation failure.

