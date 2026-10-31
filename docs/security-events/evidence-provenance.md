# Evidence Provenance and Pipeline Integrity

## Forensic Traceability
Every normalized event in SnareSight preserves end-to-end provenance back to the original sensor capture.

---

## 1. Provenance Attributes

| Field Name | Description | Forensic Role |
|:---|:---|:---|
| `raw_event_id` | Foreign key to `raw_events.raw_event_id` | Links directly to immutable raw capture payload |
| `deduplication_reference` | SHA-256 hash of immutable canonical fields | Guarantees idempotency and prevents replay spoofing |
| `schema_version` | Ingestion schema definition version (e.g. `1.0`) | Schema evolution tracking |
| `received_at` | Server clock timestamp when payload hit gateway | Latency and pipeline delay measurement |
| `normalized_at` | Timestamp when normalization completed | Processing audit record |
| `validation_status` | Status from schema validation engine (`VALID`) | Input validation proof |

---

## 2. Ingestion Pipeline Audit Trail

The event detail view reconstructs each pipeline stage:
1. **`INGESTION`**: Packet receipt via authenticated API or offline JSONL importer.
2. **`VALIDATION`**: Enforcement of type bounds, enum constraints, and schema conformance.
3. **`NORMALIZATION`**: Canonical mapping of source protocols, target ports, and action verbs.
4. **`DEDUPLICATION`**: Cryptographic uniqueness check against persistent database records.
5. **`DETECTION`**: Evaluation by rule engine, recording any generated alert IDs and severity assessments.

