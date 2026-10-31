# Database Archival Specification

**Document ID:** DB-ARCHIVE-001  
**Classification:** Operational Storage Specification  
**Scope:** SnareSight Phase 3 — Event Pipeline & Database (P14)  
**Status:** IMPLEMENTED  

---

## 1. Archival Purpose & Scope

For regulatory compliance and historical threat intelligence analysis, security telemetry exceeding operational database retention can be archived prior to database deletion.

The [`ControlledArchiver`](file:///c:/Projects/SnareSight/backend/app/retention/archiver.py) implements a lightweight, compressed export mechanism:
- Generates gzip-compressed structured JSON Lines (`.jsonl.gz`).
- Computes cryptographic SHA-256 integrity checksums over the exported payload.
- Stores files outside Git-tracked directories (`backend/storage/archives/`).
- Disallows external cloud transfers or unauthenticated access.

---

## 2. Archive Package Structure

Each archive package contains:
- `raw_event_id`: UUID of originating sensor record.
- `schema_version`: Contract version.
- `event_type` and `event_category`.
- `decoy_id`: Originating honeypot asset.
- `observed_at` and `received_at`: Timestamps.
- `sanitized_payload`: Sanitized event payload (strictly zero passwords).
- `provenance`: Originating provenance object.

### Integrity Verification
Upon export completion, the archiver produces an export manifest containing:
```json
{
  "archive_filename": "snaresight_raw_events_20261031T170000Z.jsonl.gz",
  "record_count": 500,
  "sha256_checksum": "a4b7...c901",
  "cutoff_date": "2026-08-01T00:00:00Z",
  "exported_at": "2026-10-31T17:00:00Z"
}
```
Operators can verify archive file integrity at rest using `sha256sum <filename>`.

