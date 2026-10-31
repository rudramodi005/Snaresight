# Event Deduplication and Idempotency Specification

**Document ID:** DB-DEDUP-002  
**Classification:** Technical Security Design Spec  
**Scope:** SnareSight Phase 3 — Event Pipeline & Database (P14)  
**Status:** IMPLEMENTED & VERIFIED  

---

## 1. Layered Deduplication Strategy

SnareSight protects the operational event pipeline from retransmissions, network retries, and duplicate file imports using a **3-Layer Deduplication Model**:

| Layer | Identification Mechanism | Description | Scope |
| :--- | :--- | :--- | :--- |
| **Layer 1** | Stable Event Identifier | Source-assigned `raw_event_id` (UUIDv4) | Global unique event identity |
| **Layer 2** | Source-Scoped ID | `source_id:decoy_id:raw_event_id` | Scopes identity to registered collector & decoy |
| **Layer 3** | Deterministic Fingerprint | SHA-256 hash over immutable canonical attributes | Content and payload invariance |

---

## 2. Distinction of Duplicate Categories

The engine explicitly distinguishes between five duplicate scenarios:

### A. Exact Duplicate
- **Definition:** An event with an identical source-scoped ID and identical immutable payload.
- **Action:** Return `status: DUPLICATE` with diagnostic `DUPLICATE_EVENT_DETECTED`. Zero database writes occur (`TEST DEDUP-002`).

### B. Identifier Collision
- **Definition:** An incoming event possesses an identical `raw_event_id` to an existing stored record, but its content, path, or payload differs materially.
- **Action:** Flagged as a security/integrity anomaly (`status: REJECTED`, `rejection_category: identifier_collision`). The existing database row is protected and never overwritten (`TEST DEDUP-003`).

### C. Similar Observation
- **Definition:** Two interactions from an attacker submitting the identical password guess or HTTP request, but occurring at different timestamps or under different sessions.
- **Action:** Preserved as two distinct events with unique event IDs and separate database rows (`TEST DEDUP-004`). Content similarity alone is never used to drop legitimate interactions.

### D. Retransmitted Batch
- **Definition:** An entire batch of previously ingested events is re-submitted by a collector after a network reconnect.
- **Action:** Each item in the batch evaluates as `DUPLICATE`. The batch endpoint returns HTTP 200 OK with `accepted_count: 0, duplicate_count: N`, leaving existing database rows unchanged (`TEST DEDUP-005`).

### E. Duplicate Raw Import
- **Definition:** An operator or script imports the same JSONL audit log file multiple times.
- **Action:** The file importer parses each line, identifies already processed fingerprints, and updates metrics without duplicate row insertion.

---

## 3. Database Constraints as Final Safeguard

Application-level deduplication is backed by database constraints:
- `security_events.deduplication_reference` has a `UNIQUE` index constraint (`TEST DEDUP-007`).
- `raw_events.raw_event_id` has a `UNIQUE` index constraint.
Even under concurrent multi-threaded execution, race conditions cannot produce duplicate records.

