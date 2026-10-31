# Ingestion Idempotency & Deduplication

**Document ID:** DB-DEDUP-001  
**Classification:** Technical Security Design Spec  
**Scope:** SnareSight Phase 3 — Event Pipeline & Database (P13)  
**Status:** IMPLEMENTED  

---

## 1. Idempotency Problem Statement

In distributed network monitoring and honeypot telemetry ingestion, event resubmissions frequently occur due to:
- Network disconnects prompting sensor collector retries.
- Offline file re-imports (e.g., re-running the JSONL file importer against historical logs).
- Multiple collectors forwarding duplicated segments of network logs.

Without strict idempotency, duplicate submissions create artificial spikes in attack volume, poison threat scoring metrics, and degrade analyst efficiency.

---

## 2. SHA-256 Fingerprint Computation Algorithm

The `EventDeduplicator` computes a deterministic SHA-256 fingerprint across seven canonical event attributes:

$$\text{Event Fingerprint} = \text{SHA-256}\left(\text{source\_id} \parallel \text{decoy\_id} \parallel \text{timestamp} \parallel \text{session\_id} \parallel \text{event\_type} \parallel \text{client\_ip} \parallel \text{sorted\_json}(\text{interaction})\right)$$

```python
fingerprint_raw = (
    f"{source_id}:{decoy_id}:{timestamp_str}:{session_id}:"
    f"{event_type}:{client_ip}:{interaction_digest}"
)
event_hash = hashlib.sha256(fingerprint_raw.encode("utf-8")).hexdigest()
```

### Key Characteristics:
1. **Payload Invariance:** `interaction_digest` serializes the dictionary with sorted keys (`sort_keys=True`), guaranteeing that JSON key reordering does not alter the hash.
2. **Distinct Event Discrimination:** Two distinct interactions occurring at different timestamps or from different sessions generate completely distinct fingerprints, preventing false-positive deduplication collisions.
3. **Database Uniqueness:** The column `security_events.event_hash` is indexed with a `UNIQUE` constraint, enforcing database-level idempotency protection even under concurrent multi-worker execution.

---

## 3. Idempotent Duplicate Handling Behavior

When an incoming event yields an `event_hash` or `raw_event_id` already present in the database:
1. **No-Op Persistence:** No database write occurs (`INSERT` is bypassed).
2. **Counters Updated:** The engine increments `duplicate_count` in the batch response and `metrics.duplicates_detected` in live monitoring.
3. **Status Response:** The processing status for that event returns `DUPLICATE` with diagnostic code `DUPLICATE_EVENT_DETECTED`.
4. **Non-Failure Response:** The overall batch returns HTTP 200 OK because idempotent re-submission is an expected operational event, not an unhandled exception.

