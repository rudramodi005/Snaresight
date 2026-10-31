# Ingestion Security Architecture

**Document ID:** SEC-ING-001  
**Classification:** Security Architecture & Defense-in-Depth Specification  
**Scope:** SnareSight Phase 3 — Event Pipeline & Database (P13)  
**Status:** IMPLEMENTED  

---

## 1. Threat Model & Security Boundaries

The SnareSight Ingestion Pipeline sits at the boundary between untrusted honeypot environments and the core operational backend.

```
[Untrusted / High-Risk Zone]
  Isolated Linux Guest VM (Honeypot Decoy)
  Port 8080 exposed to potential attackers
               │
               ▼  (Zero DB direct routes; Air-gapped / Controlled transfer)
[Security Boundary: Sanitizer & Ingestion Engine]
  - Pre-parse sensitive keyword inspection
  - Source authorization and cryptographic verification
  - Structural and temporal schema validation
               │
               ▼  (Sanitized, normalized objects only)
[Trusted Persistence Zone]
  PostgreSQL 16 Database
  Zero plain-text password columns
```

### Threat Vectors & Mitigations
| Threat Vector | Potential Impact | Ingestion Mitigation |
| :--- | :--- | :--- |
| **Direct DB Compromise** | Attacker pivoting from VM to Postgres | Honeypots have zero network egress or DB drivers. |
| **Credential Harvester Poisoning** | Storing plain passwords exposes user secrets | `SensitiveDataInspector` strictly blocks and discards all passwords. |
| **Rogue Decoy Injection** | Unauthorized sources injecting false events | `SourceRegistryValidator` blocks unregistered sensors. |
| **Replay & DoS Flooding** | Attacker replaying event stream to skew metrics | SHA-256 deduplication and rate/size caps prevent duplicates. |
| **Path Traversal Ingestion** | Reading arbitrary system files during batch import | Strict path boundary enforcement and traversal checks. |
| **Clock Skew Forgery** | Tampering with timestamps to distort audit trail | Reject timestamps skewed > 300 seconds into the future. |

---

## 2. Invariant Enforcement Matrix

1. **Zero Password Persistence Invariant:** No password or secret may enter storage, logs, metrics, or error payloads.
2. **Provenance Preservation Invariant:** Telemetry provenance (`real_attacker`, `synthetic_simulation`) is immutable and strictly preserved.
3. **Traceability Invariant:** Every normalized security event must link to an immutable raw event record via foreign key.
4. **Idempotency Invariant:** Identical event telemetry must never create duplicate database rows.

