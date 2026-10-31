# Event Data Preservation Security

**Document ID:** SEC-PRESERV-001  
**Classification:** Forensics & Chain-of-Custody Security Standard  
**Scope:** SnareSight Phase 3 — Event Pipeline & Database (P14)  
**Status:** IMPLEMENTED & ENFORCED  

---

## 1. Forensic Integrity Principles

Forensic evidence collected from decoy networks may become critical in subsequent incident investigations, threat actor profiling, or legal proceedings.

To preserve chain-of-custody, SnareSight enforces:
1. **Raw Evidence Immutability:** The `raw_events` table is append-only for ingest operations. Normalized events point to raw records via `ON DELETE RESTRICT`.
2. **Provenance Preservation:** Originating provenance metadata (`real_attacker`, `controlled_test`, `synthetic_simulation`) is immutable and mirrored into both `raw_events` and `security_events`.
3. **Traceability:** Every alert traces back to one or more supporting normalized security events via `alert_evidence`, which in turn trace back to their originating raw events.

---

## 2. Inadvertent Data Loss Defenses

| Mechanism | Security Enforcement | Verification Test |
| :--- | :--- | :--- |
| **Active Investigation Holds** | Any event under an active case hold cannot be deleted by retention. | `TEST RET-006`, `RET-007` |
| **Alert Evidence Restrict** | Foreign key RESTRICT prevents raw event deletion while alert evidence exists. | `TEST RET-012` |
| **Reprocessing Safety** | Re-normalizing telemetry does not delete or overwrite raw evidence. | `TEST DATA-001`, `DATA-003` |
| **Traceable Event IDs** | Original source event IDs remain traceable after normalization. | `TEST DATA-005` |

