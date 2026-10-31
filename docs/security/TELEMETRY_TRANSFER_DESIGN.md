# SnareSight: Secure Telemetry Transfer Architecture
**Document ID:** SEC-TEL-001  
**Phase:** 2 — Lab Isolation and Honeypot  
**Status:** Approved Design Baseline  

---

## 1. Architectural Strategy: Push vs. Pull Evaluation

We evaluated the four primary models for extracting telemetry from the isolated VM:

| Transfer Model | Mechanism | Host Exposure Risk | Reliability | Selection Assessment |
| :--- | :--- | :--- | :--- | :--- |
| **Model 1: Host Pull via SSH/SCP** | Windows connects via SSH to VM to fetch logs | High (Host must store VM private keys; open SSH listener on VM) | Moderate (Requires polling) | Rejected |
| **Model 2: Shared Folder / File Mount** | Hypervisor shared folder mounted in VM | Critical (VM can exploit file-sharing drivers to access host disk) | High | **Strictly Prohibited** |
| **Model 3: Dedicated Gateway VM** | Multi-hop proxy forwarding telemetry | Very Low | Complex (Requires extra VM & RAM) | Overkill for Phase 2 |
| **Model 4: Restricted HTTP Push (Selected)** | VM forwarder pushes JSON to Host Ingestion API | Low (Single stateless token-gated port, zero VM host access) | High (Immediate event streaming) | **APPROVED PRIMARY** |

---

## 2. Telemetry Ingestion Contract & Authentication

* **Transport:** HTTPS / HTTP over private Host-Only interface (`http://192.168.56.1:8000/api/v1/ingest/events`).
* **Authentication:** Pre-shared cryptographic bearer token transmitted in the `X-Decoy-Token` header.
* **Integrity Validation:** Every payload includes an SHA-256 checksum calculated over the JSON body to detect transmission corruption.
* **Untrusted Data Rule:** Telemetry is treated as **untrusted input**. The Host Ingestion API validates payload types, string lengths, and schema invariants using Pydantic before any database insertion or detection rule execution.

---

## 3. Disconnection & Buffer Recovery

* **Local Spool Buffer:** If the Windows Ingestion API is temporarily unreachable (e.g., during backend restart or debugging), the guest log shipper writes unacknowledged events to a local circular disk buffer (`/var/spool/snaresight/events.db` or JSON lines spool, capped at 50 MB).
* **Backpressure Drain:** Upon reconnection, the shipper drains the spool chronologically, preserving original `event_timestamp` values while updating `ingested_at` upon arrival.

