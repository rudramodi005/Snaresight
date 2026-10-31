# SnareSight: Security Threat Model (STRIDE Evaluation)
**Document ID:** SEC-001  
**Status:** Approved Security Threat Model  

---

## 1. Threat Modeling Methodology

SnareSight evaluates platform threats using Microsoft's **STRIDE** framework:
* **S**poofing Identity
* **T**ampering with Data
* **R**epudiation
* **I**nformation Disclosure
* **D**enial of Service
* **E**levation of Privilege

---

## 2. STRIDE Threat Assessment

### S — Spoofing Identity
* **Threat S1: Telemetry Forgery.** An attacker on the local network attempts to inject fake security events into the Ingestion API to create false alerts.
  * *Mitigation:* Ingestion endpoint requires a pre-shared cryptographic bearer token (`X-Decoy-Token`) configured via environment variables. Ingestion rejects unauthenticated payloads.
* **Threat S2: Unauthorized Dashboard User.** An unauthenticated entity accesses SOC triage controls.
  * *Mitigation:* Stateless JWT authentication with signed HMAC-SHA256 tokens and user session expiration.

### T — Tampering with Data
* **Threat T1: Log Manipulation.** An attacker interacting with the honeypot attempts to tamper with raw forensic logs.
  * *Mitigation:* Decoys ship telemetry in real time to the host ingestion service. Raw logs are stored in append-only database tables (`raw_events`) with immutable primary keys and foreign key constraints.
* **Threat T2: Event Ingestion Poisoning.** Attacker injects malicious SQL or script tags into decoy input fields.
  * *Mitigation:* Strict Pydantic schema validation, SQLAlchemy parameterized queries (zero raw string SQL), and React's automatic HTML entity encoding in the UI.

### R — Repudiation
* **Threat R1: Analyst Action Repudiation.** An analyst deletes or closes an alert without an audit trail.
  * *Mitigation:* Immutable `audit_logs` record every case status change, note creation, and administrative action with user ID and timestamp.
* **Threat R2: Event Provenance Ambiguity.** Doubts arise about whether an alert was triggered by live malware or a test simulation.
  * *Mitigation:* Enforced `provenance` metadata tags (`live_honeypot`, `synthetic_demo`, `controlled_simulation`) burned permanently into the database row.

### I — Information Disclosure
* **Threat I1: Credential Leakage via Honeypot Logs.** Attacker enters actual corporate passwords into the honeypot; plain text passwords are displayed on the dashboard or saved to disk.
  * *Mitigation:* Mandatory redaction engine masks passwords or stores only SHA-256 hashes for dictionary analysis. Plaintext passwords are never persisted.
* **Threat I2: Decoy Fingerprinting.** Attacker detects that the target is a honeypot through default headers or server error signatures.
  * *Mitigation:* Decoy application mimics a standard commercial login portal (custom templates, realistic HTTP response codes, simulated delay).

### D — Denial of Service
* **Threat D1: Ingestion API Flooding.** An automated scanner generates millions of requests to exhaust host memory or database disk.
  * *Mitigation:* Rate limiting on the Ingestion API (max 100 requests/sec per decoy), max payload size limit (64 KB), and separate thread pools for ingestion vs. web dashboard.
* **Threat D2: Database Volume Exhaustion.** Long-running honeypots accumulate gigabytes of repetitive probe logs.
  * *Mitigation:* Sliding-window deduplication drops identical payloads within 10 seconds; 90-day retention pruning policy for raw event records.

### E — Elevation of Privilege
* **Threat E1: Honeypot / Container Breakout.** Attacker exploits a vulnerability in the decoy web server to gain root on the host machine.
  * *Mitigation:* Decoys execute in a non-root, unprivileged container/VM context. Zero bridged networking. Host file mounts are strictly read-only or absent.
* **Threat E2: Malicious Payload Execution.** An attacker uploads a shell script or binary to the decoy; the host tries to analyze or execute it.
  * *Mitigation:* **Zero-Execution Invariant.** SnareSight records file metadata, size, and SHA-256 hash only. It is strictly prohibited from executing captured binary files.

