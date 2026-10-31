# SnareSight: Security Risk Register
**Document ID:** SEC-002  
**Status:** Approved Security Risk Register  

---

## 1. Risk Evaluation Scale

* **Likelihood:** Low / Medium / High
* **Impact:** Low / Medium / High / Critical
* **Severity Score:** Low / Medium / High / Critical (Composite matrix)

---

## 2. Risk Register

| Risk ID | Threat Description | Affected Component | Attack Preconditions | Impact | Likelihood | Risk Severity | Architectural Mitigation | Residual Risk | Verification Method |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **RSK-01** | Honeypot VM Escape to Host | Host OS / VM boundary | Critical zero-day in VM hypervisor/kernel | Critical | Low | **High** | Decoys run in non-root user space with zero host file mounts and isolated private vSwitch. | Very Low | Hypervisor configuration audit |
| **RSK-02** | Telemetry Ingestion Forgery | Ingestion API (`/ingest`) | Network connectivity to ingestion port | High | Medium | **High** | Cryptographic bearer token required; rate limiting enforced; strict JSON schema check. | Low | Unauthorized POST request rejection test |
| **RSK-03** | Ingestion Denial of Service | Backend / DB | High-velocity automated attack tool | High | Medium | **High** | Max payload limit (64 KB); token rate limiting (100 req/s); sliding deduplication filter. | Low | Synthetic load flooding test |
| **RSK-04** | Plaintext Password Exposure | Database / UI | Attacker enters legitimate corporate credentials | High | High | **High** | Automatic redaction of password fields; store only length and irreversible SHA-256 hash. | Very Low | Password mask verification test |
| **RSK-05** | Accidental Honeypot Internet Exposure | Network Boundary | Misconfigured router or firewall rules | Critical | Low | **High** | Absolute ban on bridged networking; bind decoys strictly to private virtual switch. | Very Low | External port scan verification |
| **RSK-06** | Database SQL Injection | PostgreSQL Database | Malicious SQL string injected into decoy inputs | High | Low | **Medium** | SQLAlchemy ORM with 100% parameterized queries; Pydantic type validation. | Very Low | Automated SQL injection test suite |
| **RSK-07** | Attacker Payload Execution | Backend / Host | Attacker uploads malicious script to decoy | Critical | Low | **Medium** | **Strict Zero-Execution Rule:** Captured payloads are hashed and logged, never executed. | Zero | Static analysis of ingest logic |
| **RSK-08** | Unauthorized Dashboard Access | SOC Dashboard / API | Exposed dashboard port on local network | High | Low | **Medium** | Dashboard & API bound to `127.0.0.1`; JWT authentication required for all routes. | Low | Unauthenticated route access test |
| **RSK-09** | Synthetic vs. Live Data Confusion | SOC Metrics / Reports | Mixing mock test data with live honeypot hits | Medium | Medium | **Medium** | Mandatory `provenance` field tagged on every row; UI badges clearly display data source. | Low | Database provenance constraint test |
| **RSK-10** | Database Disk Exhaustion | PostgreSQL Storage | Continuous long-term attack traffic | Medium | Medium | **Medium** | 90-day automatic retention pruning policy for high-volume `raw_events`. | Low | Scheduled cleanup job verification |

