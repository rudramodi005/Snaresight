# SnareSight: Security Architecture, Threat Model & Privacy Standards

**Document Version:** 1.0.0  
**Phase:** 8 — Testing, Demonstration & Project Handover  
**Date:** October 2026  
**Status:** COMPLETE & AUTHORITATIVE  

---

## 1. Security Architecture & Threat Boundaries

SnareSight operates across three distinct security and network trust zones:

```
[ ZONE 3: Decoy Honeypots ] ----(Isolated Private NAT)----> [ ZONE 2: SnareSight Core ]
(Untrusted / Attacker Probed)                                 (FastAPI Backend + DB)
                                                                       ▲
                                                                       │ (TLS / JWT Auth)
                                                                       ▼
                                                             [ ZONE 1: Analyst Browser ]
                                                              (SOC Web Application)
```

1. **Zone 3 (Decoy Honeypot Zone — High Risk):** Contains web and SSH honeypot instances directly exposed to simulated adversaries. Untrusted. Zero access to internal corporate subnets.
2. **Zone 2 (SnareSight Backend Core — Medium Risk):** Secure API server, normalizer, and database. Binds strictly to `127.0.0.1`. Ingests telemetry via authenticated forwarders.
3. **Zone 1 (Analyst Management Zone — Trusted):** SOC analyst browsers accessing the React dashboard via authenticated HTTPS and JWT sessions.

---

## 2. STRIDE Threat Model & Mitigations

| STRIDE Category | Identified Threat | System Mitigation & Defense |
|---|---|---|
| **Spoofing** | Attacker spoofs decoy forwarder to flood telemetry with garbage data. | All ingestion endpoints require a valid, non-expired `X-Sensor-Key` header mapped to an active sensor in the database. |
| **Tampering** | Rogue actor alters historical alert records to conceal intrusion traces. | Database audit logs (`system_audit_logs`, `alert_audit_logs`) are append-only. UPDATE and DELETE actions are rejected by ORM triggers. |
| **Repudiation** | Analyst performs unauthorized firewall block and denies action. | All defensive containment actions, status transitions, and user modifications record analyst identity and timestamp in audit logs. |
| **Information Disclosure** | Plaintext credentials captured on honeypots leak during analyst triage or database compromise. | **Zero-Password Storage Invariant:** Plaintext passwords are automatically redacted and salted SHA-256 hashed prior to persistence. |
| **Denial of Service** | Volumetric HTTP brute-force overwhelms backend ingestion queue. | Rate-limiting middleware, request body size limit (10MB max), and sliding-window deduplication prevent database starvation. |
| **Elevation of Privilege** | Tier-1 Analyst attempts to perform administrative actions (e.g., delete users or backups). | Role-Based Access Control (RBAC) enforced at FastAPI route dependency layer (`require_role("admin")`). |

---

## 3. The Five Immutable Security Invariants

SnareSight strictly enforces five non-negotiable security rules:

1. **Zero Public Internet Exposure During Development:** Decoys must never be placed on public IP space or forwarded via port mapping without verified enterprise firewall boundaries.
2. **Strict Host-Only / Private Subnet Isolation:** Decoy virtual machines operate strictly within isolated virtual switches with zero bridged access to local LANs.
3. **Zero-Execution Invariant:** Captured payloads, scripts, or binary files are never executed, decompiled, or detonated on the SnareSight backend host.
4. **Localhost Binding Discipline:** Backend APIs and database ports bind strictly to `127.0.0.1` unless behind a TLS reverse proxy.
5. **Zero-Password Storage Policy:** Decoy passwords captured during attacks are hashed with SHA-256 and salt before ingestion; plaintext passwords are never persisted in database logs.

---

## 4. Privacy Standards & Attribution Limitations

### 4.1 Ethical Threat Profiling
SnareSight tracks attacker interaction patterns for defensive containment. However, the platform recognizes that IP addresses and user agents do not constitute verified physical identities:
* **Attribution Disclaimer:** Source profiles represent **clusters of behavioral activity**, not confirmed individual humans. IP addresses can be spoofed, routed through VPNs, Tor exit nodes, or compromised consumer proxy networks.
* **Prohibition of Retaliation:** SnareSight provides defensive firewall containment rules only. It prohibits automated offensive retaliation, port scanning, or "hack-backs" against external IP addresses.

### 4.2 Data Protection & Redaction
* Form inputs matching common PII fields (e.g. `ssn`, `credit_card`, `dob`) submitted to decoys are replaced with `[REDACTED_PII]` tokens.
* Password hashes cannot be reversed back to plaintext by design.

---

## 5. Security Responsibility Matrix

| Responsibility Area | SnareSight Platform Responsibility | Customer / Operator Responsibility |
|---|---|---|
| **Decoy Subnet Isolation** | Provides forwarder authentication & documentation. | Correctly configures hypervisor / virtual switch isolation rules. |
| **Payload Quarantine** | Stores raw payloads safely without execution. | Never copies quarantined payloads to personal developer desktops. |
| **Credential Protection** | Hashes and redacts decoy passwords automatically. | Maintains strong, distinct passwords for SOC analyst user accounts. |
| **Backup Encryption** | Generates SHA-256 verified database snapshots. | Restricts filesystem permissions on `backend/backups/` directory. |
| **Perimeter Containment** | Generates valid, formatted firewall scripts. | Reviews and executes firewall scripts on production boundary devices. |

