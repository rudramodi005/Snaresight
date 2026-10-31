# SnareSight: Linux Guest Firewall Verification
**Document ID:** SEC-AUDIT-005  
**Phase:** 2 — Lab Isolation and Honeypot  
**Task:** P08 — Verify Isolation and Emergency Shutdown  
**Status:** Verification Specification  

---

## 1. Scope & Verification Strategy

The guest firewall verification ensures that the Linux guest enforces **Default Deny** on all traffic:
* `chain input`: Policy `DROP`. Only `lo` and `192.168.56.1:8080` (test probes) permitted.
* `chain output`: Policy `DROP`. Only `lo` and `192.168.56.1:8000` (telemetry forwarder) permitted.

---

## 2. Status Ledger

* **Specification:** Formalized in `docs/security/GUEST_FIREWALL_CONFIGURATION.md`.
* **Execution Status:** **PENDING**. Awaits guest VM provisioning and initial boot before `nft list ruleset` validation can be executed.
* **Invariant:** Decoy services will not be bound or started until this check transitions to **VERIFIED**.

