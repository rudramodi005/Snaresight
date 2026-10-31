# SnareSight: Master Reviewer Evidence Index & Artifact Guide

**Document Version:** 1.0.0  
**Phase:** 8 — Testing, Demonstration & Project Handover  
**Document:** `docs/final/EVIDENCE_INDEX.md`  
**Classification:** Reviewer & Mentor Evaluation Reference  

---

## 1. Evidence Navigation Directory

Reviewers and academic mentors can verify all claims in the presentation and reports by inspecting the authoritative artifacts cataloged below:

| Verification Category | Primary Evidence Document | Concrete Evidence Description |
|---|---|---|
| **1. System Architecture** | [SYSTEM_ARCHITECTURE.md](file:///c:/Projects/SnareSight/docs/documentation/SYSTEM_ARCHITECTURE.md) | 5 detailed Mermaid flowcharts and sequence diagrams covering component wiring, ingestion, detection, correlation, and sensor monitoring. |
| **2. Database & Data Models** | [DATABASE_REFERENCE.md](file:///c:/Projects/SnareSight/docs/documentation/DATABASE_REFERENCE.md) | Entity-Relationship diagram, 42 declarative SQLAlchemy models, and linear 9-revision Alembic migration history (`p01` to `p34`). |
| **3. API Endpoint Contracts** | [API_REFERENCE.md](file:///c:/Projects/SnareSight/docs/documentation/API_REFERENCE.md) | Exhaustive route catalog covering all 15 modular subsystems matching the live FastAPI OpenAPI specification (`/openapi.json`). |
| **4. Test Suite Execution Logs**| [evidence/SUMMARY_TEST_LOGS.txt](file:///c:/Projects/SnareSight/docs/final/evidence/SUMMARY_TEST_LOGS.txt) | Sanitized logs showing 532 Pytest tests passing (84.7s), 9 Vitest tests passing (0.57s), and clean Vite production build (3.04s). |
| **5. Detection & ATT&CK Mapping**| [DETECTION_AND_ATTACK_MAPPING.md](file:///c:/Projects/SnareSight/docs/documentation/DETECTION_AND_ATTACK_MAPPING.md) | Specifications of the 10 catalogue detection rules, dual-scoring policy (Severity vs Confidence), and evidence-grounded MITRE mapping rules. |
| **6. Honeypot Operations** | [HONEYPOT_OPERATIONS_MANUAL.md](file:///c:/Projects/SnareSight/docs/documentation/HONEYPOT_OPERATIONS_MANUAL.md) | Sensor forwarder deployment, network isolation invariants, Zero-Password redaction, and heartbeat monitoring state machine. |
| **7. SOC Analyst Operations** | [SOC_ANALYST_USER_MANUAL.md](file:///c:/Projects/SnareSight/docs/documentation/SOC_ANALYST_USER_MANUAL.md) | User workflows for alert triage, session exploration, React Flow attack chains, incident cases, and firewall rule export. |
| **8. Security & Threat Model** | [SECURITY_AND_PRIVACY.md](file:///c:/Projects/SnareSight/docs/documentation/SECURITY_AND_PRIVACY.md) | STRIDE threat model, Five Immutable Security Invariants, data protection rules, and non-attribution disclaimers. |
| **9. Performance Measurements**| [docs/release/PERFORMANCE_BENCHMARK_REPORT.md](file:///c:/Projects/SnareSight/docs/release/PERFORMANCE_BENCHMARK_REPORT.md) | Benchmarks documenting ingestion latency ($< 20\text{ ms}$ for 100 batch events), MTTD ($< 100\text{ ms}$), and database query latency ($< 15\text{ ms}$). |
| **10. Demonstration Protocols** | [LIVE_DEMONSTRATION_VALIDATION.md](file:///c:/Projects/SnareSight/docs/final/LIVE_DEMONSTRATION_VALIDATION.md) | Step-by-step verification protocol for the 6 synthetic attack scenarios (SCN-A to SCN-F) and automated evaluation harness. |
| **11. Release Candidate Status** | [docs/release/RELEASE_CANDIDATE_REPORT.md](file:///c:/Projects/SnareSight/docs/release/RELEASE_CANDIDATE_REPORT.md) | Production Docker Compose orchestration, container healthchecks, and release candidate readiness certification. |
| **12. Known Limitations & Gaps** | [05_CURRENT_PROGRESS.md](file:///c:/Projects/SnareSight/docs/final/05_CURRENT_PROGRESS.md) | Transparent disclosure of deferred rules (`CMD-001`, `FILE-001`), chunk size warnings, and future roadmap milestones. |

---

## 2. Sanitization & Privacy Compliance Notice

In strict adherence to academic ethics and the Five Immutable Security Invariants:
* **No Secrets Committed:** Zero private keys, API secrets, JWT secret keys, or database passwords are included in this directory.
* **RFC 5737 IP Ranges:** All documentation and demonstration examples use documented documentation IP ranges (e.g. `192.168.56.x` or `203.0.113.x`).
* **Zero-Password Storage:** Passwords submitted during demonstration scenarios are hashed with salted SHA-256 and redacted to `[REDACTED]`.

