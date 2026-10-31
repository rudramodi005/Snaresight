# SnareSight: Master Documentation Index & Knowledge Base

**Document Version:** 1.0.0  
**Phase:** 8 — Testing, Demonstration & Project Handover  
**Date:** October 2026  
**Classification:** Master Technical Documentation Directory  

---

## 1. Navigating SnareSight Documentation

The SnareSight documentation library provides complete coverage of system architecture, security policies, database design, API endpoints, operational procedures, and testing results. 

Choose your path based on your role:

```
[SnareSight Documentation Hub]
  ├── For Developers & DevOps ----------> Section 2 (Developer & Architecture Guides)
  ├── For SOC Analysts -----------------> Section 3 (SOC Analyst & Incident Playbooks)
  ├── For Platform Administrators ------> Section 4 (Admin, Resilience & Maintenance)
  └── For Evaluators & Mentors ---------> Section 5 (Handover & Verification Dossier)
```

---

## 2. Developer & Architecture Guides

* **[DEVELOPER_SETUP_GUIDE.md](documentation/DEVELOPER_SETUP_GUIDE.md)** — Step-by-step local development setup with verified PowerShell and Bash commands, environment variable templates, and migration procedures.
* **[SYSTEM_ARCHITECTURE.md](documentation/SYSTEM_ARCHITECTURE.md)** — Complete modular monolith architecture specification featuring 5 detailed Mermaid flowcharts and sequence diagrams.
* **[API_REFERENCE.md](documentation/API_REFERENCE.md)** — Exhaustive REST and SSE API endpoint reference covering all 15 backend subsystems.
* **[DATABASE_REFERENCE.md](documentation/DATABASE_REFERENCE.md)** — Complete database schema reference, entity-relationship diagram (ERD), table definitions, indexes, and Alembic migration lineage.
* **[TESTING_AND_QA_GUIDE.md](documentation/TESTING_AND_QA_GUIDE.md)** — Test pyramid, Pytest suites, Vitest frontend tests, Playwright browser journeys, and quality gates.
* **[TROUBLESHOOTING.md](documentation/TROUBLESHOOTING.md)** — Practical diagnostic-to-remediation knowledge base for startup, database, proxy, streaming, and sensor issues.

---

## 3. SOC Analyst & Threat Investigation Manuals

* **[SOC_ANALYST_USER_MANUAL.md](documentation/SOC_ANALYST_USER_MANUAL.md)** — Comprehensive user guide walking through the analyst mental model, alert triage, session exploration, attack-chain graphs, and report generation.
* **[DETECTION_AND_ATTACK_MAPPING.md](documentation/DETECTION_AND_ATTACK_MAPPING.md)** — Deep dive into the 10 catalogue detection rules, dual-metric scoring policy (Severity vs Confidence), deduplication windows, and MITRE ATT&CK alignment.
* **[HONEYPOT_OPERATIONS_MANUAL.md](documentation/HONEYPOT_OPERATIONS_MANUAL.md)** — Decoy sensor deployment, network isolation invariants, Zero-Password policy, and heartbeat health states.
* **[SECURITY_AND_PRIVACY.md](documentation/SECURITY_AND_PRIVACY.md)** — STRIDE threat model, Five Immutable Security Invariants, data protection rules, and threat attribution ethics.

---

## 4. Administrator, Maintenance & Resilience Runbooks

* **[ADMINISTRATOR_GUIDE.md](documentation/ADMINISTRATOR_GUIDE.md)** — Platform operations, Role-Based Access Control (RBAC), sensor key rotation, retention holds, and disaster recovery validation.
* **[Operational Resilience Subsystem (`docs/operational-resilience/`)](operational-resilience/README.md)** — Deep architectural notes on internal self-monitoring, automated backups, and isolated restore validation.
* **[Sensor Management Subsystem (`docs/sensor-management/`)](sensor-management/README.md)** — Sensor health monitoring, telemetry reliability, and failover runbooks.
* **[Defensive Response Subsystem (`docs/defensive-response/`)](defensive-response/README.md)** — Incident cases, playbook definitions, containment actions, and firewall script generators.

---

## 5. Evaluator, Reviewer & Academic Handover Dossier

* **[PROJECT_HANDOVER.md](documentation/PROJECT_HANDOVER.md)** — Executive project dossier, 10-minute quickstart verification checklist, architectural trade-offs, and future research roadmap.
* **[DOCUMENTATION_AUDIT.md](documentation/DOCUMENTATION_AUDIT.md)** — Exhaustive audit of all documentation across repository history, validating accuracy against actual code.
* **[Demonstration Lab & Synthetic Scenarios (`docs/demo/`)](demo/README.md)** — Documentation of the 6 deterministic attack scenarios (SCN-A through SCN-F), evaluation harness, and `/demo` UI.
* **[Release Candidate Verification (`docs/release/`)](release/README.md)** — Docker Compose orchestration, release readiness criteria, and performance validation reports.

---

## 6. Subsystem Domain Archive Directory

For granular, phase-by-phase design notes generated during earlier milestones, refer to the domain-specific subdirectories:

| Subsystem Directory | Focus Area |
|---|---|
| `docs/architecture/` | Foundational Architecture Decision Records (ADR-001 through ADR-012) and C4 models. |
| `docs/security/` | Phase 1 Security threat model, risk register, and data protection specifications. |
| `docs/detection/` | Detection engine condition evaluators, rule validators, and execution trackers. |
| `docs/alert-management/` | Alert lifecycle, triage center, and evidence correlation models. |
| `docs/correlation/` | Activity session models, temporal sequence correlation, and graph builders. |
| `docs/mitre-attack/` | MITRE ATT&CK Enterprise dataset versions, matrix navigation, and review workflows. |
| `docs/source-intelligence/` | Source IP profiling, behavioral features, and similarity scoring algorithms. |
| `docs/campaign-intelligence/`| Investigation clusters, campaign membership, and multi-IP correlation. |
| `docs/analytics/` | SOC reporting, KPI metric formulas, and sensor reliability indices. |
| `docs/testing/` | Comprehensive test execution logs, defect registers, and scenario test plans. |
| `docs/release/` | Final release candidate integration, performance benchmarks, and container configs. |
