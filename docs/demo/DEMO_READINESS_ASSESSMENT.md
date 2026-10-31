# SnareSight Demonstration Readiness Assessment

**Document ID:** DOC-DEMO-001  
**Project:** SnareSight — Deception-Driven Threat Detection & Security Operations Platform  
**Phase:** 8 — Testing, Demonstration & Evaluation (P36 / 40)  
**Date:** October 31, 2026  
**Status:** APPROVED FOR LAB DEMONSTRATION  
**Classification:** DEFENSIVE AUDIT & DEMONSTRATION RECORD  

---

## 1. Executive Summary

This readiness assessment establishes the operational viability of SnareSight for end-to-end laboratory demonstrations, academic evaluations, and technical audits. SnareSight is a browser-based, deception-driven threat detection platform implemented as a modular monolith utilizing React 18, TypeScript, Tailwind CSS, FastAPI, SQLAlchemy 2.0, PostgreSQL, and Server-Sent Events (SSE).

All telemetry and interactions utilized within this demonstration framework are strictly synthetic, deterministic, and contained entirely within an isolated laboratory environment.

---

## 2. Subsystem Readiness Matrix

| Subsystem | Readiness Status | Evidence / Test Verification | Limitations / Deferred Capabilities |
| :--- | :--- | :--- | :--- |
| **Telemetry Ingestion & Sanitization** | **OPERATIONAL** | `test_workflow_01_telemetry_intake_and_sanitization`<br>`app.ingestion.sanitizer`<br>`app.ingestion.validators` | Strictly rejects raw credentials; requires valid UUIDv4 and `decoy_sess_*` token. |
| **Honeypot Sensor Fleet Operations** | **OPERATIONAL** | `test_workflow_05_sensor_fleet_lifecycle`<br>`app.modules.sensors` | Sensor heartbeats, registration keys, and telemetry metrics verified. |
| **Threat Detection Engine** | **OPERATIONAL** | `app.detection.engine`<br>`app.detection.scenario_catalogue` | 8 active rules (`AUTH-001..003`, `WEB-001..003`, `BEHAV-001..002`). Rules `CMD-001` and `FILE-001` deferred for interactive SSH/Cowrie containers. |
| **Session & Cross-Session Correlation** | **OPERATIONAL** | `app.correlation.engine`<br>`app.correlation.routes` | IP grouping, session association, and sequence graphs operating cleanly. |
| **MITRE ATT&CK Mapping** | **OPERATIONAL** | `app.modules.mitre`<br>`frontend/src/features/mitre` | Techniques T1110, T1087, T1595, T1059 mapped to detection rules. |
| **SOC Alert Management & Triage** | **OPERATIONAL** | `app.modules.alerts`<br>`test_workflow_02_detection_and_alerting` | Full alert lifecycle: NEW, ACKNOWLEDGED, INVESTIGATING, ESCALATED, RESOLVED. |
| **Defensive Incident Response** | **OPERATIONAL** | `app.modules.response`<br>`test_workflow_04_defensive_response_management` | Case management, analyst notes, dual-analyst recommendation approvals, and legal evidence holds. |
| **Platform Resilience & Recovery** | **OPERATIONAL** | `app.modules.resilience`<br>`test_workflow_06_platform_health_and_sandbox_recovery` | Real-time diagnostics, SHA-256 backup creation, isolated sandbox DB restore validation. |
| **SOC Analytics & Reporting** | **OPERATIONAL** | `app.modules.analytics`<br>`test_workflow_07_reporting_and_analytics` | Aggregated metrics, trend calculations, PDF/JSON export labelled with watermarks. |
| **RBAC & Security Controls** | **OPERATIONAL** | `app.modules.security`<br>`test_workflow_08_rbac_privilege_enforcement` | ADMIN, ANALYST, VIEWER role enforcement verified across all endpoints. |

---

## 3. Demonstration Constraints & Safety Guardrails

1. **Synthetic Data Exclusivity:** All demonstration events utilize RFC 5737 documentation IP subnets (`198.51.100.0/24`, `203.0.113.0/24`, `192.0.2.0/24`). No real-world external IP addresses are contacted or correlated.
2. **Zero Password Storage:** In compliance with core security invariants, no raw passwords or authentication secrets are accepted or stored. Honeypots capture only `password_present: True` and irreversible SHA-256 username fingerprints.
3. **Selective Deletion Safety:** Demonstration data cleanup is partitioned by provenance (`is_synthetic: true`). Records tied to active evidence preservation holds (`RetentionHoldModel`) are protected from deletion during demo cleanup.
4. **No External Network Dependencies:** All demonstration workflows run completely offline or on local loopback (`http://localhost:8000`, `http://localhost:5173`).

