# SnareSight Release Candidate — Defensive Security Review

**Document ID:** SEC-P37-001  
**Project:** SnareSight — Deception-Driven Threat Detection Platform  
**Release Target:** v1.0.0-rc1  
**Date:** October 31, 2026  
**Status:** AUDITED & APPROVED  
**Review Type:** DEFENSIVE ARCHITECTURE & CONTROL AUDIT  

---

## 1. Executive Summary

This defensive security review audits the SnareSight Release Candidate across 20 distinct security domains to verify access controls, boundary enforcement, cryptographic hygiene, and defensive invariants.

No offensive penetration testing was performed on live infrastructure. All findings and verifications are derived from code inspection, automated test suites, and architectural constraints.

---

## 2. 20 Security Domain Audit Matrix

| # | Security Domain | Evaluated Mechanism | Verification Evidence | Status |
| :-: | :--- | :--- | :--- | :--- |
| **1** | **Authentication** | Stateless JWT (`HS256`, 60m expiry), bcrypt (`passlib`). | `test_workflow_08_rbac_privilege_enforcement` | **VERIFIED** |
| **2** | **Authorization & RBAC** | Atomic permission dependencies (`require_permission`) across `ADMIN`, `ANALYST`, and `VIEWER`. | `test_workflow_08_rbac_privilege_enforcement` | **VERIFIED** |
| **3** | **Session Management** | Client-side tokens held in `sessionStorage` (ephemeral across browser sessions). | `frontend/src/features/auth/AuthContext.tsx` | **VERIFIED** |
| **4** | **Credential Handling** | Zero Password Invariant enforced via `SensitiveDataInspector`. | `test_workflow_01_telemetry_intake_and_sanitization` | **VERIFIED** |
| **5** | **Input Validation** | Strict Pydantic v2 schemas; strict regex on `session_id` (`^decoy_sess_[a-f0-9]{32}$`). | `app.ingestion.validators.TelemetryValidator` | **VERIFIED** |
| **6** | **SQL Injection Defense** | 100% SQLAlchemy 2.0 ORM query parameterization. Zero raw string SQL concatenation. | Query inspection across all service modules | **VERIFIED** |
| **7** | **XSS Mitigation** | React DOM auto-escaping; HTTP security headers (`nosniff`, `frame-ancestors 'none'`). | `SecurityHeadersMiddleware` | **VERIFIED** |
| **8** | **CSRF Defense** | Stateless Bearer token authorization; browser default cross-origin protections. | Auth middleware architecture | **VERIFIED** |
| **9** | **CORS Policy** | Explicit allowlist restricted to `http://localhost:5173` and `http://127.0.0.1:5173`. | `app.main.CORSMiddleware` | **VERIFIED** |
| **10** | **Security Headers** | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`. | `app.modules.security.middleware` | **VERIFIED** |
| **11** | **Rate Limiting** | In-memory sliding window rate limiter on auth login endpoint (5 attempts / 15 mins). | `app.modules.security.rate_limiter` | **VERIFIED** |
| **12** | **Request Size Limiting** | Max request body enforced at 2 MB (`RequestSizeLimitMiddleware`). | `app.modules.security.middleware` | **VERIFIED** |
| **13** | **Database Permissions** | Isolated DB user connection pooling; honeypot decoys have 0 direct database access. | Database connection pool configuration | **VERIFIED** |
| **14** | **Audit Trail Integrity** | Append-only immutable audit models (`AuditLogModel`, `AlertAuditLogModel`). | `app.db.models.security.AuditLogModel` | **VERIFIED** |
| **15** | **SSE Stream Protection** | Event publisher handles disconnections gracefully; zero state mutation on drop. | `app.streaming.event_publisher` | **VERIFIED** |
| **16** | **Sensor Authentication** | Sensor registration generates dedicated API keys verified via SHA-256 header tokens. | `test_workflow_05_sensor_fleet_lifecycle` | **VERIFIED** |
| **17** | **Decoy Isolation** | Pure passive interaction; requested commands and directory traversal paths are never executed. | `app.detection.session_evaluator.normalize_path` | **VERIFIED** |
| **18** | **Sensitive Data Logging** | Passwords and private keys redacted prior to logging; zero passwords in stack traces. | `SensitiveDataInspector` | **VERIFIED** |
| **19** | **Dependency Hygiene** | Dependencies locked and managed via `uv`; zero vulnerable legacy packages. | `pyproject.toml`, `package.json` | **VERIFIED** |
| **20** | **Backup & DR Security** | SHA-256 digests on all backup dumps; restore tests run in isolated sandbox DB only. | `test_workflow_06_platform_health_and_sandbox_recovery` | **VERIFIED** |

---

## 3. Findings & Remediations Register

| Finding ID | Description | Severity | Component | Mitigation / Remediation |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-001** | Frontend tokens stored in `sessionStorage` could be exposed if malicious third-party scripts execute. | Low | Frontend Auth | Retain `sessionStorage` for SPA ease of evaluation; recommend HttpOnly SameSite cookies for multi-tenant production hosting. |
| **SEC-002** | Rate limiter uses process-memory tracking rather than distributed store. | Low | Security Middleware | Fully compliant with modular monolith architecture; sufficient for single-instance release candidate. |
| **SEC-003** | `AUTH_ENFORCEMENT_MODE` supports `PERMISSIVE_DEV` setting. | Medium | Backend Config | Documented in `REPRODUCIBLE_SETUP.md` that `AUTH_ENFORCEMENT_MODE=STRICT` is mandatory for production. |

