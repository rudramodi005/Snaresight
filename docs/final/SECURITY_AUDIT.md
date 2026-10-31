# SnareSight Defensive Security & Hardening Audit

**Application:** SnareSight Deception-Driven Security Operations Platform  
**Target:** Application Gateways, REST APIs, Ingestion Boundaries, Authentication Tokens  
**Date:** November 1, 2026  
**Auditor:** Senior Cybersecurity Engineer & Application Security Architect  
**Status:** **VERIFIED**

---

## 1. Defensive Security Posture Overview

SnareSight is designed strictly as a **defensive cybersecurity platform** focused on:
- Internal decoy sensors and deception telemetry ingestion.
- Behavioral detection and alert classification.
- MITRE ATT&CK framework mapping.
- Defensive incident response and containment playbooks.
- Cryptographic evidence preservation.

No offensive capabilities, active external exploitation, or unverified actor identity assertions exist within the platform.

---

## 2. Authentication, Authorization & RBAC Audit

### Implementation Verification:
1. **Password Hashing:**
   - Handled via `passlib` with `bcrypt` (12 rounds) in `backend/app/modules/security/service.py`.
   - Cleartext passwords are never stored or logged.
2. **JWT Session Management:**
   - Algorithm: `HS256`.
   - Standard claims: `sub` (user_id), `username`, `role`, `permissions`, `exp`, `iat`.
   - Expiration enforced by `backend/app/modules/security/dependencies.py`.
3. **Session Revocation (Logout):**
   - Implemented via the `revoked_tokens` table. Logged-out tokens are immediately blacklisted; subsequent requests using a revoked token receive HTTP 401 Unauthorized.
4. **Role-Based Access Control (RBAC):**
   - `ADMIN`: Full access to configuration, sensor rotation, and administrative features.
   - `ANALYST`: Access to investigations, alert triage, evidence, and response actions.
   - `VIEWER`: Read-only access to dashboards, reports, and event telemetry.
5. **Brute-Force & Rate Limiting Awareness:**
   - Consecutive authentication failures trigger account lockouts and internal security alerts (`InternalSecurityAlertModel`).

---

## 3. Ingestion & Boundary Hardening

1. **Ingestion API Key Authorization:**
   - Ingestion routes (`/api/v1/ingestion/*`) mandate the `X-API-Key` header matching `settings.INGESTION_API_KEY`.
   - Unauthorized telemetry ingestion attempts receive HTTP 401 with an immediate audit log record.
2. **Payload Protection:**
   - `RequestSizeLimitMiddleware` limits inbound request bodies to 10MB, protecting ASGI worker threads from heap memory exhaustion.
3. **HTTP Security Headers:**
   - `X-Content-Type-Options: nosniff`
   - `X-Frame-Options: DENY`
   - `X-XSS-Protection: 1; mode=block`
   - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
   - `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';`

---

## 4. Evidence Integrity & Cryptographic Chain

1. **Chain-of-Custody Verification:**
   - In `backend/app/modules/resilience/service.py`, `verify_audit_trail()` performs SHA-256 hash recalculation across `system_audit_logs`.
   - Each audit record incorporates the SHA-256 hash of its preceding record.
   - Any record alteration or deletion immediately breaks the cryptographic chain and triggers an alert.
2. **Legal Evidence Preservation Holds:**
   - Defended by `EvidencePreservationHoldModel` in the Defensive Response Center.
   - Telemetry under active legal hold cannot be purged during automated retention cycles.

---

## 5. Non-Attribution & Demonstration Safety

- **Decoy IP Segregation:** All synthetic demo events use RFC 5737 test subnets (`198.51.100.0/24`, `203.0.113.0/24`, `192.0.2.0/24`) and loopback decoys.
- **Non-Attribution Notice:** Displayed on all MITRE ATT&CK and Source Intelligence views, documenting observed tradecraft patterns without asserting state-sponsored or human actor identity without evidentiary proof.

