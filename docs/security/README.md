# SnareSight: Application Security Hardening, Access Control & Audit Protection

**Phase:** 7 — Security Hardening and Defensive Response  
**Task:** P31 / 40  
**Status:** `COMPLETED AND VERIFIED`

---

## 1. Overview & Purpose

The **SnareSight Security Hardening and Defensive Response Module** implements enterprise defense-in-depth security across the browser-based platform. Operating under strict least-privilege principles, this hardening suite secures:
1. **Authentication & Session Lifecycle**: Salted bcrypt password hashing, JWT session tracking, token revocation lists (`revoked_tokens`), rate-limiting to prevent brute force, and generic error responses to prevent user enumeration.
2. **Role-Based Access Control (RBAC)**: Fine-grained enforcement of 17 distinct operational permissions across `ADMIN`, `ANALYST`, and `VIEWER` roles, enforced strictly at the backend dependency layer.
3. **API & Transport Defense**: Defense-in-depth HTTP security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy), request payload bounds (2MB general, 10MB ingestion), and CORS allowlisting.
4. **Honeypot & Telemetry Isolation**: Cryptographic decoupling of decoys from application storage, authenticated ingestion gateways (`X-API-Key`), batch limits, and automated rejection of credentials/canaries.
5. **Real-Time SSE Protection**: Authenticated event subscriptions, decoy-level filtering, bounded buffer queues, and channel isolation.
6. **Immutable Audit Protection**: Transaction-safe logging of all security-relevant operational actions to append-only database tables (`system_audit_logs`).

---

## 2. Directory Structure

```text
c:\Projects\SnareSight\
├── backend\
│   ├── app\
│   │   ├── db\models\security.py             # UserModel, RevokedTokenModel, SystemAuditLogModel
│   │   ├── modules\security\
│   │   │   ├── __init__.py                   # Security module entrypoint
│   │   │   ├── permissions.py                # Role, Permission enums and role permission matrix
│   │   │   ├── crypto.py                     # Bcrypt hashing & JWT lifecycle engine
│   │   │   ├── rate_limiter.py               # In-memory sliding-window rate limiter
│   │   │   ├── audit_service.py              # Centralized immutable audit logger
│   │   │   ├── schemas.py                    # Pydantic auth & audit contracts
│   │   │   ├── dependencies.py               # get_current_user, require_permission, require_role
│   │   │   ├── middleware.py                 # SecurityHeadersMiddleware & RequestSizeLimitMiddleware
│   │   │   ├── routes.py                     # REST endpoints (/api/v1/auth/*, /api/v1/audit/*)
│   │   │   └── seed.py                       # Initial development user seeder
│   │   └── streaming\authorization.py        # StreamAuthorizer JWT integration
│   ├── migrations\versions\
│   │   └── p31_security_hardening.py         # Alembic migration for users, tokens, audit logs
│   └── tests\modules\security\
│       └── test_security_hardening.py        # 20 automated security test cases (100% passing)
├── frontend\
│   └── src\
│       ├── types\auth.ts                     # TypeScript definitions for auth, roles, audit
│       ├── services\authApi.ts               # REST client for auth and audit endpoints
│       ├── features\auth\
│       │   ├── AuthContext.tsx               # Context provider for session & permissions
│       │   ├── LoginPage.tsx                 # Hardened SOC login interface
│       │   └── ChangePasswordModal.tsx       # Password update modal
│       └── App.tsx                           # Protected application shell & navigation
└── docs\security\
    ├── README.md                             # Module overview (this file)
    ├── threat-model.md                       # STRIDE threat model & mitigations
    ├── authentication.md                     # Authentication & password security
    ├── authorization.md                      # RBAC matrix & backend dependencies
    ├── api-security.md                       # REST API defense & rate-limiting
    ├── frontend-security.md                  # Browser security, XSS & token handling
    ├── database-security.md                  # Database boundaries & query safety
    ├── honeypot-isolation.md                 # Honeypot isolation & telemetry boundary
    ├── sse-security.md                       # SSE authentication & stream controls
    ├── audit-logging.md                      # Audit log protection & event schemas
    ├── deployment-hardening.md               # Production deployment & HTTP headers
    ├── secrets-management.md                 # Environment variables & secret rotation
    ├── dependency-security.md                # Supply chain & dependency audit
    └── security-testing.md                   # Automated security test suite verification
```

---

## 3. Documentation Index

- [Threat Model (STRIDE)](file:///c:/Projects/SnareSight/docs/security/threat-model.md)
- [Authentication Hardening](file:///c:/Projects/SnareSight/docs/security/authentication.md)
- [Role-Based Access Control](file:///c:/Projects/SnareSight/docs/security/authorization.md)
- [API Security Controls](file:///c:/Projects/SnareSight/docs/security/api-security.md)
- [Frontend Security Controls](file:///c:/Projects/SnareSight/docs/security/frontend-security.md)
- [Database Security](file:///c:/Projects/SnareSight/docs/security/database-security.md)
- [Honeypot & Telemetry Isolation](file:///c:/Projects/SnareSight/docs/security/honeypot-isolation.md)
- [SSE Security Architecture](file:///c:/Projects/SnareSight/docs/security/sse-security.md)
- [Audit Logging Architecture](file:///c:/Projects/SnareSight/docs/security/audit-logging.md)
- [Deployment Hardening](file:///c:/Projects/SnareSight/docs/security/deployment-hardening.md)
- [Secrets & Configuration Management](file:///c:/Projects/SnareSight/docs/security/secrets-management.md)
- [Dependency & Supply-Chain Security](file:///c:/Projects/SnareSight/docs/security/dependency-security.md)
- [Security Testing & Verification](file:///c:/Projects/SnareSight/docs/security/security-testing.md)

