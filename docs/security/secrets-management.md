# SnareSight: Secrets & Configuration Management Policy

**Phase:** 7 — Security Hardening and Defensive Response  
**Task:** P31 / 40  
**Status:** `COMPLETED AND VERIFIED`

---

## 1. Secrets Handling Standards

1. **No Committed Secrets**:
   - Production secrets, API keys, private certificates, and database credentials are never committed to version control.
   - All actual secrets are loaded exclusively through environment variables.
2. **Safe Example Files (`.env.example`)**:
   - Repository `.env.example` files contain only safe descriptive placeholders (e.g. `CHANGE_ME_IN_PRODUCTION`).
3. **Gitignore Protection**:
   - `.env`, `.env.local`, `.env.production`, and temporary secret files are explicitly listed in `.gitignore`.
4. **No Secret Printing**:
   - Application startup logs, exception handlers, and diagnostic health checks are audited to ensure secret values or tokens are never printed to `stdout` or logs.

---

## 2. Key Secrets & Rotation Guidelines

| Secret Name | Purpose | Recommended Rotation Period | Rotation Method |
| :--- | :--- | :--- | :--- |
| `SECRET_KEY` / `JWT_SECRET_KEY` | Signs session JWT tokens | 90 days | Generate new 256-bit key via `openssl rand -hex 32`. Active sessions re-authenticate. |
| `INGESTION_API_KEY` | Authenticates honeypot telemetry | 90 days | Update backend `.env` and sync to honeypot adapters. |
| `DATABASE_URL` | PostgreSQL application connection | 180 days | Rotate password in PostgreSQL and update service configuration. |

---

## 3. Credential Rotation Procedure

1. **Preparation**: Generate high-entropy replacement credentials using a secure random generator:
   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
2. **Deployment**: Update environment variables in container orchestration or systemd service configurations.
3. **Verification**: Restart backend service and verify health status via `GET /api/v1/health`.
4. **Audit**: Verify successful rotation by inspecting `system_audit_logs`.

