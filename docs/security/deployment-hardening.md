# SnareSight: Production Deployment Hardening & Security Headers

**Phase:** 7 — Security Hardening and Defensive Response  
**Task:** P31 / 40  
**Status:** `COMPLETED AND VERIFIED`

---

## 1. HTTP Security Headers

SnareSight enforces defense-in-depth security headers via `SecurityHeadersMiddleware`:

```text
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self';
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=()
Strict-Transport-Security: max-age=31536000; includeSubDomains (Production only)
```

### Rationale
- **Content-Security-Policy (CSP)**: Disallows unauthorized external script execution while permitting local bundles and Tailwind CSS styles. `frame-ancestors 'none'` prevents clickjacking attacks.
- **X-Content-Type-Options: nosniff**: Prohibits browser MIME-type sniffing of telemetry or user uploads.
- **X-Frame-Options: DENY**: Forbids embedding SnareSight inside iframes or frames on external sites.
- **Referrer-Policy: strict-origin-when-cross-origin**: Shields URL parameters and internal paths from leaking to third-party endpoints.
- **HSTS**: Forces HTTPS transport in production deployments with a 1-year duration.

---

## 2. CORS Allowlisting

FastAPI `CORSMiddleware` is configured with strict origin restrictions:
- **Allowed Origins**: Strictly allowlisted frontend origins (`http://localhost:5173`, `http://127.0.0.1:5173`, or production dashboard domain).
- **Wildcards (`*`)**: Prohibited for origins when `allow_credentials=True`.
- **Allowed Headers & Methods**: Standard HTTP methods (`GET`, `POST`, `PUT`, `DELETE`, `OPTIONS`) and headers (`Content-Type`, `Authorization`, `X-API-Key`).

---

## 3. Development vs. Production Configuration

| Parameter | Development Setting | Production Hardened Setting |
| :--- | :--- | :--- |
| `ENVIRONMENT` | `development` | `production` |
| `AUTH_ENFORCEMENT_MODE` | `PERMISSIVE_DEV` | `ENFORCED` |
| `SECRET_KEY` | Dev placeholder | High-entropy random 256-bit secret |
| `DATABASE_URL` | Local loopback | Protected connection string with TLS |
| `DATABASE_ECHO` | `true` or `false` | `false` |
| `Strict-Transport-Security`| Disabled (HTTP localhost) | Enabled (`max-age=31536000`) |
| `Cookie Secure Flag` | `false` | `true` |

