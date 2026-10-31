# SnareSight: Frontend Security Architecture & Browser Hardening

**Phase:** 7 — Security Hardening and Defensive Response  
**Task:** P31 / 40  
**Status:** `COMPLETED AND VERIFIED`

---

## 1. Cross-Site Scripting (XSS) Prevention

1. **Untrusted Telemetry Handling**:
   - All deception telemetry (HTTP payloads, command strings, user-agent headers, and URL paths) is treated as potentially adversarial input.
   - Values are rendered using standard React JSX text bindings (`{value}`), ensuring automatic HTML entity encoding by React.
   - `dangerouslySetInnerHTML` is strictly prohibited throughout the application for any user-influenced or telemetry-derived content.
2. **External Link Safety**:
   - Any external navigation links (e.g. MITRE ATT&CK technique references) are configured with `rel="noopener noreferrer"` and `target="_blank"` to prevent window opener hijacking and referrer leakage.

---

## 2. Session & Token Storage Safeguards

1. **HttpOnly Cookie Primary Transport**:
   - Authentication tokens are delivered via HttpOnly, SameSite=Lax cookies, completely shielding session credentials from JavaScript-based exfiltration.
2. **Session Storage Scoping**:
   - Ephemeral in-memory React state and browser `sessionStorage` are used solely for UI token propagation. Tokens are automatically cleared on browser tab closure and upon explicit logout.
3. **No Sensitive Telemetry in Console Logs**:
   - Development debug loggers are silenced in production builds. Internal API credentials, passwords, or authentication tokens are never written to `console.log`.

---

## 3. Role-Aware UI Presentation

- **Permission Guards**:
  - Buttons triggering state mutations (such as acknowledging alerts, resolving alerts, generating reports, approving mappings, or creating users) check `hasPermission(permission)`.
  - For `VIEWER` roles, mutation controls are hidden or disabled with clear tooltips indicating read-only privileges.
- **Defense in Depth**:
  - Frontend guards serve exclusively as usability enhancements; actual authorization is enforced independently by the FastAPI backend on every request.

