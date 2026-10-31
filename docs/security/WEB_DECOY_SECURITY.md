# SnareSight: Web Decoy Security Controls Specification
**Document ID:** SEC-DEC-001  
**Phase:** 2 — Lab Isolation and Honeypot  
**Status:** Approved Security Control Specification  

---

## 1. Defensive Boundary Controls

1. **Anti-Fingerprinting Strategy:**
   * Custom HTML templates without third-party framework fingerprints.
   * Standard enterprise error codes (`AC-4019`).
   * Realistic simulated delay (50–150 ms) to mimic enterprise authentication latency.
   * OpenAPI docs (`/docs`, `/redoc`, `/openapi.json`) are disabled.
2. **Denial-of-Service (DoS) Mitigation:**
   * Maximum body size capped at 32 KB via `MaxBodySizeMiddleware`.
   * Username length capped at 128 characters; password length capped at 256 characters.
   * Log files automatically rotate at 10 MB to prevent local disk exhaustion.
3. **Inert Content Handling:**
   * HTML entity escaping applied to all user input before template rendering.
   * Zero evaluation of dynamic expressions or shell commands.
   * No file upload routes or file storage interfaces exist.

