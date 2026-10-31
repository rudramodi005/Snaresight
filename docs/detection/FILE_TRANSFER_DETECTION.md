# File Transfer Detection Specification (`FILE-001`) [DEFERRED]

## 1. Objective and Deployment Status
`FILE-001` is designed to detect file upload or download attempts conducted against honeypot endpoints.

### Status: DEFERRED
The deployed `WEB-001` decoy does not provide file upload or download capabilities. Therefore, this scenario is explicitly classified as **DEFERRED** until a honeypot adapter providing controlled file transfer interaction is approved and deployed.

---

## 2. Safety and Isolation Standards
When file transfer telemetry is supported:
- **Zero Execution:** Transferred binaries, scripts, or documents are **NEVER** executed, opened, or interpreted.
- **Untrusted Metadata:** Filenames and paths are treated as malicious input.
- **Storage Boundaries:** Raw binary payloads are not stored directly in relational database tables; metadata (direction, sanitized filename, file size, hash) is recorded.
- **Controlled Tests:** Automated unit tests verify safe parsing of file metadata without touching the filesystem.

