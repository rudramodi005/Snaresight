# Directory Traversal Detection Specification (`WEB-002`)

## 1. Objective and Safety Architecture
`WEB-002` identifies HTTP requests attempting to exploit directory traversal vulnerabilities to escape simulated web document roots (e.g. attempting to read `/etc/passwd` or `win.ini`).

> [!CAUTION]
> **Strict Operational Security Invariant:**
> The detection engine is a purely passive inspector. It **NEVER** opens, executes, resolves, or queries the host filesystem using submitted paths.

---

## 2. Recognized Traversal Indicators
The rule inspects `metadata.http_path` for canonical and encoded traversal tokens:
- Standard relative traversal: `../` and `..\`
- URL encoded slashes: `..%2f`, `..%2F`, `..%5c`, `..%5C`
- URL encoded dots: `%2e%2e%2f`, `%2e%2e/`

---

## 3. Evaluation and Severity
- **Evaluation Mode:** `EVENT` (Single event evaluation).
- **Default Severity:** `HIGH`. Directory traversal attacks represent direct active exploitation attempts rather than passive reconnaissance.
- **Evidence Reference:** The event payload containing the sanitized request path is referenced in `AlertEvidenceModel`.
- **Finding Clarification:** The alert records that traversal indicators were detected in client input; it does **not** assert that any file was accessed or leaked.

