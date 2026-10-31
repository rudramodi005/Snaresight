# Web Path Enumeration Detection Specification (`WEB-001`)

## 1. Objective and Context
`WEB-001` detects systematic discovery and crawling of diverse web endpoints on the honeypot. Automated vulnerability scanners (e.g., Nikto, DirBuster, ffuf) routinely scan web servers for exposed configuration files, administrative interfaces, and backup artifacts.

---

## 2. Path Normalization Safety Invariants
Before path counting is performed, paths undergo safe string canonicalization:
- **URL Percent Decoding:** Representations such as `/admin%2findex.php` or `%2e%2e` are decoded for consistent classification.
- **Redundant Slash Canonicalization:** Trailing slashes and multiple consecutive slashes are normalized (`/admin/` $\rightarrow$ `/admin`).
- **Filesystem Safety:** Normalization is strictly a string transformation. The engine **NEVER** calls `os.path.realpath`, `os.stat`, or filesystem APIs on client-provided paths.

---

## 3. Threshold and Alerting Configuration
- **Evaluation Mode:** `SESSION`.
- **Threshold:** $\ge 3$ distinct normalized paths requested within the session window (300s).
- **Default Severity:** `LOW`. Web scanners frequently generate hundreds of benign 404s; setting default severity to `LOW` prevents SOC alert fatigue while ensuring the reconnaissance activity is logged for correlation.

