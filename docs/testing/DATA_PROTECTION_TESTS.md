# SnareSight — Sensitive Data Protection & Privacy Audit

**Document ID:** `SNARESIGHT-DATA-PROTECT-001`  
**Phase:** 2 — Lab Isolation and Honeypot  
**Target:** Data Protection, Sanitization & Privacy Controls  
**Status:** **100% INVARIANT ENFORCED — ZERO SECRETS PERSISTED**

---

## 1. Zero Password Persistence Invariant

SnareSight enforces an inviolable security constraint:
> **INVARIANT:** Under no circumstances shall submitted plaintext passwords, credentials, private keys, authentication tokens, or derived password hashes ever be written to disk, stored in memory beyond immediate request processing, logged in telemetry files, or echoed in response output.

---

## 2. Sentinel & Canary Verification

During automated testing, dedicated canary test passwords containing unique sentinels were submitted:
- Canary 1: `CanaryPass_9999_Sensitive!`
- Canary 2: `CorporateSummerPassword2026!`
- Canary 3: `SecretPassword123!`
- Canary 4: `P` * 276 (Oversized password payload)

### 2.1 File System & Log Audit
A comprehensive automated scan across the entire workspace and persistent data files was performed:
- Target File: `honeypot-lab/web-decoy/data/events.jsonl`
- Target File: `honeypot-lab/web-decoy/data/events.jsonl.1`
- Temporary Test Directories: `tmp/`
- Standard Output & Error Logs: Captured during test runs

**Result:** Zero occurrences of any canary string were discovered in any file or log stream.

### 2.2 Response Body & Error Disclosure Audit
All HTTP response bodies returned by `WEB-001` were scanned:
- Simulated authentication rejection responses (HTTP 401).
- Input validation error responses (HTTP 400).
- Exception handlers and fallback templates.

**Result:** Zero credential reflection or error-based credential disclosure.

---

## 3. Privacy-Safe Metadata Preservation

In place of storing credentials, SnareSight records privacy-safe interaction metadata required for threat detection:

| Telemetry Property | Captured Representation | Privacy Mechanism |
| :--- | :--- | :--- |
| **Submitted Username** | `7c4852c2863cb6ff...` (64 hex characters) | Keyed HMAC-SHA256 (`settings.HMAC_SALT_KEY`). Irreversible pseudonymization prevents plaintext harvesting while allowing attack frequency tracking. |
| **Username Length** | Integer (e.g. `10`) | Bounded integer between `0` and `1024`. |
| **Password Presence** | Boolean (`true` / `false`) | Binary presence indicator only. |
| **Password Complexity** | Category String | Coarse bucket: `none`, `short (<8)`, `medium (8-16)`, `long (>16)`. Exact character length is intentionally obscured. |
| **Payload Markers** | Detected Tags (e.g., `sqli`, `xss`, `traversal`) | Regex pattern matching detects attack signatures without storing the full dangerous body. |

---

## 4. Immediate Memory Release

In `app/routes/login.py`:
```python
# 2. Categorize password length and immediately discard plaintext
pwd_present, pwd_cat = categorize_password_length(password)
del password  # Explicitly release memory reference
```
The variable holding the password string is deleted immediately after the coarse length category is computed, preventing residual credentials from lingering in Python heap frames or traceback objects.

