# Suspicious Request Detection Specification (`WEB-003` & `BEHAV-002`)

## 1. Overview
Suspicious request detection addresses abnormal and probing request patterns that deviate from normal web interactions:
- `WEB-003`: Repeated suspicious request patterns within a validated session.
- `BEHAV-002`: Unusual or abnormal HTTP methods.

---

## 2. Repeated Suspicious Patterns (`WEB-003`)
- **Objective:** Detect sessions that repeatedly execute anomalous probes (e.g. repeated SQL injection markers, traversal probes, or malformed queries).
- **Threshold:** $\ge 3$ suspicious requests within session.
- **Evaluation Mode:** `SESSION`.
- **Default Severity:** `MEDIUM`.
- **Deduplication:** Repeated evaluation of the exact same event does not increment the pattern count.

---

## 3. Unusual HTTP Methods (`BEHAV-002`)
- **Objective:** Detect HTTP requests employing diagnostic, WebDAV, or unconventional methods frequently used for capability enumeration or bypass attempts.
- **Target Methods:** `TRACE`, `TRACK`, `PROPFIND`, `PUT`, `DELETE`, `DEBUG`.
- **Evaluation Mode:** `EVENT`.
- **Default Severity:** `MEDIUM`.
- **Finding Rationale:** The web login decoy accepts standard `GET` and `POST` traffic. Submission of `TRACE` or `PROPFIND` indicates intentional scanner probing.

