# SnareSight Detection Scenario Catalogue

## 1. Overview and Architecture

The SnareSight Detection Scenario Catalogue defines concrete, explainable, and evidence-backed detection scenarios designed specifically for honeypot telemetry. It builds directly upon the foundational **P16 Rule-Based Detection Engine** and the **P17 Severity & Confidence Assessment System**.

All scenarios operate under strict safety and isolation invariants:
- **Simulated Decoy Interactions:** Activity observed on honeypots is never confused with a verified breach of production infrastructure.
- **Passive Inspection Only:** Evaluators never execute shell commands, never execute uploaded files, and never resolve traversal paths against the host operating system.
- **Zero Raw Secrets:** Plaintext passwords, private keys, and session secrets are never processed or retained by detection rules.

---

## 2. Standard Scenarios Summary

| Scenario ID | Name | Category | Evaluation Mode | Detection Type | Default Severity | Status |
|---|---|---|---|---|---|---|
| `AUTH-001` | Repeated Authentication Failures | `AUTHENTICATION` | `SESSION` | Threshold | `MEDIUM` | **IMPLEMENTED** |
| `AUTH-002` | Decoy Authentication Acceptance | `AUTHENTICATION` | `EVENT` | Single Event | `HIGH` | **IMPLEMENTED** |
| `AUTH-003` | Username Enumeration Probing | `RECONNAISSANCE` | `SESSION` | Threshold | `MEDIUM` | **IMPLEMENTED** |
| `WEB-001` | Web Path Enumeration Probing | `RECONNAISSANCE` | `SESSION` | Threshold | `LOW` | **IMPLEMENTED** |
| `WEB-002` | Suspicious Directory Traversal Request | `EXPLOITATION` | `EVENT` | Single Event | `HIGH` | **IMPLEMENTED** |
| `CMD-001` | Command Discovery Interaction | `COMMAND_EXECUTION` | `EVENT` | Single Event | `MEDIUM` | **DEFERRED** |
| `FILE-001` | File Transfer Interaction | `APPLICATION` | `EVENT` | Single Event | `MEDIUM` | **DEFERRED** |
| `WEB-003` | Repeated Suspicious Request Patterns | `APPLICATION` | `SESSION` | Threshold | `MEDIUM` | **IMPLEMENTED** |
| `BEHAV-001` | Multi-Category Suspicious Interaction | `APPLICATION` | `SESSION` | Correlation | `HIGH` | **IMPLEMENTED** |
| `BEHAV-002` | Unusual HTTP Method Interaction | `APPLICATION` | `EVENT` | Anomaly | `MEDIUM` | **IMPLEMENTED** |

---

## 3. Detailed Scenario Specifications

### `AUTH-001`: Repeated Authentication Failures
- **Objective:** Identify repeated authentication failure attempts within a validated session or sliding time window.
- **Applicable Decoy:** `WEB-001` (Web Login Honeypot).
- **Required Fields:** `event_id`, `event_category`, `action`, `outcome`, `session_id`, `decoy_id`, `observed_at`.
- **Logic:** Counts failed authentication attempts (`outcome == 'FAILURE'`) within `session_id` over sliding window (default: 300s).
- **Threshold:** $\ge 3$ failures within session.
- **Evidence Handling:** All qualifying failure event IDs are linked in `alert_evidence`.

### `AUTH-002`: Decoy Authentication Acceptance
- **Objective:** Identify simulated successful authentication on the decoy (trap account accepted).
- **Applicable Decoy:** `WEB-001`.
- **Required Fields:** `event_id`, `event_category`, `action`, `outcome`, `session_id`, `decoy_id`, `observed_at`.
- **Logic:** Single event match where `event_category == 'authentication'` and `outcome == 'SUCCESS'`.
- **Finding Meaning:** Indicates that an attacker or automated tool submitted credentials matching a simulated decoy user profile. Does **NOT** indicate compromise of production systems.

### `AUTH-003`: Username Enumeration Probing
- **Objective:** Identify attempts to test or enumerate user identities across a login form.
- **Applicable Decoy:** `WEB-001`.
- **Required Fields:** `session_id`, `metadata.username_fingerprint`, `observed_at`.
- **Logic:** Evaluates session events and counts distinct privacy-safe username fingerprints (SHA-256 hashes). Plaintext usernames are neither needed nor processed.
- **Threshold:** $\ge 3$ distinct username fingerprints within session.

### `WEB-001`: Web Path Enumeration Probing
- **Objective:** Identify scanning and brute-force probing of non-existent or sensitive HTTP endpoints.
- **Applicable Decoy:** `WEB-001`.
- **Required Fields:** `session_id`, `metadata.http_path`, `observed_at`.
- **Logic:** Safely normalizes requested URL paths (unquoting percent encodings, trimming trailing slashes) and counts distinct paths visited.
- **Threshold:** $\ge 3$ distinct normalized paths. Default severity is `LOW` to prevent alert fatigue.

### `WEB-002`: Suspicious Directory Traversal Request
- **Objective:** Detect path traversal sequences aimed at escaping web application directory roots.
- **Applicable Decoy:** `WEB-001`.
- **Required Fields:** `metadata.http_path`.
- **Logic:** Passive pattern evaluation for indicators: `../`, `..%2f`, `..%2F`, `%2e%2e%2f`, `%2e%2e/`, `..\`, `..%5c`.
- **Safety Guarantee:** Target path string is never resolved on the Windows/Linux filesystem or opened.

### `CMD-001`: Command Discovery Interaction (DEFERRED)
- **Objective:** Identify environment discovery commands (`uname`, `whoami`, `id`, `ls`) in interactive shell decoys.
- **Status:** **DEFERRED**. The current deployed decoy is `WEB-001` (HTTP login decoy), which does not provide terminal access.
- **Safety Guarantee:** Recorded command text is passive telemetry only and is never executed.

### `FILE-001`: File-Transfer Attempts (DEFERRED)
- **Objective:** Detect uploads or downloads of files on honeypot endpoints.
- **Status:** **DEFERRED**. The current web decoy does not accept file uploads.
- **Safety Guarantee:** Transferred content is never executed or opened.

### `WEB-003`: Repeated Suspicious Request Patterns
- **Objective:** Identify sessions repeatedly submitting suspicious or malformed requests.
- **Applicable Decoy:** `WEB-001`.
- **Required Fields:** `session_id`, `metadata.request_pattern`, `metadata.http_path`.
- **Logic:** Counts matching suspicious patterns or probe markers within the session.
- **Threshold:** $\ge 3$ suspicious requests.

### `BEHAV-001`: Multi-Category Suspicious Interaction
- **Objective:** Identify sessions exhibiting multiple distinct categories of suspicious activity (e.g., authentication probing combined with web path enumeration).
- **Applicable Decoy:** `WEB-001`.
- **Logic:** Chronologically evaluates session events and counts distinct security categories (e.g. `authentication` and `request`).
- **Threshold:** $\ge 2$ distinct security categories.

### `BEHAV-002`: Unusual HTTP Method Interaction
- **Objective:** Identify requests utilizing atypical HTTP methods often associated with scanner profiling or method tampering.
- **Applicable Decoy:** `WEB-001`.
- **Required Fields:** `metadata.http_method`.
- **Logic:** Matches methods `TRACE`, `TRACK`, `PROPFIND`, `PUT`, `DELETE`, `DEBUG`.

