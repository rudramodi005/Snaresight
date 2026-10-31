# SnareSight — Event Classification Taxonomy

**Document ID:** `SNARESIGHT-TAXONOMY-001`  
**Classification:** Confidential — Internal Cybersecurity Engineering  
**Authority:** Principal SIEM Engineer & Security Event Modeling Specialist  

---

## 1. Taxonomic Hierarchy

SnareSight uses a two-tiered hierarchical event classification model:
1. **Event Category (Domain Level):** High-level functional domain representing the operational surface of the decoy interaction.
2. **Event Type (Action Level):** Precise, standardized operation reflecting the specific telemetry observation.

```
                          Event Category (9 Domains)
       +-------------------------------+-------------------------------+
       |                               |                               |
  AUTHENTICATION                   REQUEST                    COMMAND_INTERACTION
       |                               |                               |
  - AUTH_ATTEMPT                  - PAGE_VISIT                   - COMMAND_EXEC
  - AUTH_FAILURE                  - PATH_PROBE                   - INTERACTIVE_SESSION
  - AUTH_SUCCESS_MOCK             - ANOMALOUS_REQUEST            - SCRIPT_EXECUTION
  - ENUMERATION_OBSERVED          - METHOD_NOT_ALLOWED           - SHELL_ESCAPE_ATTEMPT
```

---

## 2. The Nine Standard Event Categories

| Category | Definition | Primary Honey Service |
| :--- | :--- | :--- |
| `CONNECTION` | Network transport level observations (TCP handshake, connection close, port knock). | Web Decoy, Cowrie SSH, Network Sensors |
| `REQUEST` | Application-layer transactions (HTTP GET/POST, headers, query parameters, path probes). | Web Decoy (`WEB-001`), REST APIs |
| `AUTHENTICATION`| Credential verification, password length categorization, login failure, simulated grant. | Web Decoy, Cowrie SSH |
| `SESSION` | Client session lifecycle events (issuance, idle timeout, explicit logout, cookie tamper). | Web Decoy, SSH Session Manager |
| `COMMAND_INTERACTION` | Terminal commands executed inside honeypot shell (bash commands, piped syntax). | Cowrie SSH Honeypot (`SSH-001`) |
| `FILE_INTERACTION` | File transfers, script downloads, wget/curl staging, payload uploads. | Cowrie SSH, Web Upload Probes |
| `SERVICE_HEALTH` | Decoy operational telemetry (process startup, heartbeat, disk write errors, log rotation).| All Decoys & Collector Agents |
| `SECURITY_OBSERVATION` | Detected threat indicators (SQLi strings, directory traversal markers, scanner user-agents).| Detection Engine, Normalizer |
| `SIMULATION` | Controlled test submissions, synthetic validation runs, demonstration executions. | QA Test Harness, Demo Injector |

---

## 3. Standardized Event Type Specifications

### 3.1 Category: AUTHENTICATION

#### Event Type: `AUTH_ATTEMPT`
- **Description:** A client submitted credentials to a deceptive authentication surface.
- **Expected Source:** Web Login Decoy (`WEB-001`), Cowrie SSH (`SSH-001`).
- **Required Fields:** `source_address`, `decoy_id`, `session_id`, `details.auth.username_fingerprint`, `details.auth.password_present`, `outcome`.
- **Optional Fields:** `details.auth.username_length`, `details.auth.password_length_category`, `source_port`.
- **Validation Rules:** Plaintext password MUST NOT be present. `username_fingerprint` must be a valid 64-char HMAC-SHA256 hex string.

#### Event Type: `AUTH_FAILURE`
- **Description:** An authentication attempt was rejected (simulated rejection).
- **Expected Source:** Web Login Decoy, Cowrie SSH.
- **Required Fields:** `source_address`, `decoy_id`, `session_id`, `outcome="FAILURE"`, `details.auth.simulated_outcome`.
- **Optional Fields:** `details.auth.username_fingerprint`, `details.http.status_code`.
- **Validation Rules:** `outcome` must strictly equal `"FAILURE"`.

#### Event Type: `AUTH_SUCCESS_MOCK`
- **Description:** Decoy simulated a successful login to lead an adversary deeper into a sandbox.
- **Expected Source:** Advanced interactive decoys.
- **Required Fields:** `source_address`, `decoy_id`, `session_id`, `outcome="SUCCESS"`, `details.auth.simulated_outcome`.
- **Optional Fields:** `details.auth.sandbox_role_assigned`.
- **Validation Rules:** Must be tagged with provenance notes clarifying that no real system access was granted.

#### Event Type: `ENUMERATION_OBSERVED`
- **Description:** High-volume credential submissions against sequential or dictionary usernames.
- **Expected Source:** Detection Engine (derived event).
- **Required Fields:** `source_address`, `decoy_id`, `details.auth.distinct_username_count`, `details.auth.time_window_seconds`.
- **Validation Rules:** Requires minimum 5 distinct username fingerprints within observation window.

---

### 3.2 Category: REQUEST

#### Event Type: `PAGE_VISIT`
- **Description:** A client accessed and rendered an application web page or portal interface.
- **Expected Source:** Web Login Decoy (`WEB-001`).
- **Required Fields:** `source_address`, `decoy_id`, `session_id`, `details.http.method`, `details.http.path`, `details.http.status_code`.
- **Optional Fields:** `details.http.user_agent`, `source_port`.
- **Validation Rules:** `details.http.status_code` must be an integer (e.g. 200).

#### Event Type: `PATH_PROBE`
- **Description:** Client requested a non-existent or administrative path indicative of vulnerability scanning (`/wp-admin`, `/.env`, `/phpmyadmin`).
- **Expected Source:** Web Decoy, Reverse Proxy.
- **Required Fields:** `source_address`, `decoy_id`, `details.http.path`, `details.http.status_code="404"`.
- **Optional Fields:** `session_id`, `details.http.user_agent`.
- **Validation Rules:** Requested path must be sanitized; control characters stripped.

#### Event Type: `ANOMALOUS_REQUEST`
- **Description:** HTTP request with malformed structure, unsupported MIME types, or oversized buffers.
- **Expected Source:** Web Decoy input validation middleware.
- **Required Fields:** `source_address`, `decoy_id`, `outcome="BLOCKED"`, `details.http.status_code`.
- **Optional Fields:** `details.anomaly_reason`.
- **Validation Rules:** Request body must be discarded.

---

### 3.3 Category: COMMAND_INTERACTION

#### Event Type: `COMMAND_EXEC`
- **Description:** A shell or CLI command string was submitted to an interactive decoy terminal.
- **Expected Source:** Cowrie SSH Honeypot (`SSH-001`).
- **Required Fields:** `source_address`, `decoy_id`, `session_id`, `details.command.command_raw`, `details.command.command_category`.
- **Optional Fields:** `details.command.execution_output_simulated`.
- **Validation Rules:** Command text is treated as inert string data; never executed on the host.

---

### 3.4 Category: FILE_INTERACTION

#### Event Type: `FILE_DOWNLOAD`
- **Description:** Adversary initiated a file download from an external URL into the honeypot (e.g. via `curl`, `wget`).
- **Expected Source:** Cowrie SSH Honeypot (`SSH-001`).
- **Required Fields:** `source_address`, `decoy_id`, `session_id`, `details.file.file_name`, `details.file.file_sha256`.
- **Optional Fields:** `details.file.source_url`.
- **Validation Rules:** Downloaded artifacts must be contained in isolated quarantine with SHA-256 computed.

---

### 3.5 Category: SESSION

#### Event Type: `SESSION_START`
- **Description:** A new client session was initialized and issued a correlation identifier.
- **Expected Source:** Web Decoy, Cowrie SSH.
- **Required Fields:** `source_address`, `decoy_id`, `session_id`, `observed_at`.
- **Optional Fields:** `details.http.user_agent`.
- **Validation Rules:** `session_id` must match `^decoy_sess_[a-f0-9]{32}$`.

#### Event Type: `SESSION_END`
- **Description:** Client session terminated due to explicit logout, idle expiration, or client disconnect.
- **Expected Source:** Web Decoy, Cowrie SSH.
- **Required Fields:** `session_id`, `decoy_id`, `details.session_duration_seconds`.
- **Optional Fields:** `details.termination_reason`.
- **Validation Rules:** Duration must be a non-negative integer.

---

### 3.6 Category: SERVICE_HEALTH

#### Event Type: `DECOY_HEALTH_CHANGED`
- **Description:** Decoy service state transition (healthy, degraded, log rotation, network state).
- **Expected Source:** Decoy Heartbeat Monitor, Logger Subsystem.
- **Required Fields:** `decoy_id`, `details.health.status`, `observed_at`.
- **Optional Fields:** `details.health.component`, `details.health.error_message`.
- **Validation Rules:** Must not contain internal file paths, stack traces, or credentials.

