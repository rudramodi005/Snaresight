# SnareSight — Normalized Security Event Schema Specification

**Document ID:** `SNARESIGHT-SCHEMA-NORM-001`  
**Schema Version:** `1.0`  
**Classification:** Confidential — Internal Cybersecurity Engineering  
**Authority:** Principal Data Architect & Detection Systems Engineer  

---

## 1. Purpose & Core Responsibilities

The **Normalized Security Event Schema** represents validated, standardized security activity across the SnareSight platform. Regardless of whether an event originates from a web authentication portal (`WEB-001`), an interactive SSH/Telnet honeypot (`SSH-001` Cowrie), or an operational SMB decoy, it is transformed into this common contract.

The Normalized Event is the **authoritative data contract** consumed by:
1. **Detection Rule Engine:** Evaluates behavioral threshold and signature rules.
2. **Correlation Engine:** Links sequential events into multi-stage attack chains.
3. **MITRE ATT&CK Mapper:** Associates validated observations with adversary techniques.
4. **SOC Dashboard Analytics:** Aggregates metrics, trends, and source timelines.

```
+-----------------------------------+
|            Raw Events             |
| (Web Decoy, Cowrie, Network Probes)|
+-----------------+-----------------+
                  |
                  v [Event Ingestion & Normalization Pipeline]
+-----------------------------------+
|     Normalized Security Event     | <--- Universal Detection Engine Baseline
|          (Version 1.0)            |      Strict Vendor/Decoy Agnostic Format
+-----------------+-----------------+
                  |
       +----------+----------+
       v                     v
+--------------+      +--------------+
|  Detection   |      | Correlation  |
| Rule Engine  |      | Attack Chains|
+--------------+      +--------------+
```

---

## 2. Invariant Design Principles

1. **Decoy Independence:** Detection rules never parse raw honeypot log syntax; they query standardized fields (`event_category`, `action`, `outcome`, `source_address`).
2. **Evidentiary Traceability:** Every normalized event maintains a permanent, non-null foreign reference (`raw_event_id`) back to the originating raw record.
3. **Zero Sensitive Leakage:** No plaintext passwords or prohibited tokens are carried forward during normalization.
4. **Strict Temporal Integrity:** `observed_at` (event occurrence time) and `normalized_at` (ingestion time) are strictly separated.
5. **No Speculative Attribution:** The schema records observed facts (e.g., `outcome="FAILURE"`). It never assumes an interaction implies system compromise.

---

## 3. Comprehensive Field Definitions

### Group A: Event Identifiers
| Field Name | Type | Req | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `event_id` | UUID (string) | Yes | Internal | Primary key for this normalized event. | Valid UUIDv4 format (`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`). |
| `raw_event_id` | UUID (string) | Yes | Internal | Foreign key link to source Raw Event record. | Valid UUIDv4 format. |
| `schema_version` | String | Yes | Public | Version of normalized event contract. | Strictly `"1.0"`. |
| `event_source_id` | String | Yes | Internal | Identifier of collector or ingestion pipeline. | Max 64 chars, e.g., `"collector-web-01"`. |
| `decoy_id` | String | Yes | Internal | Honeypot identifier where event occurred. | Max 64 chars, e.g., `"WEB-001"`, `"SSH-001"`. |

### Group B: Event Classification
| Field Name | Type | Req | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `event_type` | Enum (string) | Yes | Public | Standardized event operation name. | Allowed: `PAGE_VISIT`, `AUTH_ATTEMPT`, `AUTH_FAILURE`, `AUTH_SUCCESS_MOCK`, `PATH_PROBE`, `COMMAND_EXEC`, `FILE_DOWNLOAD`, `SESSION_START`, `SESSION_END`, `ANOMALOUS_REQUEST`. |
| `event_category` | Enum (string) | Yes | Public | High-level SIEM domain category. | Allowed: `CONNECTION`, `REQUEST`, `AUTHENTICATION`, `SESSION`, `COMMAND_INTERACTION`, `FILE_INTERACTION`, `SERVICE_HEALTH`, `SECURITY_OBSERVATION`, `SIMULATION`. |
| `event_subcategory` | String | Optional | Public | Specialized behavioral grouping. | Max 64 chars, e.g., `"CREDENTIAL_BRUTE_FORCE"`, `"DIR_TRAVERSAL"`. |
| `action` | String | Yes | Public | Specific action performed by source. | Max 64 chars, e.g., `"SUBMIT_CREDENTIALS"`, `"EXECUTE_COMMAND"`, `"HTTP_GET"`. |
| `outcome` | Enum (string) | Yes | Public | Operational result of the action. | Strictly: `"SUCCESS"`, `"FAILURE"`, `"BLOCKED"`, `"ERROR"`, `"UNKNOWN"`. |

### Group C: Event Timestamps
| Field Name | Type | Req | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `observed_at` | String (ISO) | Yes | Internal | Exact UTC timestamp of interaction at decoy. | ISO-8601 UTC string (`YYYY-MM-DDTHH:MM:SS.ffffff+00:00`). |
| `received_at` | String (ISO) | Yes | Internal | UTC timestamp when collector ingested event. | ISO-8601 UTC string. |
| `normalized_at` | String (ISO) | Yes | Internal | UTC timestamp when normalization completed. | ISO-8601 UTC string (`normalized_at >= received_at >= observed_at`). |

### Group D: Source Metadata
| Field Name | Type | Req | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `source_address` | String | Yes | Sensitive | Originating network IP address. | Valid IPv4 or IPv6, or `"testclient"` in simulations. |
| `source_port` | Integer | Optional | Sensitive | Originating transport port. | Bounded `1` to `65535`. Nullable. |
| `source_protocol` | String | Yes | Public | Application protocol used by source. | Lowercase enum: `"http"`, `"https"`, `"ssh"`, `"telnet"`, `"smb"`. |
| `source_identity_type` | Enum (string) | Yes | Internal | Source address nature assessment. | Enum: `"DIRECT_IP"`, `"PROXY_IP"`, `"TOR_NODE"`, `"INTERNAL_TEST"`, `"UNKNOWN"`. |
| `observed_source_id` | String | Optional | Internal | Synthetic source actor profile identifier. | Max 64 chars, e.g., `"src_profile_a1b2c3d4"`. |

### Group E: Target Metadata
| Field Name | Type | Req | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `target_service` | String | Yes | Public | Logical service targeted by interaction. | Allowed: `"WEB_PORTAL"`, `"SSH_DAEMON"`, `"REST_API"`, `"SMB_SHARE"`. |
| `target_protocol` | String | Yes | Public | Decoy listening protocol. | Uppercase: `"HTTP"`, `"HTTPS"`, `"SSH"`, `"TCP"`. |
| `target_port` | Integer | Yes | Public | Decoy listening port. | Bounded `1` to `65535` (e.g. `8080`, `2222`). |

### Group F: Session Metadata
| Field Name | Type | Req | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `session_id` | String | Yes | Sensitive | Correlation session identifier. | Max 64 chars, regex `^decoy_sess_[a-f0-9]{32}$`. |
| `interaction_id` | String | Optional | Sensitive | Granular request identifier. | Max 64 chars. |
| `sequence_number` | Integer | Optional | Internal | Monotonic sequence number within session. | Integer `>= 1`. |
| `previous_event_id` | UUID (string) | Optional | Internal | Immediate preceding event ID in session. | Valid UUIDv4 format. Enables chain tracking. |

### Group G: Normalized Event Details
The `details` object encapsulates service-specific metadata in standardized sub-dictionaries:

| Sub-Dictionary | Field Name | Type | Sensitivity | Description |
| :--- | :--- | :--- | :--- | :--- |
| `details.auth` | `username_fingerprint` | String (hex) | Sensitive | Keyed HMAC-SHA256 hash of submitted username. |
| `details.auth` | `username_length` | Integer | Public | Character count of submitted username (`0-1024`). |
| `details.auth` | `password_present` | Boolean | Public | Whether a credential secret was submitted. |
| `details.auth` | `password_length_category` | String | Public | Bucketed length: `"none"`, `"short (<8)"`, `"medium (8-16)"`, `"long (>16)"`. |
| `details.auth` | `simulated_outcome` | String | Public | Simulated response (e.g. `"simulated_rejection"`). |
| `details.http` | `method` | String | Public | HTTP method (`"GET"`, `"POST"`, etc.). |
| `details.http` | `path` | String | Internal | Sanitized requested URI path. |
| `details.http` | `status_code` | Integer | Public | HTTP response code (`200`, `401`, `400`, `404`). |
| `details.http` | `user_agent` | String | Sensitive | Client user-agent string (max 256 chars). |
| `details.command`| `command_raw` | String | Sensitive | Inert command text submitted (for SSH/terminal). |
| `details.command`| `command_category` | String | Public | Normalized category: `"RECON"`, `"PRIV_ESC"`, `"PERSISTENCE"`. |
| `details.file` | `file_name` | String | Internal | Name of uploaded/downloaded artifact. |
| `details.file` | `file_sha256` | String | Internal | Cryptographic hash of isolated artifact. |
| `details.file` | `transfer_direction` | String | Public | `"UPLOAD"` or `"DOWNLOAD"`. |

### Group H: Provenance
| Field Name | Type | Req | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `provenance.source_type` | Enum (string) | Yes | Public | Ground-truth origin classification. | Enum: `"LIVE_HONEYPOT"`, `"CONTROLLED_TEST"`, `"SYNTHETIC_SIMULATION"`, `"IMPORTED_DATA"`. |
| `provenance.environment` | String | Yes | Public | Runtime isolation boundary. | Enum: `"ISOLATED_LAB"`, `"DEMO_SANDBOX"`, `"PRODUCTION"`. |
| `provenance.source_system` | String | Optional | Internal | Host machine or VM identifier. | Max 64 chars, e.g., `"lab-vm-01"`. |
| `provenance.collection_method`| String | Optional | Public | Ingestion transport channel. | Enum: `"FILE_WATCHER"`, `"HTTP_INGESTION"`, `"BATCH_IMPORT"`. |
| `provenance.simulation_run_id`| String | Optional | Internal | Test run identifier for audits. | Max 64 chars. |

### Group I: Processing Metadata
| Field Name | Type | Req | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `processing.validation_status` | Enum (string) | Yes | Internal | Schema validation outcome. | Enum: `"VALID"`, `"INVALID"`, `"REQUIRES_REVIEW"`, `"DUPLICATE"`, `"UNSUPPORTED_VERSION"`. |
| `processing.normalization_status`| Enum (string)| Yes | Internal | Normalization transformation result. | Enum: `"SUCCESS"`, `"PARTIAL"`, `"FAILED"`. |
| `processing.processing_version` | String | Yes | Internal | Ingestion engine release version. | E.g., `"1.0.0"`. |
| `processing.deduplication_reference`| String (hex)| Yes | Internal | SHA-256 idempotency fingerprint. | 64-char lowercase hex digest. |

