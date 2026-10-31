# SnareSight — Raw Event Schema Specification

**Document ID:** `SNARESIGHT-SCHEMA-RAW-001`  
**Schema Version:** `1.0`  
**Classification:** Confidential — Internal Cybersecurity Engineering  
**Authority:** Principal Data Architect & SIEM Engineering Specialist  

---

## 1. Purpose & Scope

The **Raw Event Schema** represents the first boundary of telemetry entering the SnareSight platform. Its purpose is to capture and preserve the permitted original interaction metadata received from a honeypot decoy (such as the `WEB-001` web-login honeypot or future `SSH-001` Cowrie service) in a structured, immutable, and privacy-safe format.

A Raw Event retains sufficient technical evidence to reconstruct what occurred during an interaction without persisting prohibited sensitive information such as plaintext passwords, password-derived hashes, session authentication tokens, or private secrets.

```
+--------------------------+
|  Honeypot Decoy Service  |
|  (e.g., WEB-001, SSH-001)|
+-------------+------------+
              | Emits JSONL Telemetry
              v
+--------------------------+
|     Raw Event Schema     | <--- Immutably Preserves Original Observation
|      (Version 1.0)       |      Strict Zero-Password Invariant
+-------------+------------+
              | Ingested & Validated
              v
+--------------------------+
|  Normalized Event Schema |
+--------------------------+
```

---

## 2. Inviolable Data Protection Rules

Under no circumstances does "Raw Event" signify an uninspected or unrestricted dump of network requests. The Raw Event schema strictly enforces the following data protection boundaries:

1. **Forbidden Credential Persistence:** Plaintext passwords, authentication tokens, API secrets, and private keys MUST NEVER be persisted.
2. **Forbidden Reversible Hashes:** Hashes derived directly from submitted passwords (e.g., MD5, SHA-256 of password) MUST NEVER be calculated or stored.
3. **Privacy-Preserving Identifiers:** Usernames are converted to irreversible keyed HMAC-SHA256 pseudonyms (`username_fingerprint`) using a local salt key before storage.
4. **Coarse Metadata Preservation:** Credential characteristics are reduced to safe metrics: `password_present` (boolean) and `password_length_category` (`none`, `short (<8)`, `medium (8-16)`, `long (>16)`).
5. **Request Body Sanitization:** Full POST bodies are discarded; only parsed query parameters or explicit deception fields (e.g. detected payload markers) are retained.

---

## 3. Comprehensive Field Definitions

The Raw Event is structured into eight logical field groups:

### Group A: Event Identity
| Field Name | Type | Required | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `raw_event_id` | UUID (string) | Yes | Internal | Globally unique identifier for this raw observation. | Valid UUIDv4 format (`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`). |
| `schema_version` | String | Yes | Public | Version of the raw event schema contract. | Must equal `"1.0"`. |
| `event_type` | Enum (string) | Yes | Public | Primary categorization of the captured interaction. | Must match taxonomy: `decoy_page_visited`, `login_attempt`, `simulated_decoy_access`, `invalid_request`, `session_terminated`. |
| `event_category` | Enum (string) | Yes | Public | Top-level domain category. | One of: `connection`, `request`, `authentication`, `session`, `system`. |
| `decoy_id` | String | Yes | Internal | Unique identifier of the originating honeypot. | Max 64 chars, regex `^[A-Z0-9_-]+$`, e.g., `"WEB-001"`. |
| `collector_id` | String | Optional | Internal | Identifier of the telemetry collector agent. | Max 64 chars, e.g., `"collector-node-01"`. Nullable. |

### Group B: Event Timing
| Field Name | Type | Required | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `observed_at` | String (ISO-8601) | Yes | Internal | UTC timestamp when the interaction occurred at the decoy. | Valid ISO-8601 string with UTC offset (`+00:00` or `Z`), microsecond precision permitted. |
| `received_at` | String (ISO-8601) | Optional | Internal | UTC timestamp when the collector received the event. | Valid ISO-8601 UTC. Nullable prior to ingestion. |
| `timestamp_precision` | String | Optional | Internal | Declared precision of the observation clock. | Default `"microsecond"`. Allowed: `"millisecond"`, `"microsecond"`, `"second"`. |
| `source_timezone` | String | Optional | Internal | Timezone reported by the collector host. | Default `"UTC"`. Must be valid IANA timezone string. |

### Group C: Source Information
| Field Name | Type | Required | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `source.ip_address` | String | Yes | Sensitive | Remote IP address initiating the interaction. | Valid IPv4 or IPv6 address, or `"testclient"` in controlled simulations. |
| `source.port` | Integer | Optional | Sensitive | Remote TCP/UDP port. | Bounded `1` to `65535`. Nullable if unavailable. |
| `source.protocol` | String | Optional | Public | Transport and application protocol. | Lowercase enum: `"http"`, `"https"`, `"ssh"`, `"tcp"`. |
| `source.user_agent_summary` | String | Yes | Sensitive | Sanitized client User-Agent string. | Max 256 chars. Control characters stripped. |

### Group D: Session Information
| Field Name | Type | Required | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `session_id` | String | Yes | Sensitive | Correlation key tracking multi-interaction visits. | Regex `^decoy_sess_[a-f0-9]{32}$`. |
| `interaction_id` | String | Optional | Sensitive | Sub-session sequence identifier. | Max 64 chars. Nullable. |
| `associated_request_id` | String | Optional | Internal | Tracing request ID passed via HTTP headers. | Max 64 chars. Nullable. |

### Group E: Request Information
| Field Name | Type | Required | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `request.method` | String | Yes | Public | HTTP or protocol method invoked. | Uppercase: `"GET"`, `"POST"`, `"HEAD"`, `"PUT"`, `"DELETE"`. |
| `request.path` | String | Yes | Internal | URI path requested by client. | Max 1024 chars. Must start with `"/"`. |
| `request.content_type` | String | Optional | Public | Declared MIME type of request body. | Max 128 chars, e.g., `"application/x-www-form-urlencoded"`. |
| `request.headers_summary` | Object | Optional | Sensitive | Key-value pairs of non-sensitive request headers. | Allowed keys: `accept`, `accept-language`, `host`. Forbidden: `authorization`, `cookie`. |

### Group F: Interaction Details
| Field Name | Type | Required | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `interaction.username_fingerprint` | String | Optional | Sensitive | Irreversible HMAC-SHA256 hash of submitted username. | 64-character lowercase hex string (`^[0-9a-f]{64}$`). |
| `interaction.username_length` | Integer | Optional | Public | Character count of submitted username. | Bounded `0` to `1024`. |
| `interaction.password_present` | Boolean | Yes | Public | Flag indicating if a password field was provided. | Strictly `true` or `false`. |
| `interaction.password_length_category`| Enum (string) | Optional | Public | Coarse complexity bucket. | Enum: `"none"`, `"short (<8)"`, `"medium (8-16)"`, `"long (>16)"`. |
| `interaction.status_code` | Integer | Yes | Public | HTTP response code returned by decoy. | Bounded `100` to `599`. |
| `interaction.simulated_outcome` | String | Yes | Public | High-level simulation result. | Max 64 chars, e.g., `"simulated_auth_failure"`, `"portal_rendered"`. |
| `interaction.notes` | String | Optional | Internal | Operational notes or detected attack markers. | Max 512 chars. |
| `interaction.payload_markers` | Array[String]| Optional | Sensitive | List of inert attack patterns detected. | Allowed items: `"sqli"`, `"xss"`, `"traversal"`, `"command_injection"`, `"brute_force"`. |

### Group G: Provenance
| Field Name | Type | Required | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `provenance.source_type` | Enum (string) | Yes | Public | Ground-truth classification of data origin. | Enum: `"live_honeypot"`, `"controlled_test"`, `"synthetic_simulation"`, `"imported_data"`. |
| `provenance.source_id` | String | Optional | Internal | Origin system identifier. | Max 64 chars, e.g., `"lab-vm-node-01"`. |
| `provenance.environment` | String | Yes | Public | Operational environment boundary. | Enum: `"isolated_lab"`, `"demo_sandbox"`, `"production"`. |
| `provenance.collection_method` | String | Optional | Public | Method used to ingest the event. | Enum: `"local_file_tail"`, `"syslog"`, `"http_push"`, `"manual_import"`. |
| `provenance.simulation_run_id` | String | Optional | Internal | Trace ID for test and demo executions. | Max 64 chars. Required if `source_type == "controlled_test"`. |

### Group H: Processing Metadata
| Field Name | Type | Required | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `processing.ingestion_status` | Enum (string) | Optional | Internal | Ingestion pipeline state. | Enum: `"pending"`, `"ingested"`, `"failed"`. |
| `processing.validation_status` | Enum (string) | Optional | Internal | Schema validation result. | Enum: `"valid"`, `"invalid"`, `"requires_review"`. |
| `processing.processing_timestamp`| String (ISO) | Optional | Internal | UTC timestamp of pipeline execution. | Valid ISO-8601 UTC. |
| `processing.deduplication_hash` | String | Optional | Internal | SHA-256 fingerprint of canonical event fields. | 64-character lowercase hex string. |

---

## 4. Discarded Fields & Rationale

| Discarded Information | Technical & Security Rationale |
| :--- | :--- |
| **Plaintext Password** | Prevents SnareSight storage from becoming a credential liability or harvesting database. |
| **Password Hashes (MD5/SHA)** | Password hashes can be cracked using offline rainbow tables or dictionary attacks. |
| **Full HTTP Request Body** | May contain dangerous executable binary payloads, unparsed secrets, or buffer-overflow vectors. |
| **Client Session Cookies** | Real session cookies or tokens from third-party sites must never be captured or replayed. |
| **Authorization Headers** | `Authorization: Bearer <token>` or `Basic <base64>` contains raw secrets that must be dropped. |

---

## 5. Backward Compatibility with Phase 2 (P09/P10)

The P09/P10 web decoy generated events using the `DecoyEvent` Pydantic model with fields:
`schema_version`, `event_id`, `event_type`, `observed_at`, `decoy_id`, `session_id`, `source`, `request`, `interaction`, `provenance`.

The Raw Event Schema (v1.0) achieves **100% backward compatibility** through the following mapping:
1. `event_id` in P09 is mapped directly to `raw_event_id`.
2. `source`, `request`, `interaction`, and `provenance` sub-objects match the P09 schema keys exactly.
3. Added fields (`event_category`, `collector_id`, `received_at`, `processing`) are optional with deterministic defaults, allowing older P09 JSONL records to be ingested without modification or data loss.

