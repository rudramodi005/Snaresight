# Observed Source Profile Data Model

## Relational Schema Specifications

The Source Intelligence Subsystem introduces 5 dedicated PostgreSQL tables registered with `Base.metadata`.

---

### 1. `source_profiles` (`SourceProfileModel`)
Primary persistent profile representing an observed network source.

| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | UUID | No | Primary Key |
| `profile_id` | VARCHAR(64) | No | Unique stable identifier (`PROF-...`) |
| `display_label` | VARCHAR(128) | No | Standardized label: `Observed Source Profile: <IP>` |
| `source_ip` | VARCHAR(45) | No | Canonical IPv4 or IPv6 address |
| `ip_family` | VARCHAR(10) | No | `IPv4` or `IPv6` (Check Constraint) |
| `fingerprint` | VARCHAR(64) | No | Deterministic SHA-256 fingerprint token |
| `first_observed_at`| TIMESTAMPTZ | No | Timestamp of earliest observed activity |
| `last_observed_at` | TIMESTAMPTZ | No | Timestamp of latest observed activity |
| `total_sessions` | INTEGER | No | Total correlated activity sessions |
| `total_events` | INTEGER | No | Total security events |
| `total_alerts` | INTEGER | No | Total alerts triggered |
| `distinct_categories`| INTEGER | No | Count of distinct event categories |
| `distinct_honeypots` | INTEGER | No | Count of distinct honeypot decoys targeted |
| `protocol_distribution`| JSONB | No | Frequency count per protocol (e.g. `{"SSH": 15, "HTTP": 3}`) |
| `behavioral_summary` | JSONB | No | High-level behavioral attributes and rationale |
| `profile_priority` | VARCHAR(20) | No | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `INSUFFICIENT_DATA` |
| `profile_status` | VARCHAR(20) | No | `ACTIVE`, `DORMANT`, `ARCHIVED` |
| `is_shared_infrastructure` | BOOLEAN | No | Flag indicating shared NAT / proxy / VPN gateway |
| `analyst_notes_count` | INTEGER | No | Total analyst notes attached |
| `version` | INTEGER | No | Monotonically increasing schema/aggregation version |
| `last_aggregated_at` | TIMESTAMPTZ | No | Timestamp of last aggregation execution |
| `created_at` | TIMESTAMPTZ | No | Record creation timestamp |
| `updated_at` | TIMESTAMPTZ | Yes | Record last update timestamp |

---

### 2. `source_profile_sessions` (`SourceProfileSessionModel`)
Relational junction linking observed source profiles to correlated activity sessions.

| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | UUID | No | Primary Key |
| `profile_id` | VARCHAR(64) | No | Foreign Key -> `source_profiles.profile_id` (CASCADE) |
| `session_id` | VARCHAR(64) | No | Foreign Key -> `activity_sessions.session_id` (CASCADE) |
| `associated_at` | TIMESTAMPTZ | No | Timestamp when association was created |
| `confidence_score` | SMALLINT | No | Association confidence score (0–100, default 100) |
| `association_type`| VARCHAR(32) | No | `DIRECT_IP`, `FINGERPRINT`, `ANALYST_MERGED`, `SUBNET_PROXIMITY` |
| `is_active` | BOOLEAN | No | Active association status flag |

---

### 3. `source_profile_features` (`SourceProfileFeatureModel`)
Multi-window behavioral metrics and baseline statistics.

| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | UUID | No | Primary Key |
| `profile_id` | VARCHAR(64) | No | Foreign Key -> `source_profiles.profile_id` (CASCADE) |
| `window_type` | VARCHAR(16) | No | `1H`, `24H`, `7D`, `30D`, `ALL_TIME` (Check Constraint) |
| `window_start` | TIMESTAMPTZ | Yes | Beginning of the window interval |
| `window_end` | TIMESTAMPTZ | Yes | End of the window interval |
| `interaction_tempo`| FLOAT | No | Events per active minute |
| `burstiness_ratio` | FLOAT | No | Peak 1-minute rate vs average rate |
| `concurrency_level`| INTEGER | No | Max simultaneous active sessions |
| `auth_attempt_count`| INTEGER | No | Total authentication attempts |
| `auth_failure_count`| INTEGER | No | Failed authentication attempts |
| `distinct_usernames_count`| INTEGER | No | Unique usernames tested |
| `path_traversal_probes` | INTEGER | No | Count of traversal / command probe events |
| `distinct_paths_probed` | INTEGER | No | Count of unique URIs / paths explored |
| `distinct_honeypots_targeted` | INTEGER | No | Unique decoys contacted in this window |
| `tactic_distribution` | JSONB | No | MITRE tactic frequencies |
| `technique_distribution` | JSONB | No | MITRE technique frequencies |
| `severity_breakdown` | JSONB | No | Alert count by severity tier |
| `calculated_at` | TIMESTAMPTZ | No | Timestamp of calculation |

---

### 4. `source_profile_history` (`SourceProfileHistoryModel`)
Immutable audit log tracking analyst notes, reviews, and status adjustments.

| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | UUID | No | Primary Key |
| `profile_id` | VARCHAR(64) | No | Foreign Key -> `source_profiles.profile_id` (CASCADE) |
| `action` | VARCHAR(64) | No | `ANALYST_NOTE`, `ASSOCIATION_REVIEW`, `PRIORITY_CHANGED`, etc. |
| `analyst_id` | VARCHAR(64) | Yes | Identifier of investigating analyst |
| `previous_value` | JSONB | Yes | State before modification |
| `new_value` | JSONB | Yes | State after modification |
| `notes` | TEXT | Yes | Investigation rationale or commentary |
| `created_at` | TIMESTAMPTZ | No | Timestamp of change |

---

### 5. `source_profile_recurrences` (`SourceProfileRecurrenceModel`)
Tracks return events when a source re-engages after an extended dormancy period.

| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | UUID | No | Primary Key |
| `profile_id` | VARCHAR(64) | No | Foreign Key -> `source_profiles.profile_id` (CASCADE) |
| `dormant_interval_seconds` | INTEGER | No | Inactive duration in seconds |
| `dormant_interval_display` | VARCHAR(64) | No | Human-readable duration (e.g. `3d 14h`) |
| `reactivation_at` | TIMESTAMPTZ | No | Timestamp of returning session |
| `reactivation_session_id` | VARCHAR(64) | No | Identifier of new session |
| `pattern_similarity` | FLOAT | No | Similarity of reactivation pattern to baseline (0.0–1.0) |
| `summary` | TEXT | No | Human-readable recurrence summary |
| `created_at` | TIMESTAMPTZ | No | Timestamp of detection |

