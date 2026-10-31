# Campaign Intelligence Data Model

## Schema Overview
Task P24 introduces five dedicated relational database tables within PostgreSQL (managed via SQLAlchemy and Alembic migration `p24_campaign_clusters.py`):

1. `investigation_clusters`: Top-level investigation grouping entity.
2. `cluster_memberships`: Polymorphic junction linking entities (sessions, source profiles, sequences, alerts) to clusters.
3. `cluster_evidence`: Evidentiary artifacts and observed indicators backing the cluster.
4. `cluster_relationships`: Pairwise relationships between clusters (e.g., overlapping infrastructure, similar TTPs).
5. `cluster_audit_logs`: Immutable audit trail tracking all state transitions, reviews, merges, and splits.

---

## 1. `investigation_clusters` Table

| Column Name | Type | Constraints / Defaults | Description |
|:---|:---|:---|:---|
| `id` | VARCHAR(64) | PRIMARY KEY | Unique identifier (`CLUST-...` or UUID) |
| `cluster_code` | VARCHAR(64) | UNIQUE, NOT NULL | Human-readable tracking code (e.g. `GRP-202610-001`) |
| `title` | VARCHAR(255) | NOT NULL | Descriptive title of the investigation cluster |
| `description` | TEXT | NULLABLE | Detailed technical narrative and summary |
| `lifecycle_status` | VARCHAR(32) | NOT NULL, DEFAULT `'CANDIDATE'` | `CANDIDATE`, `UNDER_REVIEW`, `ACTIVE`, `MONITORING`, `CLOSED`, `DISMISSED`, `MERGED`, `SPLIT` |
| `confidence_score` | FLOAT | NOT NULL, DEFAULT `0.5` | Calculated relationship confidence (0.0 - 1.0) |
| `confidence_level` | VARCHAR(32) | NOT NULL, DEFAULT `'MODERATE'` | `UNCONFIRMED`, `LOW`, `MODERATE`, `STRONG`, `HIGH` |
| `priority` | VARCHAR(32) | NOT NULL, DEFAULT `'MEDIUM'` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `first_seen_at` | TIMESTAMP (TZ) | NOT NULL | Earliest timestamp of any member activity |
| `last_seen_at` | TIMESTAMP (TZ) | NOT NULL | Latest timestamp of any member activity |
| `entity_counts` | JSONB | NOT NULL, DEFAULT `{}` | Counts of member sessions, profiles, sequences, alerts |
| `shared_indicators` | JSONB | NOT NULL, DEFAULT `{}` | Common IPs, ports, honeypot types, user agents |
| `mitre_tactics` | JSONB | NOT NULL, DEFAULT `[]` | Aggregated MITRE tactics across members |
| `mitre_techniques` | JSONB | NOT NULL, DEFAULT `[]` | Aggregated MITRE techniques across members |
| `merged_into_id` | VARCHAR(64) | NULLABLE, FK -> `investigation_clusters.id` | Target cluster ID if this cluster was merged |
| `split_from_id` | VARCHAR(64) | NULLABLE, FK -> `investigation_clusters.id` | Parent cluster ID if this cluster was created via split |
| `analyst_notes` | TEXT | NULLABLE | Analyst documentation and rationale |
| `assigned_to` | VARCHAR(128) | NULLABLE | Analyst username assigned to this cluster |
| `created_at` | TIMESTAMP (TZ) | NOT NULL, DEFAULT `now()` | Record creation timestamp |
| `updated_at` | TIMESTAMP (TZ) | NOT NULL, DEFAULT `now()` | Record update timestamp |

---

## 2. `cluster_memberships` Table

| Column Name | Type | Constraints / Defaults | Description |
|:---|:---|:---|:---|
| `id` | VARCHAR(64) | PRIMARY KEY | Unique identifier |
| `cluster_id` | VARCHAR(64) | NOT NULL, FK -> `investigation_clusters.id` | Associated cluster ID (Indexed) |
| `entity_type` | VARCHAR(32) | NOT NULL | `SESSION`, `SOURCE_PROFILE`, `BEHAVIORAL_SEQUENCE`, `ALERT` |
| `entity_id` | VARCHAR(128) | NOT NULL | Primary key of the member record (Indexed) |
| `association_reason` | TEXT | NOT NULL | Rationale for inclusion in cluster |
| `confidence_score` | FLOAT | NOT NULL, DEFAULT `0.5` | Degree of association confidence (0.0 - 1.0) |
| `is_primary` | BOOLEAN | NOT NULL, DEFAULT `FALSE` | Anchor/primary entity of the cluster |
| `added_by` | VARCHAR(128) | NOT NULL, DEFAULT `'SYSTEM'` | Added by system or analyst username |
| `created_at` | TIMESTAMP (TZ) | NOT NULL, DEFAULT `now()` | Membership creation timestamp |

*Unique constraint:* `(cluster_id, entity_type, entity_id)` prevents duplicate associations.

---

## 3. `cluster_evidence` Table

| Column Name | Type | Constraints / Defaults | Description |
|:---|:---|:---|:---|
| `id` | VARCHAR(64) | PRIMARY KEY | Unique identifier |
| `cluster_id` | VARCHAR(64) | NOT NULL, FK -> `investigation_clusters.id` | Associated cluster ID (Indexed) |
| `evidence_type` | VARCHAR(64) | NOT NULL | `IP_MATCH`, `PAYLOAD_HASH`, `BEHAVIORAL_SIGNATURE`, `HONEYPOT_PORT`, `CREDENTIAL_PATTERN`, `USER_AGENT` |
| `evidence_value` | TEXT | NOT NULL | The observed artifact or indicator value |
| `description` | TEXT | NOT NULL | Explanation of the evidentiary finding |
| `relevance_score` | FLOAT | NOT NULL, DEFAULT `0.5` | Evidentiary weight (0.0 - 1.0) |
| `raw_data` | JSONB | NOT NULL, DEFAULT `{}` | Contextual event/packet metadata |
| `created_at` | TIMESTAMP (TZ) | NOT NULL, DEFAULT `now()` | Evidence attachment timestamp |

---

## 4. `cluster_relationships` Table

| Column Name | Type | Constraints / Defaults | Description |
|:---|:---|:---|:---|
| `id` | VARCHAR(64) | PRIMARY KEY | Unique identifier |
| `source_cluster_id` | VARCHAR(64) | NOT NULL, FK -> `investigation_clusters.id` | Source cluster ID (Indexed) |
| `target_cluster_id` | VARCHAR(64) | NOT NULL, FK -> `investigation_clusters.id` | Target cluster ID (Indexed) |
| `relationship_type` | VARCHAR(64) | NOT NULL | `OVERLAPPING_INFRASTRUCTURE`, `SIMILAR_TTPS`, `SHARED_INDICATORS`, `TEMPORAL_CORRELATION`, `RELATED_CAMPAIGN` |
| `confidence_score` | FLOAT | NOT NULL, DEFAULT `0.5` | Association confidence (0.0 - 1.0) |
| `rationale` | TEXT | NOT NULL | Justification for linking the two clusters |
| `created_at` | TIMESTAMP (TZ) | NOT NULL, DEFAULT `now()` | Relationship creation timestamp |

---

## 5. `cluster_audit_logs` Table

| Column Name | Type | Constraints / Defaults | Description |
|:---|:---|:---|:---|
| `id` | VARCHAR(64) | PRIMARY KEY | Unique identifier |
| `cluster_id` | VARCHAR(64) | NOT NULL, FK -> `investigation_clusters.id` | Associated cluster ID (Indexed) |
| `action` | VARCHAR(64) | NOT NULL | `CREATED`, `STATUS_CHANGE`, `ANALYST_REVIEW`, `MEMBER_ADDED`, `MEMBER_REMOVED`, `MERGED`, `SPLIT`, `EVIDENCE_ADDED` |
| `previous_state` | JSONB | NULLABLE | State before mutation |
| `new_state` | JSONB | NULLABLE | State after mutation |
| `performed_by` | VARCHAR(128) | NOT NULL | Username or system component |
| `notes` | TEXT | NULLABLE | Action details or analyst comments |
| `created_at` | TIMESTAMP (TZ) | NOT NULL, DEFAULT `now()` | Immutable log timestamp |

