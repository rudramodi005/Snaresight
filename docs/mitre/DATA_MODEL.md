# SnareSight MITRE ATT&CK Relational Data Model

## 1. Entity Relationship Diagram

```mermaid
erDiagram
    ATTACK_DATASET_VERSIONS ||--o{ ATTACK_IMPORT_RUNS : "initiates"
    ATTACK_DATASET_VERSIONS ||--o{ ATTACK_TACTICS : "contains"
    ATTACK_DATASET_VERSIONS ||--o{ ATTACK_TECHNIQUES : "contains"
    ATTACK_DATASET_VERSIONS ||--o{ ATTACK_SUBTECHNIQUES : "contains"
    ATTACK_DATASET_VERSIONS ||--o{ ATTACK_RELATIONSHIPS : "contains"
    
    ATTACK_TECHNIQUES ||--o{ ATTACK_SUBTECHNIQUES : "parents"
    ATTACK_TECHNIQUES ||--o{ TECHNIQUE_MAPPINGS : "referenced_by"

    ATTACK_DATASET_VERSIONS {
        uuid id PK
        string domain
        string version
        string stix_version
        string source_repo
        string source_filename
        timestamp retrieval_date
        timestamp release_date
        string sha256_checksum
        boolean is_active
        string status
        int object_count
        timestamp created_at
    }

    ATTACK_TACTICS {
        uuid id PK
        string tactic_id UK
        string stix_id
        string name
        string short_name
        text description
        string external_url
        int display_order
        boolean is_deprecated
        string dataset_version
        timestamp created_at
        timestamp updated_at
    }

    ATTACK_TECHNIQUES {
        uuid id PK
        string technique_id UK
        string stix_id
        string name
        text description
        json platforms
        json tactics
        json data_sources
        boolean is_subtechnique
        boolean is_deprecated
        boolean is_revoked
        string revoked_by
        string detection_guidance
        string external_url
        string dataset_version
        timestamp created_at
        timestamp updated_at
    }

    ATTACK_SUBTECHNIQUES {
        uuid id PK
        string subtechnique_id UK
        string parent_technique_id FK
        string stix_id
        string parent_stix_id
        string name
        text description
        json platforms
        json tactics
        boolean is_deprecated
        boolean is_revoked
        string revoked_by
        string detection_guidance
        string external_url
        string dataset_version
        timestamp created_at
        timestamp updated_at
    }

    ATTACK_RELATIONSHIPS {
        uuid id PK
        string relationship_id UK
        string source_stix_id
        string relationship_type
        string target_stix_id
        text description
        string dataset_version
        timestamp created_at
    }

    ATTACK_IMPORT_RUNS {
        uuid id PK
        string dataset_version
        string source_filename
        string sha256_checksum
        string status
        int total_parsed
        int total_accepted
        int total_rejected
        int total_added
        int total_updated
        int total_unchanged
        int total_deprecated
        int total_revoked
        float duration_seconds
        string initiated_by
        text error_message
        timestamp started_at
        timestamp completed_at
    }
```

---

## 2. Table Specifications

### 2.1 `attack_dataset_versions`
Stores metadata and state transitions for each imported ATT&CK release.
- **`id`** (`UUID`, Primary Key): Internal unique identifier.
- **`domain`** (`VARCHAR(64)`): Domain identifier, default `enterprise-attack`.
- **`version`** (`VARCHAR(32)`): ATT&CK release string, e.g. `14.1`.
- **`stix_version`** (`VARCHAR(16)`): Standard specification version (`2.1`).
- **`sha256_checksum`** (`VARCHAR(64)`): Cryptographic hash verifying bundle integrity.
- **`is_active`** (`BOOLEAN`): Single active version flag per domain used for current detections.
- **`status`** (`VARCHAR(32)`): Lifecycle stage (`ACTIVE`, `SUPERSEDED`, `REJECTED`, `ARCHIVED`).
- **`object_count`** (`INTEGER`): Total tactics, techniques, subtechniques, and relationships imported.

### 2.2 `attack_tactics`
Matrix tactics representing adversary tactical goals.
- **`tactic_id`** (`VARCHAR(32)`, Unique): Official ATT&CK ID (e.g. `TA0001`, `TA0006`).
- **`stix_id`** (`VARCHAR(128)`): STIX object ID (`x-mitre-tactic--*`).
- **`name`** (`VARCHAR(128)`): Human-readable tactic name (`Initial Access`, `Credential Access`).
- **`short_name`** (`VARCHAR(64)`): STIX shortname used in `kill_chain_phases` (`initial-access`, `credential-access`).
- **`display_order`** (`INTEGER`): Canonical Enterprise matrix order (1 through 14).

### 2.3 `attack_techniques`
Primary ATT&CK techniques. Fully backward-compatible with Phase 3/P11 schema (`id`, `technique_id`, `name`, `tactics`, `description`).
- **`technique_id`** (`VARCHAR(32)`, Unique): Official identifier (e.g. `T1110`, `T1078`).
- **`stix_id`** (`VARCHAR(128)`): STIX object ID (`attack-pattern--*`).
- **`platforms`** (`JSONB/JSON`): Targeted operating systems and environments (`["Linux", "Windows", "macOS"]`).
- **`tactics`** (`JSONB/JSON`): Associated tactic short names (`["credential-access"]`).
- **`data_sources`** (`JSONB/JSON`): Telemetry data sources providing evidence.
- **`is_subtechnique`** (`BOOLEAN`): Flag indicating if object is a parent or sub-technique.
- **`is_deprecated`** / **`is_revoked`** (`BOOLEAN`): Lifecycle status within ATT&CK.

### 2.4 `attack_subtechniques`
Granular adversary actions representing concrete procedural variations of a technique.
- **`subtechnique_id`** (`VARCHAR(32)`, Unique): Subtechnique ID (e.g. `T1110.001`, `T1078.001`).
- **`parent_technique_id`** (`VARCHAR(32)`, Foreign Key -> `attack_techniques.technique_id`): Parent technique identifier.
- **`parent_stix_id`** (`VARCHAR(128)`): STIX ID of parent `attack-pattern`.

### 2.5 `attack_relationships`
STIX 2.1 relationships between ATT&CK entities (`subtechnique-of`, etc.).

### 2.6 `attack_import_runs`
Audit and operational log of every import, dry-run preview, and rollback operation.

