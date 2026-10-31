# SnareSight — Relational Table Specifications

**Document ID:** `SNARESIGHT-DB-TABLES-001`  
**Phase:** 3 — Event Pipeline and Database  
**Classification:** Confidential — Internal Cybersecurity Engineering  
**Authority:** Principal Database Architect & Data Modeler  

---

## 1. Table Catalog & Schema Mapping

The following 12 relational tables form the approved persistence foundation for SnareSight Phase 3, mapped strictly from the P11 data contracts:

---

### Table 1: `honeypots`
Registers deployed decoy instances and tracks their lifecycle.
```sql
CREATE TABLE honeypots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    decoy_id VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(128) NOT NULL,
    decoy_type VARCHAR(64) NOT NULL,       -- 'WEB_LOGIN', 'COWRIE_SSH', etc.
    protocol VARCHAR(16) NOT NULL,         -- 'HTTP', 'HTTPS', 'SSH'
    environment VARCHAR(32) NOT NULL,      -- 'isolated_lab', 'production'
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE', -- 'ACTIVE', 'MAINTENANCE', 'RETIRED'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

### Table 2: `event_sources`
Identifies collector agents, forwarders, and ingestion points.
```sql
CREATE TABLE event_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id VARCHAR(64) UNIQUE NOT NULL,
    source_type VARCHAR(64) NOT NULL,      -- 'LOCAL_FILE_WATCHER', 'HTTP_COLLECTOR'
    source_name VARCHAR(128) NOT NULL,
    environment VARCHAR(32) NOT NULL,
    schema_version VARCHAR(16) NOT NULL DEFAULT '1.0',
    status VARCHAR(32) NOT NULL DEFAULT 'ONLINE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

### Table 3: `raw_events`
Stores privacy-sanitized original telemetry lines for evidentiary preservation.
```sql
CREATE TABLE raw_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    raw_event_id UUID UNIQUE NOT NULL,
    schema_version VARCHAR(16) NOT NULL DEFAULT '1.0',
    event_type VARCHAR(64) NOT NULL,
    event_category VARCHAR(64) NOT NULL,
    decoy_id VARCHAR(64) NOT NULL REFERENCES honeypots(decoy_id) ON DELETE RESTRICT,
    event_source_id VARCHAR(64) NOT NULL,
    session_id VARCHAR(64) NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sanitized_payload JSONB NOT NULL,     -- Complete sanitized raw event object
    provenance JSONB NOT NULL,            -- source_type, environment, simulation_run_id
    validation_status VARCHAR(32) NOT NULL DEFAULT 'VALID',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

### Table 4: `security_events`
Authoritative normalized security event repository for detection and correlation.
```sql
CREATE TABLE security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID UNIQUE NOT NULL,
    raw_event_id UUID NOT NULL REFERENCES raw_events(raw_event_id) ON DELETE RESTRICT,
    schema_version VARCHAR(16) NOT NULL DEFAULT '1.0',
    event_type VARCHAR(64) NOT NULL,
    event_category VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,
    outcome VARCHAR(16) NOT NULL,          -- 'SUCCESS', 'FAILURE', 'BLOCKED', 'ERROR'
    decoy_id VARCHAR(64) NOT NULL REFERENCES honeypots(decoy_id) ON DELETE RESTRICT,
    session_id VARCHAR(64) NOT NULL,
    observed_source_id VARCHAR(64),
    source_address VARCHAR(45) NOT NULL,
    source_port INTEGER,
    source_protocol VARCHAR(16) NOT NULL,
    target_service VARCHAR(32) NOT NULL,
    target_port INTEGER NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    normalized_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sanitized_metadata JSONB NOT NULL,     -- details (auth, http, command)
    provenance JSONB NOT NULL,
    processing_status VARCHAR(32) NOT NULL DEFAULT 'PROCESSED',
    deduplication_reference CHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

### Table 5: `sessions`
Honeypot visitor interaction sessions.
```sql
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id VARCHAR(64) UNIQUE NOT NULL,
    decoy_id VARCHAR(64) NOT NULL REFERENCES honeypots(decoy_id) ON DELETE RESTRICT,
    source_address VARCHAR(45) NOT NULL,
    user_agent_summary VARCHAR(256),
    started_at TIMESTAMPTZ NOT NULL,
    last_activity_at TIMESTAMPTZ NOT NULL,
    ended_at TIMESTAMPTZ,
    provenance JSONB NOT NULL,
    session_status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE', -- 'ACTIVE', 'EXPIRED', 'TERMINATED'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

### Table 6: `detection_rules`
Active and historical behavioral detection rule configurations.
```sql
CREATE TABLE detection_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id VARCHAR(64) UNIQUE NOT NULL,
    rule_name VARCHAR(128) NOT NULL,
    rule_version VARCHAR(16) NOT NULL,
    description TEXT NOT NULL,
    category VARCHAR(64) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    severity VARCHAR(16) NOT NULL,          -- 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    configuration JSONB NOT NULL,           -- Thresholds, window size, markers
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

### Table 7: `alerts`
Actionable security findings produced by the detection and correlation engines.
```sql
CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID UNIQUE NOT NULL,
    schema_version VARCHAR(16) NOT NULL DEFAULT '1.0',
    detection_rule_id VARCHAR(64) NOT NULL REFERENCES detection_rules(rule_id) ON DELETE RESTRICT,
    detection_rule_version VARCHAR(16) NOT NULL,
    title VARCHAR(128) NOT NULL,
    summary TEXT NOT NULL,
    severity VARCHAR(16) NOT NULL,          -- 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    confidence SMALLINT NOT NULL CHECK (confidence >= 0 AND confidence <= 100),
    assessment_status VARCHAR(32) NOT NULL DEFAULT 'NEW', -- 'NEW', 'TRIAGED', 'RESOLVED'
    evidence_strength VARCHAR(32) NOT NULL, -- 'DEFINITIVE', 'CORROBORATED', 'HEURISTIC'
    source_address VARCHAR(45) NOT NULL,
    observed_source_id VARCHAR(64) NOT NULL,
    decoy_id VARCHAR(64) NOT NULL REFERENCES honeypots(decoy_id) ON DELETE RESTRICT,
    target_service VARCHAR(32) NOT NULL,
    first_observed_at TIMESTAMPTZ NOT NULL,
    last_observed_at TIMESTAMPTZ NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ,
    detection_explanation TEXT NOT NULL,
    recommendations JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

### Table 8: `alert_evidence`
Many-to-many junction table linking supporting security events to alerts.
```sql
CREATE TABLE alert_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    event_id UUID NOT NULL REFERENCES security_events(event_id) ON DELETE RESTRICT,
    evidence_role VARCHAR(64) NOT NULL DEFAULT 'TRIGGERING_OBSERVATION',
    evidence_summary TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_alert_event UNIQUE (alert_id, event_id)
);
```

---

### Table 9: `simulation_runs`
Tracks controlled tests and demonstration scenario executions.
```sql
CREATE TABLE simulation_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    simulation_run_id VARCHAR(64) UNIQUE NOT NULL,
    scenario_id VARCHAR(64) NOT NULL,
    source_type VARCHAR(64) NOT NULL DEFAULT 'CONTROLLED_TEST',
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    status VARCHAR(32) NOT NULL DEFAULT 'RUNNING',
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

### Table 10: `observed_sources`
Pseudonymous aggregated profiles of observed source endpoints.
```sql
CREATE TABLE observed_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id VARCHAR(64) UNIQUE NOT NULL, -- 'src_profile_...'
    source_address VARCHAR(45) NOT NULL,
    source_identity_type VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN',
    first_observed_at TIMESTAMPTZ NOT NULL,
    last_observed_at TIMESTAMPTZ NOT NULL,
    observation_count INTEGER NOT NULL DEFAULT 1,
    provenance JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

### Table 11: `attack_techniques`
Local catalog of MITRE ATT&CK techniques.
```sql
CREATE TABLE attack_techniques (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    technique_id VARCHAR(16) UNIQUE NOT NULL, -- 'T1110.001'
    technique_name VARCHAR(128) NOT NULL,
    tactic_id VARCHAR(16) NOT NULL,          -- 'TA0006'
    tactic_name VARCHAR(64) NOT NULL,
    framework_version VARCHAR(16) NOT NULL DEFAULT 'v14.1',
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

### Table 12: `technique_mappings`
Evidence-backed mappings associating security events or alerts with ATT&CK techniques.
```sql
CREATE TABLE technique_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID REFERENCES security_events(event_id) ON DELETE CASCADE,
    alert_id UUID REFERENCES alerts(alert_id) ON DELETE CASCADE,
    technique_id VARCHAR(16) NOT NULL REFERENCES attack_techniques(technique_id) ON DELETE RESTRICT,
    mapping_confidence SMALLINT NOT NULL CHECK (mapping_confidence >= 0 AND mapping_confidence <= 100),
    mapping_rationale TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_target_exists CHECK (event_id IS NOT NULL OR alert_id IS NOT NULL)
);
```

