# SnareSight — Event Data Contracts Architecture

**Document ID:** `SNARESIGHT-ARCH-CONTRACTS-001`  
**Classification:** Confidential — Internal Cybersecurity Engineering  
**Authority:** Principal Software Architect & Principal Data Architect  

---

## 1. Architectural Scope & The Three-Schema Paradigm

A fundamental architectural principle of SnareSight is the **Strict Separation of Concerns** across the event data pipeline. Rather than forcing all operational, evidentiary, and detection fields into a single monolithic record, the platform enforces three distinct primary data contracts:

```
+---------------------------------------------------------------------------------+
|                                 SNARESIGHT PIPELINE                             |
+---------------------------------------------------------------------------------+
|  1. RAW EVENT CONTRACT (Evidentiary Preservation)                              |
|     - Captures original decoy observation.                                      |
|     - Preserves source-specific syntax (HTTP, SSH, SMB).                        |
|     - Enforces Zero Password Persistence at point of ingestion.                 |
+---------------------------------------+-----------------------------------------+
                                        | Transforms via Ingestion Normalizer
                                        v
+---------------------------------------------------------------------------------+
|  2. NORMALIZED EVENT CONTRACT (Universal Analytics & Detection Baseline)        |
|     - Decoy-agnostic taxonomy (AUTHENTICATION, REQUEST, COMMAND_INTERACTION).    |
|     - Normalized timestamps, outcome enums, and structured service details.     |
|     - Consumed by Detection Rules, Attack Chain Correlator, and Metrics Engine. |
+---------------------------------------+-----------------------------------------+
                                        | Evaluated by Detection Engine
                                        v
+---------------------------------------------------------------------------------+
|  3. SECURITY ALERT CONTRACT (Actionable Incident Finding)                       |
|     - Evidence-backed security finding linked to supporting event IDs.          |
|     - Independent Severity (Impact) and Confidence (Certainty) scoring.         |
|     - MITRE ATT&CK association & human-in-the-loop defensive recommendations.   |
+---------------------------------------------------------------------------------+
```

---

## 2. Responsibilities & Separation Matrix

| Architectural Dimension | Raw Event Contract | Normalized Event Contract | Security Alert Contract |
| :--- | :--- | :--- | :--- |
| **Primary Consumer** | Event Ingestion Worker, Forensic Auditor | Detection Rule Engine, Correlation Engine | SOC Analyst, Realtime Dashboard UI, Incident Responder |
| **Data Mutability** | Strictly Immutable (Append-Only) | Immutable | Mutable Status Lifecycle (`NEW` -> `RESOLVED`) |
| **Format Dependency** | Reflects originating honeypot | 100% Vendor/Decoy Agnostic | Detection Rule Agnostic |
| **Volume Expectations** | High (Every interaction captured) | High (1:1 with valid Raw Events) | Low to Moderate (Triggered on thresholds) |
| **Sensitive Protection** | Passwords stripped; Usernames hashed | Zero credentials; Hashes preserved | Aggregated metadata only |
| **Storage Placement** | High-throughput append log / JSONB | Partitioned Relational Database | Relational Database with Junction Tables |

---

## 3. SOC Dashboard Metric Compatibility

The data contracts are engineered to directly power the SOC dashboard without custom aggregation tables:

| Planned SOC Dashboard Metric | Authoritative Contract | Query Source Fields |
| :--- | :--- | :--- |
| **Total Event Volume** | Normalized Event | `COUNT(event_id)` |
| **Events by Category** | Normalized Event | `GROUP BY event_category` |
| **Events by Honeypot Decoy** | Normalized Event | `GROUP BY decoy_id` |
| **Events by Provenance** | Normalized Event | `GROUP BY provenance.source_type` |
| **Active Visitor Sessions** | Normalized Event | `COUNT(DISTINCT session_id) WHERE observed_at >= NOW() - INTERVAL '30m'` |
| **Total Security Alerts** | Security Alert | `COUNT(alert_id)` |
| **Alerts by Severity** | Security Alert | `GROUP BY severity` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) |
| **Alerts by Lifecycle Status**| Security Alert | `GROUP BY assessment_status` (`NEW`, `TRIAGED`, `RESOLVED`) |
| **Top Targeted Decoys** | Security Alert | `GROUP BY decoy_id ORDER BY count DESC` |
| **Observed Source Threat Ranking**| Security Alert | `GROUP BY observed_source_id, source_address ORDER BY COUNT(alert_id) DESC` |
| **MITRE ATT&CK Heatmap** | Security Alert | `GROUP BY mitre_attack.technique_id, mitre_attack.tactic_id` |
| **Attack Chain DAG** | Security Alert | Query `attack_chain_id` with linked `related_event_ids` |

