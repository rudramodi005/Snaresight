# SnareSight — Security Alert Schema Specification

**Document ID:** `SNARESIGHT-SCHEMA-ALERT-001`  
**Schema Version:** `1.0`  
**Classification:** Confidential — Internal Cybersecurity Engineering  
**Authority:** Principal Cybersecurity Architect & SOC Detection Specialist  

---

## 1. Purpose & Scope

The **Security Alert Schema** defines the data contract for suspicious activities, security anomalies, and adversary behaviors identified by the SnareSight Detection and Correlation Engines.

An alert does not represent raw telemetry; it represents an **evidence-backed security finding**. Every alert must be explainable, actionable, traceable to concrete supporting normalized events, and accompanied by defensive recommendations requiring SOC analyst approval.

```
+-----------------------------------+
|     Normalized Security Events    |
| (Streamed or Correlated Batches)  |
+-----------------+-----------------+
                  |
                  v [Detection Rules / Thresholds / Multi-Stage Correlation]
+-----------------------------------+
|       Security Alert Schema       | <--- Actionable finding presented to SOC Analyst
|           (Version 1.0)           |      Explainable, Evidence-Backed, MITRE Mapped
+-----------------+-----------------+
                  |
       +----------+----------+
       v                     v
+--------------+      +--------------+
| SOC Dashboard|      | Investigation|
| Realtime UI  |      | Attack Chains|
+--------------+      +--------------+
```

---

## 2. Invariant Design Principles

1. **Independent Severity & Confidence:** Severity (potential impact) and Confidence (evidence certainty) are maintained as separate fields. High severity does not imply high confidence.
2. **Strict Evidence Provenance:** An alert MUST reference one or more valid `related_event_ids`. Speculative alerts without underlying telemetry are strictly prohibited.
3. **Evidence-Backed ATT&CK Association:** MITRE ATT&CK techniques are attached only when explicit evidentiary conditions are satisfied. Generic tags are prohibited.
4. **Analyst Workflow Traceability:** State transitions (`NEW` -> `TRIAGED` -> `ESCALATED` -> `RESOLVED`) are recorded with timestamps and assigned analyst identifiers.
5. **Human-in-the-Loop Response:** Automated response recommendations carry `response_approval_required=true` by default to prevent accidental denial-of-service.

---

## 3. Comprehensive Field Definitions

### Group A: Alert Identity
| Field Name | Type | Req | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `alert_id` | UUID (string) | Yes | Internal | Globally unique identifier for this alert. | Valid UUIDv4 format (`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`). |
| `alert_schema_version` | String | Yes | Public | Version of alert contract. | Strictly `"1.0"`. |
| `alert_type` | String | Yes | Public | Standardized detection rule type. | Uppercase identifier, e.g., `"BRUTE_FORCE_BURST"`, `"CREDENTIAL_STUFFING"`, `"SUSPICIOUS_PATH_SCAN"`. |
| `title` | String | Yes | Public | Clear, concise SOC headline. | Max 128 characters. Plain text. |
| `summary` | String | Yes | Public | Human-readable explanation of detected behavior. | Max 512 characters. |

### Group B: Detection Information
| Field Name | Type | Req | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `detection_rule_id` | String | Yes | Internal | Unique identifier of triggering detection rule. | Regex `^RULE-[A-Z0-9_-]+$`, e.g., `"RULE-AUTH-001"`. |
| `detection_rule_version`| String | Yes | Internal | Semantic version of active detection rule. | Semantic version format, e.g., `"1.2.0"`. |
| `detection_category` | Enum (string) | Yes | Public | High-level threat category. | Enum: `"BRUTE_FORCE"`, `"RECONNAISSANCE"`, `"CREDENTIAL_STUFFING"`, `"COMMAND_INJECTION"`, `"DIRECTORY_TRAVERSAL"`, `"ANOMALOUS_PROBE"`, `"PERSISTENCE"`. |
| `detection_explanation` | String | Yes | Public | Detailed architectural rationale for alert trigger. | Explains why the observed pattern is malicious. |

### Group C: Threat Assessment
| Field Name | Type | Req | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `severity` | Enum (string) | Yes | Public | Potential operational impact level. | Strictly: `"INFO"`, `"LOW"`, `"MEDIUM"`, `"HIGH"`, `"CRITICAL"`. |
| `confidence` | Integer | Yes | Public | Certainty score based on evidence strength. | Bounded integer `0` to `100`. |
| `assessment_status` | Enum (string) | Yes | Internal | Lifecycle triage status of the alert. | Enum: `"NEW"`, `"TRIAGED"`, `"ESCALATED"`, `"CONTAINED"`, `"FALSE_POSITIVE"`, `"RESOLVED"`, `"CLOSED"`. |
| `evidence_strength` | Enum (string) | Yes | Public | Evidentiary corroboration category. | Enum: `"DEFINITIVE"`, `"CORROBORATED"`, `"INDICATIVE"`, `"HEURISTIC"`. |

### Group D: Source and Target
| Field Name | Type | Req | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `observed_source_id` | String | Yes | Sensitive | Synthetic actor profile grouping related sessions. | Max 64 chars, e.g., `"src_profile_98765"`. |
| `source_address` | String | Yes | Sensitive | Primary remote IP associated with alert. | Valid IPv4 or IPv6 address. |
| `decoy_id` | String | Yes | Internal | Primary honeypot service targeted. | Max 64 chars, e.g., `"WEB-001"`. |
| `target_service` | String | Yes | Public | Targeted protocol or decoy application. | E.g., `"WEB_PORTAL"`, `"SSH_DAEMON"`. |

### Group E: Time Information
| Field Name | Type | Req | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `first_observed_at` | String (ISO) | Yes | Internal | UTC timestamp of earliest supporting event. | Valid ISO-8601 UTC string. |
| `last_observed_at` | String (ISO) | Yes | Internal | UTC timestamp of most recent supporting event. | Valid ISO-8601 UTC string (`last_observed_at >= first_observed_at`). |
| `generated_at` | String (ISO) | Yes | Internal | UTC timestamp when alert was generated. | Valid ISO-8601 UTC string. |
| `updated_at` | String (ISO) | Yes | Internal | UTC timestamp of latest status update or event merge.| Valid ISO-8601 UTC string. |

### Group F: Related Activity & Attack Chains
| Field Name | Type | Req | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `session_ids` | Array[String]| Yes | Sensitive | List of decoy session IDs involved in this alert. | Array of `^decoy_sess_[a-f0-9]{32}$`. Min items: 1. |
| `related_event_ids` | Array[UUID] | Yes | Internal | List of normalized event IDs serving as evidence. | Array of valid UUIDv4 strings. Min items: 1. |
| `related_alert_ids` | Array[UUID] | Optional | Internal | List of linked alerts exhibiting common source/behavior.| Array of valid UUIDv4 strings. |
| `attack_chain_id` | UUID (string) | Optional | Internal | Identifier of correlated multi-stage attack campaign.| Valid UUIDv4 format. Nullable. |

### Group G: Evidence Details
| Field Name | Type | Req | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `evidence.summary` | String | Yes | Public | Plain-text summary of observed metrics. | E.g., `"15 failed login attempts in 42 seconds across 3 unique usernames"`. |
| `evidence.supporting_count`| Integer | Yes | Public | Total count of supporting telemetry events. | Integer `>= 1`. |
| `evidence.triggering_conditions`| Object | Yes | Internal | Key-value metrics that met detection threshold. | E.g., `{"threshold_window_sec": 60, "observed_count": 15, "threshold_limit": 10}`. |

### Group H: MITRE ATT&CK Association
When supported by evidence, the `mitre_attack` object links observations to the enterprise ATT&CK framework:

| Field Name | Type | Req | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `mitre_attack.framework_version`| String | Yes | Public | MITRE ATT&CK dataset version. | E.g., `"v14.1"`. |
| `mitre_attack.tactic_id` | String | Yes | Public | ATT&CK Tactic identifier. | Regex `^TA\d{4}$`, e.g., `"TA0006"` (Credential Access). |
| `mitre_attack.tactic_name` | String | Yes | Public | Official tactic name. | E.g., `"Credential Access"`, `"Discovery"`. |
| `mitre_attack.technique_id` | String | Yes | Public | ATT&CK Technique or Sub-technique identifier. | Regex `^T\d{4}(\.\d{3})?$`, e.g., `"T1110.001"`. |
| `mitre_attack.technique_name`| String | Yes | Public | Official technique name. | E.g., `"Password Guessing"`. |
| `mitre_attack.mapping_confidence`| Integer | Yes | Public | Certainty of ATT&CK alignment. | Bounded integer `0` to `100`. |
| `mitre_attack.mapping_evidence` | String | Yes | Public | Explicit evidentiary justification for mapping. | Explains why the observed activity matches the technique. |

### Group I: Analyst Workflow & Investigation
| Field Name | Type | Req | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `analyst_workflow.assigned_analyst_id`| String | Optional | Internal | Identifier of SOC analyst assigned to triage. | Max 64 chars. Nullable. |
| `analyst_workflow.investigation_id` | UUID (string) | Optional | Internal | Formal case investigation tracking ID. | Valid UUIDv4 format. Nullable. |
| `analyst_workflow.analyst_notes_reference`| String | Optional | Internal | Reference URI or note hash for case log. | Max 256 chars. |

### Group J: Defensive Recommendations
| Field Name | Type | Req | Sensitivity | Description | Validation Rule / Constraints |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `recommendations.recommended_action`| String | Yes | Public | Concrete mitigation advice for SOC personnel. | E.g., `"Block source IP 192.0.2.45 at perimeter edge firewall"`. |
| `recommendations.recommendation_reason`| String | Yes | Public | Rationale supporting the action. | E.g., `"Source exhibited sustained brute force attempts against isolated decoy"`. |
| `recommendations.response_approval_required`| Boolean| Yes | Public | Human-in-the-loop gate for defensive action. | Strictly `true` by default. |

