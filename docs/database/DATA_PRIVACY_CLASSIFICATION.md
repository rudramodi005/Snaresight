# SnareSight — Data Privacy & Sensitivity Classification

**Document ID:** `SNARESIGHT-PRIVACY-001`  
**Classification:** Confidential — Internal Cybersecurity Engineering  
**Authority:** Principal Data Privacy Officer & Application Security Specialist  

---

## 1. Classification Framework

SnareSight implements a four-tiered Data Privacy Classification model to govern how information is captured, stored, displayed, and exported across the platform:

```
+------------------------------------------------------------------------+
| RESTRICTED: NEVER PERSISTED                                            |
| Plaintext passwords, derived password hashes, tokens, keys, raw bodies |
+-----------------------------------+------------------------------------+
| SENSITIVE: ACCESS CONTROLLED      |
| IP addresses, user agents, HMAC fingerprints, session IDs, payloads    |
+-----------------------------------+------------------------------------+
| INTERNAL: OPERATIONAL SCOPE       |
| Event IDs, rule versions, processing timestamps, collector health      |
+-----------------------------------+------------------------------------+
| PUBLIC: UNRESTRICTED WITHIN SOC   |
| Schema versions, event categories, outcomes, ports, ATT&CK mappings    |
+------------------------------------------------------------------------+
```

---

## 2. Sensitivity Tier Specifications

### 2.1 Tier 1: PUBLIC (Unrestricted SOC Metadata)
- **Definition:** Non-sensitive architectural and taxonomy definitions.
- **Allowed Fields:** `schema_version`, `event_category`, `event_type`, `action`, `outcome`, `target_service`, `target_protocol`, `target_port`, `status_code`, `severity`, `confidence`, `mitre_attack.*`, `recommendations.recommended_action`.
- **Access Policy:** Visible to all authenticated SOC dashboard users (Level 1 Analyst, SOC Lead, Auditors).
- **Export Policy:** Unrestricted in summary reports and executive dashboards.

### 2.2 Tier 2: INTERNAL (Operational System Telemetry)
- **Definition:** Telemetry required for platform reliability, pipeline diagnostics, and audit verification.
- **Allowed Fields:** `raw_event_id`, `event_id`, `alert_id`, `detection_rule_id`, `detection_rule_version`, `collector_id`, `processing.*`, `decoy_id`, `provenance.environment`, `provenance.collection_method`.
- **Access Policy:** Accessible to SOC Engineers, SIEM Administrators, and automated pipeline processes.
- **Export Policy:** Included in technical engineering exports; excluded from external client-facing reports.

### 2.3 Tier 3: SENSITIVE (Forensic Evidence & Source Metadata)
- **Definition:** Telemetry directly related to an external interacting client, session tracking, or payload markers.
- **Allowed Fields:** `source_address`, `source_port`, `source.user_agent_summary`, `session_id`, `interaction.username_fingerprint`, `interaction.payload_markers`, `observed_source_id`, `details.command.command_raw`.
- **Handling & Protection:**
  1. *Pseudonymization:* Usernames are hashed via keyed HMAC-SHA256 (`username_fingerprint`). Raw usernames are never stored.
  2. *Inert Handling:* All script, SQL, or command strings are treated as plain text strings and HTML-escaped.
- **Access Policy:** Restricted to authenticated SOC Analysts (Level 2+) and Incident Responders.
- **Retention Policy:** Default retention of 90 days in active storage; 365 days in encrypted cold archive.
- **Export Policy:** Anonymized or masked (e.g. `192.0.2.***`) when generating external compliance reports.

### 2.4 Tier 4: RESTRICTED (Prohibited Secrets — Strictly Excluded)
- **Definition:** Data that MUST NEVER be stored, logged, buffered beyond immediate execution, or exported under any circumstances.
- **Prohibited Data Elements:**
  - Submitted plaintext passwords (regardless of whether they match real accounts).
  - Cryptographic hashes computed directly from submitted passwords (e.g. `md5(password)`, `sha256(password)`).
  - External authentication cookies or session bearer tokens.
  - TLS private keys, SSH host private keys, or API credentials.
  - Full raw POST request bodies.
  - Real personally identifiable information (PII) belonging to employees or customers.
- **Enforcement Mechanisms:**
  1. Pydantic schema model validation rejects payloads with prohibited keys.
  2. In-memory explicit variable deletion (`del password`) immediately after categorizing length.
  3. Pre-write assertion in `DecoyEventLogger` rejects any payload containing `"password":`.

---

## 3. Redaction & Display Rules for SOC Dashboard

1. **Password Reflection Prohibition:** No user interface view, table, modal, or toast notification shall ever display a password input field or reflect submitted credentials.
2. **Username Display:** The dashboard displays the 64-character `username_fingerprint` or a short 8-character prefix badge (`fp:7c4852c2...`) to allow analysts to correlate repeated attempts without exposing harvested corporate usernames.
3. **IP Masking:** Exported PDF or CSV compliance reports provide an option to mask the last octet of external IP addresses.

