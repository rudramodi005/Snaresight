# SnareSight Curated MITRE ATT&CK Mapping Registry

> [!WARNING]
> **CRITICAL OPERATIONAL NOTICE:**
> An ATT&CK mapping indicates that observed behavior is consistent with a documented adversary technique. It does not, by itself, establish attacker identity, successful compromise, intent, or completion of an attack.

---

## 1. Registry Architecture

The SnareSight Mapping Registry defines controlled, versioned associations between detection rules and official MITRE ATT&CK Enterprise techniques.

To prevent over-attribution, speculative classification, and false confidence, the registry adheres to three core rules:
1. **Conservative Association:** Only map rules where the observed telemetry defensibly matches the adversary technique scope.
2. **Support Hierarchy:** Parent techniques (e.g. `T1110`) are preferred over sub-techniques (e.g. `T1110.001`) unless specific evidence (e.g. distinct password attempts) justifies the sub-technique.
3. **Explicit Non-Mapping:** Rules with deferred telemetry, generic anomaly patterns, or cross-category correlations remain `NOT_MAPPED`.

---

## 2. Curated Detection Scenario Mapping Table

| Detection Rule ID | Scenario Name | Status | ATT&CK Technique ID | Technique Name | Sub-Technique ID | Mapping Category | Default Conf. | Required Evidence | Analyst Review Required? |
|---|---|---|---|---|---|---|---|---|---|
| `AUTH-001` | Repeated Authentication Failures | ACTIVE | `T1110` | Brute Force | `T1110.001` (Password Guessing) | `DIRECTLY_SUPPORTED` | 85 | `event_category == "authentication"`, `outcome == "FAILURE"` | No (Automated finding; analyst review optional) |
| `AUTH-002` | Decoy Authentication Accepted | ACTIVE | `T1078` | Valid Accounts | None | `REQUIRES_ANALYST_REVIEW` | 45 | `event_category == "authentication"`, `outcome == "SUCCESS"` | **YES (Mandatory Review)** |
| `AUTH-003` | Username Enumeration Probing | ACTIVE | `T1087` | Account Discovery | `T1087.001` (Local Account) | `PARTIALLY_SUPPORTED` | 65 | `event_category == "authentication"`, `metadata.username_fingerprint` | No |
| `WEB-001` | Web Path Enumeration Probing | ACTIVE | `T1083` | File and Directory Discovery | None | `PARTIALLY_SUPPORTED` | 65 | `event_category == "request"`, `metadata.http_path` | No |
| `WEB-002` | Suspicious Directory Traversal Request | ACTIVE | `T1190` | Exploit Public-Facing Application | None | `PARTIALLY_SUPPORTED` | 70 | `metadata.http_path` (contains `../`, `..%2f`, etc.) | No |
| `CMD-001` | Command Discovery Interaction | DRAFT | — | — | None | `NOT_MAPPED` | 0 | None (Rule disabled; web decoy has no shell) | N/A |
| `FILE-001` | File Transfer Interaction | DRAFT | — | — | None | `NOT_MAPPED` | 0 | None (Rule disabled; web decoy has no file upload) | N/A |
| `WEB-003` | Repeated Suspicious Request Patterns | ACTIVE | — | — | None | `NOT_MAPPED` | 0 | None (Generic statistical pattern; lacks signature specificity) | N/A |
| `BEHAV-001` | Multi-Category Suspicious Interaction | ACTIVE | — | — | None | `NOT_MAPPED` | 0 | None (Cross-category aggregation belongs to Phase 5 correlation) | N/A |
| `BEHAV-002` | Unusual HTTP Method Interaction | ACTIVE | — | — | None | `NOT_MAPPED` | 0 | None (Baseline method anomaly lacks technique specificity) | N/A |

---

## 3. Scenario Analysis & Rationale Details

### 3.1 `AUTH-001`: Repeated Authentication Failures
- **Mapped Technique:** `T1110` (Brute Force) / `T1110.001` (Password Guessing)
- **Official Catalogue Description:** "Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown or when password hashes are unavailable."
- **Observed Telemetry:** Repeated failed login attempts within a validated session or sliding time window.
- **Evidential Proving Scope:** Proves automated or interactive credential guessing against a web login decoy.
- **Limitations:** Does **not** prove credential acquisition or account breach.

### 3.2 `AUTH-002`: Decoy Authentication Accepted
- **Mapped Technique:** `T1078` (Valid Accounts)
- **Official Catalogue Description:** "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion."
- **Observed Telemetry:** Simulated successful authentication on the honeypot trap.
- **Evidential Proving Scope:** The simulated honeypot accepted the interaction as part of its deception workflow.
- **CRITICAL DECEPTION WARNING:** The interaction occurred on a trap account; it does **not** demonstrate compromise of genuine production directory accounts, domain credentials, or real systems. Mandatory analyst review is enforced.

### 3.3 `AUTH-003`: Username Enumeration Probing
- **Mapped Technique:** `T1087` (Account Discovery) / `T1087.001` (Local Account)
- **Observed Telemetry:** Multiple distinct privacy-safe username SHA-256 fingerprints tested in a single session.
- **Limitations:** Proves enumeration probing; does not prove attacker discovered authentic production accounts.

### 3.4 `WEB-001`: Web Path Enumeration Probing
- **Mapped Technique:** `T1083` (File and Directory Discovery)
- **Observed Telemetry:** Multiple distinct HTTP requested paths within a session.
- **Limitations:** Proves endpoint scanning; does not establish file disclosure.

### 3.5 `WEB-002`: Suspicious Directory Traversal Request
- **Mapped Technique:** `T1190` (Exploit Public-Facing Application)
- **Observed Telemetry:** Passive pattern matching of traversal tokens (`../`, `..%2f`, `%2e%2e/`).
- **Execution Safety:** Path was never resolved or executed on host filesystem. Proves exploitation attempt; does not prove successful file exposure.

### 3.6 Unmapped Scenarios (`CMD-001`, `FILE-001`, `WEB-003`, `BEHAV-001`, `BEHAV-002`)
- **`CMD-001` & `FILE-001`:** Deferred draft rules. Web decoy provides no shell or file transfers. Fictional or inferred activity is strictly unmapped.
- **`WEB-003`:** Statistical request patterns lack behavioral specificity.
- **`BEHAV-001`:** Multi-category activity spans multiple techniques; synthesized during Phase 5 attack-chain correlation.
- **`BEHAV-002`:** Statistical HTTP method anomalies lack signature correlation with a specific ATT&CK technique.

