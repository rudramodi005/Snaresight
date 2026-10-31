# SnareSight MITRE ATT&CK Mapping Versioning & Reassessment Policy

> [!WARNING]
> **CRITICAL OPERATIONAL NOTICE:**
> An ATT&CK mapping indicates that observed behavior is consistent with a documented adversary technique. It does not, by itself, establish attacker identity, successful compromise, intent, or completion of an attack.

---

## 1. Version Dependencies

A SnareSight ATT&CK detection mapping record is derived from four versioned components:

1. **Detection Rule Version:** The specific version of the detection rule (e.g. `AUTH-001 v1.0`) that evaluated the telemetry.
2. **ATT&CK Dataset Version:** The active STIX 2.1 release version (e.g. `14.1`) against which techniques and sub-techniques are validated.
3. **Mapping Definition Version:** The version of the mapping rule (e.g. `MAP-AUTH-001-T1110 v1.0`) defining the evidential criteria.
4. **Mapping Confidence Policy Version:** The version of the scoring calculation model (e.g. `v1.0`).

All four version identifiers are permanently stored in every `attack_detection_mappings` record.

---

## 2. Dataset Version Transitions & Rollbacks

When a new MITRE ATT&CK version (e.g. `v15.0`) is imported or an active version is rolled back:

1. **Historical Integrity:** Existing mappings created under prior dataset versions retain their original `dataset_version` tag and historical evidence. Previous records are never modified retroactively.
2. **Revocation & Deprecation Handling:**
   - If a technique is revoked in a new dataset release, existing historical records remain intact.
   - Future detections trigger mapping evaluation against the active version's successor technique indicated in STIX relationships.
3. **Audit History Log:** Any controlled reassessment triggered by policy updates is logged in `attack_mapping_history` with `change_reason = "DATASET_UPGRADE"` or `"POLICY_RECALCULATION"`.

