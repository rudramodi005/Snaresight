# Audit & Security Requirements

## 1. Zero Credential Persistence Invariant

SnareSight strictly enforces that no plaintext passwords, bearer tokens, or secrets are ever persisted, logged, or returned in alert summaries or evidence:
1. **Schema Level:** No column named `password`, `secret`, `hash`, or `token` exists in `alerts`, `alert_evidence`, `alert_audit_logs`, or `alert_notes`. Verified by automated test `test_03_zero_password_columns_exist_across_all_models`.
2. **Ingestion & Redaction:** Telemetry payloads undergo mandatory credential redaction before persistence.
3. **API Level:** Any payload retrieved through alert evidence links is scrubbed, displaying `"[REDACTED_CREDENTIAL]"` in place of raw secrets.

---

## 2. Tamper-Evident Forensic Immutability

1. **Delete Restrictions:**
   - Forensics tables use `ON DELETE RESTRICT` constraints to prevent accidental or malicious deletion of core telemetry.
2. **Append-Only Auditing:**
   - Every analyst decision, note, assignment, and status change is written to `alert_audit_logs`.
   - Records include `actor_id`, `action_type`, `previous_status`, `new_status`, `reason`, `details`, and UTC `created_at`.
3. **No In-Place Overwrites:**
   - Original detection explanations, rule conditions, and evidence links are immutable once created.

---

## 3. Strict Non-Attribution Policy

All alert visualizations, prioritization scores, and cross-subsystem links adhere to the platform's non-attribution policy:
- Telemetry originates exclusively from isolated honeypot decoys.
- Observed IP addresses, user agents, and JA3/JA4 fingerprints represent infrastructure and tooling, not confirmed human identity.
- No nation-state or actor attribution claims are made without external threat intelligence feeds.

