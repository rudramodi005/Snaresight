# SnareSight — Schema Versioning & Backward Compatibility Policy

**Document ID:** `SNARESIGHT-VERSIONING-001`  
**Classification:** Confidential — Internal Cybersecurity Engineering  
**Authority:** Principal Software Architect & Release Engineer  

---

## 1. Versioning Philosophy & Semantic Rules

SnareSight enforces strict **Semantic Schema Versioning** (`MAJOR.MINOR`) across all data contracts. 

```
                          MAJOR . MINOR
                            |       |
  Breaking Changes ---------+       +--------- Backward-Compatible Additions
  - Removal of fields                         - Addition of optional fields
  - Change in field types                     - New enum values (handled safely)
  - Semantic redefinition                     - New optional sub-objects
```

### Initial Baseline Versions:
- **Raw Event Schema:** `1.0`
- **Normalized Event Schema:** `1.0`
- **Security Alert Schema:** `1.0`

---

## 2. When to Increment Version Numbers

### 2.1 MINOR Version Increment (e.g., `1.0` -> `1.1`)
A minor version increment indicates a **backward-compatible change**:
1. Adding a new optional field with a sensible default.
2. Introducing a new event type to the taxonomy without changing existing event definitions.
3. Adding a new optional sub-dictionary to `details` (e.g. adding `details.cowrie` for SSH honeypots).
4. Expanding an enum with a non-breaking value.

*Client & Ingestion Contract:* An ingestion pipeline built for version `1.1` can safely process records formatted in `1.0`.

### 2.2 MAJOR Version Increment (e.g., `1.0` -> `2.0`)
A major version increment indicates a **breaking change**:
1. Renaming or deleting an existing required field.
2. Changing the data type of an existing field (e.g. changing `session_id` from string to object).
3. Restricting validation constraints such that previously valid records are rejected.
4. Redefining the semantics of an existing field (e.g. changing `observed_at` to represent local time instead of UTC).

*Client & Ingestion Contract:* Major version transitions require formal pipeline migration adapters and schema converters.

---

## 3. Ingestion Behavior for Unknown Versions

When the ingestion pipeline encounters an event with an unrecognized schema version:

1. **Exact Match (`1.0`):** Accepted and validated against the `1.0` JSON Schema.
2. **Compatible Minor Version (`1.x` where `x > 0`):** Accepted; unknown optional fields are preserved in processing metadata without rejection.
3. **Incompatible Major Version (`2.x` or unknown):**
   - The event is **NEVER silently dropped**.
   - The event is marked with `validation_status="UNSUPPORTED_VERSION"`.
   - The raw record is safely routed to an isolated quarantine queue (`data/quarantine/`).
   - An operational health alert is emitted to notify SOC administrators of an out-of-sync collector agent.

---

## 4. Multi-Decoy Extensibility (Future Cowrie SSH Integration)

A core requirement of SnareSight is the ability to ingest future honeypots (such as the Cowrie SSH/Telnet decoy) without modifying existing web telemetry semantics.

### How Cowrie Integrates under Schema v1.0:
1. **Decoy Identifier:** Cowrie instances declare `decoy_id="SSH-001"`.
2. **Target Service:** Sets `target_service="SSH_DAEMON"`, `target_protocol="SSH"`, `target_port=2222`.
3. **Authentication Telemetry:** Cowrie login attempts reuse the existing `AUTH_ATTEMPT` taxonomy:
   - `details.auth.username_fingerprint` (HMAC-SHA256 of submitted SSH user)
   - `details.auth.password_present` (boolean)
   - `details.auth.password_length_category`
4. **Command Telemetry:** Terminal sessions emit `event_category="COMMAND_INTERACTION"`, populating `details.command.command_raw` with submitted shell syntax.
5. **Zero Schema Modification Required:** Web detection rules continue evaluating `WEB_PORTAL` events unchanged, while SSH detection rules query `SSH_DAEMON` events concurrently.

