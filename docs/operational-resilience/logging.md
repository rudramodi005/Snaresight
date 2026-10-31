# Control-Plane Structured Event Logging & Telemetry Formats

## 1. Internal Security Event Schema

Internal control-plane telemetry is modeled by `InternalSecurityEventModel` and emitted during authentication events, permission checks, system config modifications, backup jobs, and ingestion anomalies.

### Event Format Reference
```json
{
  "id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "event_type": "AUTH_FAILURE",
  "timestamp": "2026-10-31T22:30:15.120Z",
  "actor_username": "soc_admin",
  "actor_role": "ADMIN",
  "source_component": "FastAPI_Auth",
  "outcome": "FAILURE",
  "severity": "HIGH",
  "correlation_id": "CORR-99812",
  "metadata_payload": {
    "client_ip": "192.168.1.105",
    "user_agent": "Mozilla/5.0 ...",
    "failed_attempts": 5
  }
}
```

---

## 2. Event Types & Classification

1. **Authentication & Authorization**:
   - `AUTH_FAILURE`, `LOGIN_FAILED`, `TOKEN_REJECTED`, `TOKEN_REVOKED`
   - `ACCESS_DENIED`, `FORBIDDEN_ENDPOINT`, `ROLE_CHANGE_ATTEMPT`
2. **Platform Configuration & Maintenance**:
   - `SYSTEM_CONFIG_CHANGED`, `SECURITY_POLICY_ALTERED`, `RETENTION_POLICY_MUTATED`
3. **Backup & Recovery Operations**:
   - `BACKUP_STARTED`, `BACKUP_COMPLETED`, `BACKUP_FAILED`
   - `RESTORE_TEST_STARTED`, `RESTORE_TEST_SUCCESS`, `RESTORE_TEST_FAILED`
4. **Audit Trail Integrity**:
   - `AUDIT_PERSISTENCE_FAILURE`, `AUDIT_HASH_CORRUPTION`, `AUDIT_CHAIN_BROKEN`
5. **Collector & Ingestion Engine**:
   - `INGESTION_SPIKE_REJECTIONS`, `SENSOR_AUTH_FLOOD`, `CORRUPTED_TELEMETRY_BATCH`

