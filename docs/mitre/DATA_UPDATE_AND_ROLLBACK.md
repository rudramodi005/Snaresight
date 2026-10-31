# SnareSight MITRE ATT&CK Version Update and Rollback Procedures

## 1. Upgrading ATT&CK Dataset Versions

When a new version of the MITRE ATT&CK framework is released (e.g., v15.0):

1. **Download New STIX 2.1 Release**:
   Acquire `enterprise-attack.json` for v15.0 from the official MITRE repository.
2. **Execute Dry-Run Preview**:
   ```bash
   curl -X POST "http://localhost:8000/api/v1/mitre/import/dry-run?version=15.0" \
     -H "Authorization: Bearer <ADMIN_API_KEY>" \
     -H "Content-Type: application/json" \
     --data-binary "@enterprise-attack-v15.0.json"
   ```
3. **Inspect the Diff**:
   The response categorizes objects:
   - `added`: Newly introduced techniques / sub-techniques.
   - `updated`: Techniques with modified descriptions or platform lists.
   - `unchanged`: Identical techniques.
   - `deprecated`: Objects deprecated in the new version.
   - `revoked`: Objects replaced by newer techniques.
4. **Approve Import**:
   ```bash
   curl -X POST "http://localhost:8000/api/v1/mitre/import/approve?version=15.0" \
     -H "Authorization: Bearer <ADMIN_API_KEY>" \
     -H "Content-Type: application/json" \
     --data-binary "@enterprise-attack-v15.0.json"
   ```
5. **Atomic Version Transition**:
   - The new version (`15.0`) is set to `is_active = True`.
   - The prior version (`14.1`) is marked `SUPERSEDED` with `is_active = False`.
   - Existing techniques retain their historical references.

---

## 2. Emergency Rollback Procedure

If an imported version contains discrepancies or breaking changes with downstream systems, an administrator can trigger an immediate rollback to any prior active release without data loss.

### Rollback API Call:
```bash
curl -X POST "http://localhost:8000/api/v1/mitre/import/rollback" \
  -H "Authorization: Bearer <ADMIN_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "target_version": "14.1",
    "reason": "Compatibility issue detected in v15.0 sub-technique definitions"
  }'
```

### Rollback Lifecycle Steps:
1. Validates that `target_version` exists and was previously successfully imported.
2. Sets `is_active = False` on the superseded version.
3. Sets `is_active = True` and `status = ACTIVE` on `target_version`.
4. Emits an audit entry in `attack_import_runs` logging the rollback reason and caller.
5. All future catalogue queries immediately resolve to the restored version.

