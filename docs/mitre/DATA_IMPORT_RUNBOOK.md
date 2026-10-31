# SnareSight MITRE ATT&CK Data Import Runbook

## 1. Overview
This runbook provides step-by-step procedures for importing and updating official MITRE ATT&CK Enterprise datasets in SnareSight.

---

## 2. Prerequisites
1. **Source Bundle**: Official STIX 2.1 JSON file downloaded from `https://github.com/mitre-attack/attack-stix-data/tree/master/enterprise-attack`.
2. **Access Token**: An administrator API token with role `admin` or matching `API_COLLECTOR_KEY`.
3. **Backend Service**: SnareSight FastAPI backend running on `http://localhost:8000`.

---

## 3. Step-by-Step Procedure

### Step 1: Pre-Import Verification
Compute the SHA-256 hash of the downloaded STIX 2.1 bundle:
```bash
# Linux / macOS
sha256sum enterprise-attack.json

# Windows PowerShell
Get-FileHash -Algorithm SHA256 .\enterprise-attack.json
```

Verify that the bundle size is within the allowed ceiling:
- **Maximum bundle size**: 35 MB (`MAX_BUNDLE_BYTES = 35 * 1024 * 1024`)
- **Maximum objects**: 10,000 objects

---

### Step 2: Execute Non-Destructive Dry-Run Preview
Send the STIX bundle to the `/api/v1/mitre/import/dry-run` endpoint:

```bash
curl -X POST "http://localhost:8000/api/v1/mitre/import/dry-run?version=14.1&domain=enterprise-attack" \
  -H "Authorization: Bearer <ADMIN_API_KEY>" \
  -H "Content-Type: application/json" \
  --data-binary "@enterprise-attack.json"
```

#### Expected Output:
```json
{
  "dataset_version": "14.1",
  "domain": "enterprise-attack",
  "sha256_checksum": "e860626185c19506e89ff9de077cac29a4c1169fd01a66b9c2a42f2bd819d654",
  "total_objects": 28,
  "tactics_count": 3,
  "techniques_count": 10,
  "subtechniques_count": 10,
  "relationships_count": 5,
  "diff_summary": {
    "added": 28,
    "updated": 0,
    "unchanged": 0,
    "deprecated": 0,
    "revoked": 0
  },
  "is_valid": true,
  "validation_errors": []
}
```

Review the preview:
- Confirm `is_valid` is `true`.
- Review `validation_errors`.
- Verify the `diff_summary` matches expectations.

---

### Step 3: Approve and Execute Transactional Import
Once the dry-run diff is reviewed and approved, execute the live import:

```bash
curl -X POST "http://localhost:8000/api/v1/mitre/import/approve?version=14.1&domain=enterprise-attack" \
  -H "Authorization: Bearer <ADMIN_API_KEY>" \
  -H "Content-Type: application/json" \
  --data-binary "@enterprise-attack.json"
```

#### Expected Output:
```json
{
  "import_run_id": "84898144-8cb3-488f-9a78-ea1e5c26b864",
  "status": "COMPLETED",
  "dataset_version": "14.1",
  "sha256_checksum": "e860626185c19506e89ff9de077cac29a4c1169fd01a66b9c2a42f2bd819d654",
  "total_parsed": 28,
  "total_accepted": 28,
  "total_rejected": 0,
  "total_added": 28,
  "total_updated": 0,
  "total_unchanged": 0,
  "total_deprecated": 0,
  "total_revoked": 0,
  "duration_seconds": 0.12,
  "initiated_by": "admin",
  "timestamp": "2026-10-31T18:15:00Z"
}
```

---

### Step 4: Verify Post-Import Catalogue Health
Verify that the catalogue is active and populated:

```bash
curl "http://localhost:8000/api/v1/mitre/status"
```

Expected response status: `"HEALTHY"`, `catalogue_available: true`.

---

## 4. Idempotency Guarantee
Re-submitting an already imported dataset version with an identical SHA-256 checksum returns the existing import receipt immediately without re-inserting or duplicating database records:

```json
{
  "import_run_id": "idempotent-...",
  "status": "ACTIVE",
  "total_added": 0,
  "total_unchanged": 28
}
```

