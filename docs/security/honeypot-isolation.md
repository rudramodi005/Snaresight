# SnareSight: Honeypot Isolation & Telemetry Ingestion Boundary

**Phase:** 7 — Security Hardening and Defensive Response  
**Task:** P31 / 40  
**Status:** `COMPLETED AND VERIFIED`

---

## 1. Honeypot Isolation Model

Honeypots operate inside isolated virtual network boundaries established in Phase 2 (P06–P10):
- **No Inbound Application Secrets**: Honeypot processes possess zero knowledge of application database credentials, encryption keys, or administrative tokens.
- **No Direct Database Connectivity**: Perimeter decoys cannot reach PostgreSQL (port 5432) or any internal backend service other than the specific ingestion collector port.
- **Firewall Containment**: Host and guest firewalls strictly drop outbound traffic from decoys toward internal enterprise networks or external internet destinations.

---

## 2. Ingestion Gateway Security Boundary

Telemetry flows from honeypots into the backend exclusively through the ingestion REST gateway:
- **Endpoint**: `POST /api/v1/ingestion/events/batch`
- **Authentication**: Requires valid `X-API-Key` collector header matching `INGESTION_API_KEY`. Unauthenticated requests are rejected with `HTTP 401 Unauthorized`.
- **Batch Ceiling**: Batches are strictly limited to **500 events per request**.
- **Request Size Ceiling**: Request body capped at **10 MB**.
- **Schema Validation**: Every raw event must conform to `EventBatchRequest` schemas. Malformed JSON or schema mismatches are rejected cleanly without crashing the pipeline.

---

## 3. Sensitive Data Rejection & Non-Execution

1. **Sensitive Data Inspector (`SensitiveDataInspector`)**:
   - Inbound event payloads are scanned for forbidden credential keys (`password`, `auth_token`, `private_key`, `secret_key`) or synthetic canaries (`CanaryPass`).
   - Telemetry violating credential rejection policies is discarded at the gateway, preventing honeypot credentials from entering the database.
2. **Untrusted Telemetry Guarantee**:
   - Telemetry payloads are strictly inert data structures. The backend contains zero evaluation or execution interpreters (`eval`, `exec`, shell scripts) acting on incoming event contents.

