# Ingestion Access Control Specification

**Document ID:** SEC-AUTH-001  
**Classification:** Operational Security Policy  
**Scope:** SnareSight Phase 3 — Event Pipeline & Database (P13)  
**Status:** IMPLEMENTED  

---

## 1. Authentication for Ingestion Endpoints

All external interactions with the Ingestion REST API Gateway require strict API Key authentication:

```http
POST /api/v1/ingestion/events/batch HTTP/1.1
Host: localhost:8000
Content-Type: application/json
X-API-Key: snaresight_dev_secret_key_change_in_production
```

### Access Control Rules:
1. **Missing Header:** If `X-API-Key` is missing, the gateway terminates request processing immediately with `HTTP 401 Unauthorized` (`{"detail": "Missing API Key header"}`).
2. **Invalid Secret:** If the supplied key does not match the configured platform ingestion key (`SNARESIGHT_API_KEY`), access is denied with `HTTP 401 Unauthorized` (`{"detail": "Invalid or revoked API Key"}`).
3. **No Direct Decoy Access:** Honeypot decoys do not possess this key. The key is issued only to authorized intermediate forwarders or administrative ingestion scripts operating on trusted networks.

---

## 2. Source Registry Authorization

Even with a valid API key, telemetry payloads must declare a `source.source_id` that is actively registered in the `SourceRegistryValidator`:

- **Known Active Sources:** Telemetry accepted and processed.
- **Unregistered Sources:** Rejected with `IngestionErrorCode.UNKNOWN_SOURCE_ID`.
- **Disabled Sources:** Rejected with `IngestionErrorCode.SOURCE_DEACTIVATED`.
- **Decoy Binding Mismatch:** If collector `A` submits events for decoy `B` without prior binding authorization, the event is rejected with `IngestionErrorCode.SOURCE_DECOY_MISMATCH`.

