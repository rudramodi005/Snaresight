# Operational Diagnostics and Troubleshooting Guide

## 1. Streaming Diagnostics

### Checking Stream Status
Security operators can query the dedicated stream monitoring endpoint:
```http
GET /api/v1/stream/status
Authorization: Bearer <soc_analyst_token>
```
Response:
```json
{
  "active_subscribers": 3,
  "max_connections": 50,
  "max_per_user": 5,
  "events_published": 1420,
  "notifications_failed": 0
}
```

### Investigating Connection Drops
- Check `stream_queue_drops` metric in `/api/v1/health/pipeline`.
- If increasing, consumers are not draining frames within the 100-message buffer size.
- Inspect network latency between subscriber clients and SnareSight backend.

## 2. Ingestion and Database Diagnostics

### Investigating High Ingestion Rejections
- Review `/api/v1/health/pipeline` for `ingestion_rejected`.
- Common causes:
  1. Honeypot collector token expired or invalid.
  2. Malformed JSON payload or schema version mismatch.
  3. Decoy ID not registered in database.

### Investigating Database Outages
- If `/api/v1/health/ready` returns 503:
  1. Inspect PostgreSQL service logs.
  2. Check database connection pool saturation.
  3. Verify database network route and credentials in `.env`.

