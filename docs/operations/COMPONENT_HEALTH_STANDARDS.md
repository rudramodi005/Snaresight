# Component Health Standards and Status Rules

## 1. Component Health Status Enums

SnareSight enforces standard status enums defined in `app/monitoring/status.py`:

- `HEALTHY`: Component is operational and performing within baseline tolerances.
- `DEGRADED`: Component is functioning with errors, high drop rates, or elevated latency.
- `UNHEALTHY`: Component is failing critical operations or unreachable.
- `UNKNOWN`: Component status cannot be determined or decoy has not reported within heartbeat intervals.
- `NOT_CONFIGURED`: Component is designed but not yet enabled or configured (e.g. Phase 4 Rule Engine).

## 2. Invariant Rules for Health Evaluation

1. **Unknown is Never Healthy**:
   - If a decoy has been silent or marked `INACTIVE`, its status is reported as `UNKNOWN`, never masked as `HEALTHY`.

2. **Unconfigured vs. Failing**:
   - Components scheduled for future phases (Rule Engine, Alert Manager) are explicitly stamped `NOT_CONFIGURED`.
   - They do not degrade the overall pipeline status to `DEGRADED` or `UNHEALTHY`.

3. **Readiness vs. Liveness Distinction**:
   - Liveness indicates the web service process is alive.
   - Readiness indicates external resources (PostgreSQL) are verified with active query roundtrips (`SELECT 1`).
   - If the database drops, `/health/live` remains 200 OK while `/health/ready` returns 503 Service Unavailable, signaling orchestrators to avoid routing traffic without prematurely restarting a healthy container.

