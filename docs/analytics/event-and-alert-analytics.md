# SnareSight: Event & Alert Trend Analytics

**Phase:** 6 — Security Operations Center (SOC) Dashboard  
**Task:** P30 / 40  
**Status:** `COMPLETED AND VERIFIED`

---

## 1. Event Timeline Analytics

The event timeline endpoint (`GET /api/v1/analytics/events/timeline`) computes temporal distribution of normalized honeypot events across discrete buckets (`minute`, `hour`, or `day`).

### Breakdown Groupings
1. **Total Volume**: Aggregate count per time interval.
2. **By Event Category**:
   - `AUTHENTICATION_ATTEMPT`
   - `COMMAND_EXECUTION`
   - `FILE_TRANSFER`
   - `NETWORK_CONNECTION`
   - `RECONNAISSANCE`
3. **By Decoy Sensor**:
   - Discrete counts per active decoy identifier (e.g. `WEB-001`, `SSH-001`).
4. **By Protocol**:
   - `HTTP`, `HTTPS`, `SSH`, `TELNET`, `FTP`, `SMB`, etc.

---

## 2. Alert Timeline Analytics

The alert timeline endpoint (`GET /api/v1/analytics/alerts/timeline`) visualizes the generation of security alerts across time intervals.

### Breakdown Groupings
1. **By Severity**:
   - `CRITICAL` (Dark Red)
   - `HIGH` (Red / Amber)
   - `MEDIUM` (Yellow)
   - `LOW` (Blue)
   - `INFO` (Slate Gray)
2. **By Lifecycle Status**:
   - `NEW`
   - `ACKNOWLEDGED`
   - `INVESTIGATING`
   - `ESCALATED`
   - `RESOLVED`
   - `CLOSED`

---

## 3. Event-to-Alert Density Overview

The density endpoint (`GET /api/v1/analytics/event-alert-overview`) pairs total event volume with alert volume to provide operational clarity into detection sensitivity and sensor noise.

Analysts can immediately determine whether an observed spike in events was purely high-volume network noise or resulted in elevated threat alerts requiring immediate triage.

