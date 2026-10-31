# SnareSight: Security Audit Trail Verification & Forensic Export Specification

## 1. Executive Summary
In regulated SOC environments, non-repudiation and tamper-evidence of audit logs are mandatory. This specification details the cryptographic verification protocol used by SnareSight to ensure analyst actions, triage decisions, and configuration modifications cannot be altered undetected.

## 2. Integrity Verification Architecture
Each audit record emitted by `AuditService` (`backend/app/modules/security/audit_service.py`) contains:
- `audit_id`: Unique UUID v4.
- `timestamp`: UTC ISO-8601 timestamp with sub-second precision.
- `actor_id` & `actor_username`: Authenticated analyst or service principal identity.
- `action_type`: Standardized SOC operation verb (e.g. `ALERT_STATUS_UPDATE`, `ISOLATION_RULE_CREATED`).
- `target_type` & `target_id`: Entity impacted by the operation.
- `client_ip`: Originating network address.
- `details`: JSON payload of operation parameters.

## 3. Cryptographic Verification Procedure
1. **Canonical JSON Serialization:** Keys in `details` are sorted alphabetically with whitespace normalized.
2. **Hash Chain Digest:** Compute SHA-256 over `timestamp + actor_username + action_type + target_id + canonical_details`.
3. **Forensic Export:** Export records to signed CSV/JSON format for archival and external SIEM ingestion.
