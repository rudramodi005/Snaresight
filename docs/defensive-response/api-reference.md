# Defensive Response API Reference

## Base URL
`/api/v1/response`

All endpoints require standard `Authorization: Bearer <token>` authentication headers.

---

## 1. Summary & Overview

### `GET /api/v1/response/summary`
Retrieves aggregated metrics for the Defensive Response Center.

- **Response `200 OK`**:
```json
{
  "total_active_cases": 12,
  "open_cases": 4,
  "investigating_cases": 5,
  "awaiting_approval_count": 2,
  "critical_cases_count": 3,
  "high_priority_cases_count": 4,
  "recently_resolved_count": 8,
  "active_evidence_holds_count": 7,
  "cases_by_status": {
    "OPEN": 4,
    "INVESTIGATING": 5,
    "AWAITING_APPROVAL": 2,
    "RESOLVED": 8
  },
  "cases_by_priority": {
    "P1_CRITICAL": 3,
    "P2_HIGH": 4,
    "P3_MEDIUM": 5
  }
}
```

---

## 2. Response Cases

### `GET /api/v1/response/cases`
Lists response cases with optional filtering, search, and pagination.

- **Query Parameters**:
  - `status`: e.g. `OPEN`, `INVESTIGATING`, `AWAITING_APPROVAL` (optional)
  - `priority`: e.g. `P1_CRITICAL`, `P2_HIGH` (optional)
  - `assigned_analyst`: username string (optional)
  - `search`: keyword matching title, case_id, or description (optional)
  - `page`: default `1`
  - `limit`: default `20`

### `POST /api/v1/response/cases`
Creates a new incident response case.

- **Request Body**:
```json
{
  "title": "Credential Stuffing Attack on Deception SSH Node",
  "description": "High volume of failed auth attempts against root and admin decoys.",
  "priority": "P2_HIGH",
  "severity": "HIGH",
  "assigned_analyst": "analyst_bob",
  "primary_alert_id": "ALT-20261031-SSH-01",
  "initial_note": "Initial triage initiated."
}
```

### `GET /api/v1/response/cases/{case_id}`
Fetches complete case details including relationships, notes, recommendations, executions, approvals, actions, and evidence holds.

### `POST /api/v1/response/cases/{case_id}/status`
Transitions a case to a new lifecycle state.

- **Request Body**:
```json
{
  "new_status": "INVESTIGATING",
  "reason": "Correlating multi-session attack pattern.",
  "resolution_category": null
}
```

### `POST /api/v1/response/cases/{case_id}/notes`
Appends an analyst note to the case timeline.

- **Request Body**:
```json
{
  "note_type": "ANALYST_NOTE",
  "content": "Observed identical JA3 hash on honeypot web sensor 2."
}
```

### `POST /api/v1/response/cases/{case_id}/links`
Links a security entity (`ALERT`, `EVENT`, `SESSION`, `SOURCE_PROFILE`, `CAMPAIGN_CLUSTER`) to the case.

- **Request Body**:
```json
{
  "related_entity_type": "SESSION",
  "related_entity_id": "sess-908124",
  "relationship_reason": "Originates from same threat actor subnet.",
  "confidence_score": 0.95
}
```

---

## 3. Recommendations

### `POST /api/v1/response/cases/{case_id}/recommendations/generate`
Evaluates the case against the 5 heuristic recommendation rules and records proposals.

### `POST /api/v1/response/cases/{case_id}/recommendations/{rec_id}/decision`
Accepts or rejects a proposed recommendation.

- **Request Body**:
```json
{
  "decision": "ACCEPT",
  "reason": "Matches observed brute force pattern, approved for canary rotation."
}
```

---

## 4. Playbooks

### `GET /api/v1/response/playbooks`
Lists all available standard response playbooks in the catalog.

### `POST /api/v1/response/cases/{case_id}/playbooks/start`
Starts a playbook execution on a case.

- **Request Body**:
```json
{
  "playbook_id": "PB-AUTH-FAILURES",
  "inputs": {}
}
```

### `POST /api/v1/response/cases/{case_id}/playbooks/{execution_id}/advance`
Advances the current step of an active playbook.

- **Request Body**:
```json
{
  "step_status": "SUCCESS",
  "step_notes": "Rotated honeypot credentials and verified canary deployment."
}
```

---

## 5. Approvals

### `POST /api/v1/response/cases/{case_id}/approvals`
Submits a dual-custody approval request for a controlled action.

- **Request Body**:
```json
{
  "action_type": "HONEYPOT_SENSITIVITY_BOOST",
  "justification": "Targeted scanning activity requires increased telemetry fidelity.",
  "recommendation_id": "REC-AUTH-01"
}
```

### `POST /api/v1/response/cases/{case_id}/approvals/{approval_id}/decision`
Records an approval decision by an independent reviewer (enforces separation of duties).

- **Request Body**:
```json
{
  "decision": "APPROVE",
  "reason": "Approved by SOC Lead for sensor cluster 01."
}
```

---

## 6. Defensive Actions

### `POST /api/v1/response/cases/{case_id}/actions/execute`
Dispatches a safe defensive action.

- **Request Body**:
```json
{
  "action_type": "CREDENTIAL_CANARY_ROTATION",
  "approval_id": "uuid-of-approved-request",
  "parameters": {
    "sensor_id": "hp-ssh-01",
    "canary_family": "admin_decoys"
  }
}
```

---

## 7. Evidence Preservation Holds

### `POST /api/v1/response/cases/{case_id}/holds`
Applies a retention hold to an evidence record.

- **Request Body**:
```json
{
  "evidence_type": "ALERT",
  "evidence_identifier": "ALT-20261031-SSH-01",
  "hold_reason": "Litigation and compliance retention hold."
}
```

### `POST /api/v1/response/cases/{case_id}/holds/{hold_id}/release`
Releases an evidence hold with documented justification.

- **Request Body**:
```json
{
  "justification": "Investigation closed and forensic report exported."
}
```

