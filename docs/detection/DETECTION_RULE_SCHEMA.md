# Detection Rule Schema Specification

## 1. Declarative Structure

SnareSight rules are defined declaratively using strict JSON / Pydantic structures:

```json
{
  "rule_id": "TEST-RULE-001",
  "rule_version": "1.0",
  "rule_name": "Login Attempt Event Match Test",
  "description": "Matches when event_type equals LOGIN_ATTEMPT in test scenarios.",
  "category": "AUTHENTICATION",
  "subcategory": "CREDENTIAL_SUBMISSION",
  "detection_type": "SINGLE_EVENT",
  "enabled": true,
  "rule_status": "ACTIVE",
  "evaluation_mode": "EVENT",
  "severity_default": "LOW",
  "conditions": {
    "all": [
      {
        "field": "event_type",
        "operator": "EQUALS",
        "value": "LOGIN_ATTEMPT"
      }
    ]
  },
  "threshold_configuration": null,
  "time_window_seconds": null,
  "schema_version": "1.0"
}
```

## 2. Field Specifications

| Attribute | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `rule_id` | `string` | 3 - 64 chars, unique | Stable identifier for rule across versions. |
| `rule_version` | `string` | 1 - 16 chars | Monotonic version string (e.g. "1.0", "1.1"). |
| `rule_name` | `string` | 3 - 128 chars | Human-readable name displayed in SOC. |
| `description` | `string` | 5 - 2000 chars | Behavioral context and threat rationale. |
| `category` | `string` | Allowed category list | Security domain classification. |
| `detection_type` | `enum` | SINGLE_EVENT, THRESHOLD, CORRELATION | Detection evaluation topology. |
| `enabled` | `boolean` | True / False | Operational activation state. |
| `evaluation_mode`| `enum` | EVENT, SESSION, TIME_WINDOW | Scope of input events inspected. |
| `severity_default`| `enum` | INFO, LOW, MEDIUM, HIGH, CRITICAL | Baseline severity before scoring. |
| `conditions` | `object` | Logical `all` / `any` groups | Predicate tree with max depth of 3. |

