# Analyst Review Model

## 1. Dual-Track Assessment Architecture

To preserve machine-learning-free determinism while empowering human SOC operators, SnareSight separates:

1. **Automated Assessment**: Immutable evaluation derived deterministically from scoring policies.
2. **Analyst Review**: Optional human review structure attached to the assessment.

```json
{
  "analyst_review": {
    "reviewed": true,
    "reviewer_id": "analyst_alice",
    "reviewed_at": "2026-10-31T12:00:00.000000+00:00",
    "proposed_severity": "HIGH",
    "proposed_confidence": 95,
    "review_reason": "External threat intel correlation confirmed high-threat scanner group",
    "approval_status": "APPROVED"
  }
}
```

## 2. Invariants
- The original `severity_level` and `confidence_score` assigned by the automated engine are preserved.
- Analyst overrides are captured in `analyst_review.proposed_severity` and `proposed_confidence`, ensuring full transparency between system logic and human decision-making.

