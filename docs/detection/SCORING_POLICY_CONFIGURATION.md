# Scoring Policy Configuration and Versioning

## 1. Declarative Structure

Scoring policies govern how severity, confidence weights, and evidence penalties are calculated. They are declaratively specified via `ScoringPolicyDefinition`:

```json
{
  "policy_id": "DEFAULT_SCORING_POLICY",
  "policy_version": "1.0",
  "policy_name": "Standard Deception Threat Assessment Policy",
  "description": "Baseline evidence-based scoring policy for SnareSight honeypot observations.",
  "enabled": true,
  "confidence_weights": {
    "rule_match_quality": 0.25,
    "event_validity": 0.20,
    "source_reliability": 0.15,
    "provenance_fidelity": 0.15,
    "session_consistency": 0.15,
    "timestamp_quality": 0.10
  },
  "penalties": {
    "invalid_timestamp": 30.0,
    "contradictory_evidence": 25.0,
    "missing_session_context": 15.0,
    "unverified_source": 20.0
  },
  "confidence_tier_boundaries": {
    "VERY_LOW": 0,
    "LOW": 20,
    "MODERATE": 40,
    "HIGH": 60,
    "VERY_HIGH": 80
  },
  "allow_critical_auto_escalation": false,
  "created_by": "system"
}
```

## 2. Invariants & Governance

1. **Weight Normalization**:
   - `confidence_weights` must sum exactly to `1.0` (validated at schema instantiation).
2. **Version Immutability**:
   - Attempting to overwrite an existing `(policy_id, version)` tuple raises `InvalidPolicyError`.
   - Modifying policy parameters requires registering an incremented version (e.g. `2.0`).
3. **Historical Auditability**:
   - Assessments store the exact `scoring_policy_id` and `scoring_policy_version` used during evaluation.
   - Deploying a new policy version does not silently rescore historical assessments.

