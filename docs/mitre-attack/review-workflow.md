# Analyst Mapping Review and Triage Workflow

## Purpose
While automated rules associate telemetry with ATT&CK techniques, human oversight is critical to ensure classification fidelity. The mapping review workflow enables SOC analysts to validate or contest machine-generated associations.

## Permitted Review Actions
Enforced by PostgreSQL check constraints on `attack_mapping_reviews`:
1. `APPROVE` (`ACCEPT`):
   - Confirms that the telemetry evidence accurately exemplifies the ATT&CK technique.
   - Transitions `review_status` to `ACCEPTED`.
2. `REJECT` (`REJECT`):
   - Disqualifies the mapping as a false correlation or inappropriate technique assignment.
   - Transitions `review_status` to `REJECTED`.
3. `REQUEST_REVIEW` (`REQUEST_MORE_EVIDENCE`):
   - Flags that evidence is ambiguous and requires deeper sensor packet capture or multi-event correlation.
   - Transitions `review_status` to `PENDING` (or `NEEDS_MORE_EVIDENCE`).

## Audit Trail Persistence
Every review decision records:
- An entry in `attack_mapping_reviews` with `reviewer_id`, `review_action`, `previous_status`, `new_status`, `review_comment`, and timestamps.
- An entry in `attack_mapping_history` documenting the change reason, confidence, dataset version, and recorded timestamp.
- Updated fields on `attack_detection_mappings`: `reviewed_by`, `reviewed_at`, `review_comment`, and `review_status`.

