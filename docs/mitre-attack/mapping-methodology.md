# Deception-to-ATT&CK Mapping Methodology

## Mapping Principles for Deception Telemetry
Because honeypots present deliberate attack surfaces, observed telemetry represents attacker reconnaissance and interaction rather than genuine enterprise breaches. Mappings must adhere to rigorous criteria:

1. **Behavioral Specificity**:
   - Only map rules where the trigger condition directly matches the ATT&CK technique definition.
   - Example: Multiple failed SSH login attempts cleanly map to `T1110` (Brute Force) or `T1110.001` (Password Guessing).
2. **Conservative Confidence Defaults**:
   - Direct high-fidelity telemetry receives higher confidence (e.g., 85%).
   - Generic or heuristic detections receive moderate confidence (e.g., 50-60%) and require manual review.
3. **Registry-Driven Governance**:
   - All mapping definitions are defined in code with versioning (`v1.0`).
   - Each mapping record details:
     - `rule_id`: SnareSight detection rule.
     - `technique_id`: MITRE ATT&CK technique identifier.
     - `mapping_category`: `DIRECTLY_SUPPORTED`, `PARTIALLY_SUPPORTED`, or `REQUIRES_ANALYST_REVIEW`.
     - `mapping_rationale`: Human-readable technical justification.
     - `default_confidence`: Baseline scoring percentage (0-100).

## Non-Attribution Caveat
Under no circumstances should an ATT&CK mapping be interpreted as:
- Attribution to a specific APT threat group or human adversary without external threat intelligence corroboration.
- Confirmation of internal production compromise, since honeypots are isolated decoys.

