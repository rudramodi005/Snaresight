# Detection Rule Registry Specification

## 1. Registry Architecture

The `RuleRegistry` provides an in-memory, thread-safe, and version-aware registry for all active and historical detection rules:

- **Storage Structure**:
  `{rule_id: {version: DetectionRuleDefinition}}`
- **Active Version Pointer**:
  `{rule_id: latest_version_str}`

## 2. Invariants & Capabilities

1. **Version Immutability**:
   - Registering a rule with an existing `(rule_id, version)` tuple raises `DuplicateRuleError`.
   - Historical versions cannot be overwritten in place; rule modifications must publish a new version string.
2. **Operational Toggling**:
   - Rules can be enabled or disabled at runtime via `set_rule_enabled()`.
   - Disabled rules remain stored but are excluded from `list_enabled_rules()`.
3. **Historical Retrieval**:
   - Evaluators or audit services can query any historical rule version by specifying `version="1.0"`.

