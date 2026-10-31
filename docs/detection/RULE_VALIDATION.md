# Detection Rule Validation Specification

## 1. Validation Lifecycle

Before any rule is accepted into the registry or evaluated against events, it must pass comprehensive syntactic, semantic, and security validation through `RuleValidator.validate_rule()`.

## 2. Validation Checks

1. **Identifier & Category Integrity**:
   - `rule_id` must be non-empty and within bounds.
   - `category` must belong to approved categories (`AUTHENTICATION`, `RECONNAISSANCE`, `EXPLOITATION`, `PERSISTENCE`, `DECEPTION`, `COMMAND_EXECUTION`, `CREDENTIAL_ACCESS`, `NETWORK`, `APPLICATION`).
2. **Prohibited Field Rejection**:
   - Condition field names are checked against `PROHIBITED_SENSITIVE_FIELDS` (`password`, `secret`, `token`, `auth_token`, etc.).
   - Matches immediately raise `RestrictedFieldError`.
3. **Approved Field Allowlist**:
   - Condition fields must exist in `FieldRegistry`. Unknown fields raise `UnsupportedFieldError`.
4. **Operator Allowlist & Operand Types**:
   - Operators must be members of the `Operator` enum.
   - `GREATER_THAN`, `LESS_THAN`, etc., strictly require numeric operands (`int` or `float`).
   - `IN` and `NOT_IN` strictly require list/tuple operands capped at 50 items.
5. **Structural Bounds**:
   - **Maximum Nesting Depth**: 3 levels.
   - **Maximum Total Conditions**: 20 conditions per rule.
   - **Maximum String Length**: 1,000 characters per string operand.

