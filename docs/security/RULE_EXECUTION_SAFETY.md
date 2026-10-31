# Rule Execution Safety and Operator Isolation

## 1. Safe Operator Isolation

SnareSight implements a strictly bounded predicate evaluator in `ConditionEvaluator`. Every condition must map to a member of the `Operator` enumeration:

- `EQUALS` / `NOT_EQUALS`: Case-insensitive string matching or literal scalar equality.
- `CONTAINS` / `STARTS_WITH` / `ENDS_WITH`: Native Python string/collection inspection.
- `GREATER_THAN` / `LESS_THAN`: Float/integer numerical comparisons.
- `IN` / `NOT_IN`: Membership tests in explicit literal arrays.
- `EXISTS` / `NOT_EXISTS`: Null and emptiness checks.

## 2. Prohibited Paradigms

Under no circumstances does the engine support:
1. Dynamic code evaluation (`eval()`, `exec()`).
2. Regular expressions without complexity bounds.
3. Lambdas or function calls in rule payloads.
4. Shell process invocation (`subprocess`, `os.system`).
5. Direct raw SQL execution.

