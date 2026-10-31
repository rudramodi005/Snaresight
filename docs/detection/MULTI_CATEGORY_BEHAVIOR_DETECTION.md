# Multi-Category Behavior Detection Specification (`BEHAV-001`)

## 1. Objective and Concept
`BEHAV-001` identifies sessions exhibiting multiple distinct categories of suspicious behavior (for example, combining web request enumeration with credential probing).

Observing multiple operational vectors within the same validated session provides substantially stronger evidence of concerted reconnaissance than isolated, single-vector interactions.

---

## 2. Detection Logic and Correlation Scope
1. Session Boundary Enforcement: `BEHAV-001` queries events bound strictly to a single `session_id`. It never combines events across different sessions based solely on a shared IP address.
2. Category Aggregation: `SessionEvaluator.count_distinct_categories()` extracts and deduplicates event categories observed in the session.
3. Threshold: Triggers when the count of distinct security categories is $\ge 2$ within a 600-second window.
4. Future ATT&CK Readiness: `BEHAV-001` preserves references to all supporting events across both categories, providing structured evidence for future attack-chain correlation (Task P22).

---

## 3. Severity and Confidence Assessment
- **Default Severity:** `HIGH`. Multi-vector activity indicates sustained engagement by an external actor.
- **Confidence:** High, backed by multiple independent observation types within the same session.

