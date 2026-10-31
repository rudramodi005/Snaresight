# Threat Assessment & Scoring Test Results

## 1. Execution Summary

- **Test Suite**: `backend/tests/test_scoring.py`
- **Execution Mode**: Pytest / Unittest
- **Tests Executed**: 40
- **Status**: 40 Passed, 0 Failed, 0 Skipped
- **Execution Duration**: 0.604s

## 2. Test Verification Matrix

| Test ID | Category | Description | Result |
| :--- | :--- | :--- | :--- |
| **TEST SCORE-001** | Severity | Baseline severity assigned from rule default | PASS |
| **TEST SCORE-002** | Severity | LOW severity within bounds [20, 39] | PASS |
| **TEST SCORE-003** | Severity | MEDIUM severity within bounds [40, 59] | PASS |
| **TEST SCORE-004** | Severity | HIGH severity requires configured criteria | PASS |
| **TEST SCORE-005** | Severity | CRITICAL severity requires explicit policy support | PASS |
| **TEST SCORE-006** | Severity | Severity is not derived from confidence | PASS |
| **TEST SCORE-007** | Severity | Severity score clamped between 0 and 100 | PASS |
| **TEST SCORE-008** | Confidence | Confidence score stays within 0–100 | PASS |
| **TEST SCORE-009** | Confidence | Valid evidence produces expected high score | PASS |
| **TEST SCORE-010** | Confidence | Missing evidence does not receive maximum points | PASS |
| **TEST SCORE-011** | Confidence | Invalid timestamps apply documented penalty | PASS |
| **TEST SCORE-012** | Confidence | Duplicate evidence does not increase confidence | PASS |
| **TEST SCORE-013** | Confidence | Independent corroboration handled correctly | PASS |
| **TEST SCORE-014** | Confidence | Contradictory evidence triggers penalty | PASS |
| **TEST SCORE-015** | Confidence | Source reliability reflected in score | PASS |
| **TEST SCORE-016** | Confidence | Unknown provenance receives lower score | PASS |
| **TEST SCORE-017** | Confidence | Synthetic provenance clearly identified | PASS |
| **TEST SCORE-018** | Confidence | Confidence and severity remain independent | PASS |
| **TEST SCORE-019** | Evidence | Evidence strength classified into 4 tiers | PASS |
| **TEST SCORE-020** | Evidence | Insufficient evidence not presented as strong | PASS |
| **TEST SCORE-021** | Evidence | Supporting event IDs remain traceable | PASS |
| **TEST SCORE-022** | Evidence | Evidence references remain valid pointers | PASS |
| **TEST SCORE-023** | Explanation | Severity explanation generated dynamically | PASS |
| **TEST SCORE-024** | Explanation | Confidence explanation generated dynamically | PASS |
| **TEST SCORE-025** | Explanation | Explanations reference real scoring factors | PASS |
| **TEST SCORE-026** | Explanation | No misleading claims of real-system compromise | PASS |
| **TEST SCORE-027** | Policy | Valid policy loads correctly | PASS |
| **TEST SCORE-028** | Policy | Invalid policy (weights != 1.0) rejected | PASS |
| **TEST SCORE-029** | Policy | Policy versions preserved immutably | PASS |
| **TEST SCORE-030** | Policy | Re-registering existing version rejected | PASS |
| **TEST SCORE-031** | Policy | Historical assessment retains original policy | PASS |
| **TEST SCORE-032** | Integration | Detection result reaches scoring service | PASS |
| **TEST SCORE-033** | Integration | Assessment persists and is retrievable | PASS |
| **TEST SCORE-034** | Integration | Scoring failure does not delete database events | PASS |
| **TEST SCORE-035** | Integration | Duplicate assessments prevented (idempotency) | PASS |
| **TEST SCORE-036** | Integration | Reassessment creates traceable history entry | PASS |
| **TEST SCORE-037** | Security | Passwords never included in assessments | PASS |
| **TEST SCORE-038** | Security | Secrets unavailable to scoring engine | PASS |
| **TEST SCORE-039** | Security | User expressions cannot execute code | PASS |
| **TEST SCORE-040** | Review | Analyst review does not overwrite original score | PASS |

