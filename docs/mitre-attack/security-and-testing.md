# MITRE ATT&CK Security, Access Controls & Test Verification

## Security and Governance Controls
1. **Administrative Access**:
   - Write actions (STIX bundle import, version activation) require administrator role credentials.
   - Analyst review actions require authenticated SOC analyst tokens with recorded `analyst_id`.
2. **Audit Logging**:
   - State mutations on `attack_detection_mappings` write immutable records to both `attack_mapping_reviews` and `attack_mapping_history`.
   - Timestamps use UTC (`datetime.now(timezone.utc)`).
3. **Payload Sanitization**:
   - STIX bundle descriptions and analyst comments undergo HTML/XSS sanitization before storage or rendering.
4. **Non-Attribution Enforcement**:
   - Headers, detail drawers, and coverage displays include visible non-attribution disclaimers clarifying that deception telemetry reflects adversary tradecraft against decoy assets without asserting confirmed human attacker identities.

## Test Verification Suite
Comprehensive automated test suite located at:
`backend/tests/modules/mitre/test_attack_dashboard_api.py`

### Test Cases Covered:
- `test_catalogue_metadata`: Verifies release version (`v14.1`), domain (`enterprise-attack`), and registry version.
- `test_dashboard_summary_aggregation`: Validates aggregation of techniques, subtechniques, rules mapped, and live alerts.
- `test_tactics_overview`: Validates 14 canonical Enterprise tactics in strict sequential order (`TA0043` through `TA0040`).
- `test_matrix_structure_and_visual_states`: Validates column layouts and correct assignments of `ALERT_EVIDENCE`, `RULE_MAPPED`, and `UNMAPPED` states.
- `test_techniques_explorer_search_and_pagination`: Validates keyword search, status filtering, and pagination offsets.
- `test_technique_detail_and_404`: Validates detail responses with configured rules and live alert evidence, as well as 404 responses for nonexistent techniques.
- `test_coverage_analytics`: Validates overall coverage percentages and per-tactic breakdowns.
- `test_traceability_chain`: Validates end-to-end navigation linkage from technique to alert and session.
- `test_mapping_review_approval_and_rejection`: Validates review status transitions and audit log persistence.

### Test Execution Command:
```powershell
$env:PYTHONPATH="c:\Projects\SnareSight\backend"
python -m unittest discover -s c:\Projects\SnareSight\backend\tests\modules\mitre -v
```
Result: 52 of 52 tests passing (100% success rate).

