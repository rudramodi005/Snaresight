# Security Events Explorer Verification & Testing

## Overview
Comprehensive test suites verify the Security Events Explorer, covering database models, multi-attribute filtering, server-side pagination, free-text search, credential redaction, relationship mapping, session timelines, multi-event comparison, analyst notes, and investigation associations.

Test Directory: `backend/tests/modules/security_events/`

---

## 1. Test Suite Breakdown

| Test File | Focus Area | Tests | Status |
|:---|:---|:---:|:---:|
| `test_security_events_api.py` | `TestSecurityEventsListingAndFiltering`: empty DB, pagination, sorting, category/sensor/outcome filters, search, detection/severity filters | 6 | PASSED |
| `test_security_events_api.py` | `TestSecurityEventDetailAndRedaction`: detail response, sensitive field redaction, 404 handling | 2 | PASSED |
| `test_security_events_api.py` | `TestSecurityEventRelationshipsAndTimeline`: cross-entity relationship mapping, session chronological timeline | 2 | PASSED |
| `test_security_events_api.py` | `TestSecurityEventComparisonAndAudit`: multi-event comparison, analyst notes, review status updates, cluster association, summary | 3 | PASSED |
| `test_models.py` | Model table registration, `event_audit_logs` table constraint verification (43 registered tables total) | 5 | PASSED |

**Total Security Events Tests:** 13  
**Total Module Tests (MITRE + Source + Campaign + Events):** 120  
**Total Platform Regression Tests:** 460  
**Result:** 100% Passed, 0 Failures, 0 Errors.

---

## 2. Running the Test Suites

### Execute Security Events Tests Only:
```powershell
$env:PYTHONPATH="c:\Projects\SnareSight\backend"
python -m unittest discover -s c:\Projects\SnareSight\backend\tests\modules\security_events -v
```

### Execute Full Platform Regression Suite:
```powershell
$env:PYTHONPATH="c:\Projects\SnareSight\backend"
python -m unittest discover -s c:\Projects\SnareSight\backend\tests
python -m unittest discover -s c:\Projects\SnareSight\backend\tests\modules
```

