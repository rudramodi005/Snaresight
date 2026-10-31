# Campaign Intelligence Verification & Testing

## Overview
Comprehensive test suites verify the Campaign Intelligence subsystem, covering scoring algorithms, lifecycle state machine enforcement, automated clustering, non-destructive merge and split operations, unified timeline construction, and REST APIs.

Test Directory: `backend/tests/modules/campaign_intelligence/`

---

## 1. Test Suites & Coverage

| Test File | Focus Area | Tests | Status |
|:---|:---|:---:|:---:|
| `test_scoring.py` | `RelationshipScorer`: signal evaluation, contradiction deductions, clamping, confidence level mapping | 5 | PASSED |
| `test_lifecycle.py` | `ClusterLifecycleManager`: state transitions, invalid transition rejection, audit log verification | 3 | PASSED |
| `test_clustering_engine.py` | `ClusteringEngine`: automated candidate discovery, entity association, shared indicator calculation | 1 | PASSED |
| `test_merge_and_split.py` | Non-destructive cluster merges, entity migration, audit trail, partial cluster split | 4 | PASSED |
| `test_timeline.py` | `InvestigationTimelineBuilder`: multi-source telemetry ordering, chronological consistency | 2 | PASSED |
| `test_api.py` | FastAPI REST routes: CRUD, status transition, membership management, evidence attachment, merge, split, timeline | 11 | PASSED |
| `test_models.py` | Model table registration, foreign keys, table counts (42 tables total) | 5 | PASSED |

**Total Campaign Intelligence Tests:** 26  
**Total Module Tests (MITRE + Source + Campaign):** 107  
**Total Platform Regression Tests:** 447  
**Result:** 100% Passed, 0 Failures, 0 Errors.

---

## 2. Running the Test Suites

### Execute Campaign Intelligence Tests Only:
```powershell
$env:PYTHONPATH="c:\Projects\SnareSight\backend"
python -m unittest discover -s c:\Projects\SnareSight\backend\tests\modules\campaign_intelligence -v
```

### Execute All Module Tests:
```powershell
$env:PYTHONPATH="c:\Projects\SnareSight\backend"
python -m unittest discover -s c:\Projects\SnareSight\backend\tests\modules -v
```

### Execute Full Platform Regression Suite:
```powershell
$env:PYTHONPATH="c:\Projects\SnareSight\backend"
python -m unittest discover -s c:\Projects\SnareSight\backend\tests
python -m unittest discover -s c:\Projects\SnareSight\backend\tests\modules
```

---

## 3. Verified Invariants
- State machine forbids illegal transitions (e.g., `CLOSED` directly to `MERGED` or `SPLIT` directly to `ACTIVE`).
- Merges retain the source cluster with status `MERGED` and set `merged_into_id`.
- Splits produce a new cluster with `split_from_id` while retaining unselected members in the original cluster.
- All relationships produce deterministic confidence scores between `0.0` and `1.0`.
- Passwords are never persisted in raw form in any evidence or indicators table.

