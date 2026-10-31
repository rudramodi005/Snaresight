# Testing and Verification Guide

## 1. Test Suite Organization

The test suite for Task P23 is located in `backend/tests/modules/source_intelligence/`:

| Test Module | Coverage Area | Key Assertions |
|---|---|---|
| `test_fingerprint.py` | IP canonicalization & fingerprinting | IPv4/IPv6 RFC compliance, private/loopback vs public detection, deterministic SHA-256 tokens, display label compliance |
| `test_feature_extractor.py` | Behavioral feature calculation | Tempo calculation, burstiness ratio, concurrency level, auth failure counting, zero password persistence, traversal pattern recognition |
| `test_prioritization.py` | Profile prioritization | `INSUFFICIENT_DATA`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` decision paths, priority rationale text generation |
| `test_similarity.py` | Multi-dimensional similarity | Vector cosine alignment, Jaccard set metrics, contributing factor weights, identical vs orthogonal profiles |
| `test_recurrence.py` | Recurrence & dormancy detection | Duration string formatting, inter-session gap detection ($\ge 24\text{ hours}$), reactivation pattern similarity |
| `test_aggregator_and_service.py` | Pipeline & database persistence | Idempotent aggregation, window feature upserts, session junction creation, analyst note auditing, association updates |
| `test_api.py` | REST API endpoints | All `/api/v1/source-profiles` endpoints, query filters, search, pagination, HTTP status codes |

---

## 2. Running Backend Tests

Run all Source Intelligence tests:
```powershell
$env:PYTHONPATH="backend"
python -m unittest discover -s backend/tests/modules/source_intelligence -v
```

Run the entire regression test suite (P01–P23):
```powershell
$env:PYTHONPATH="backend"
python -m unittest discover -s backend/tests
```

**Result:**
- Total 375 tests passing cleanly (340 baseline P01–P22 + 35 P23 tests).
- 0 failures, 0 errors.

