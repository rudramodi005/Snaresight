# SnareSight Backend Testing Architecture & Execution

## 1. Scope & Test Framework

The SnareSight backend testing architecture is built on Python's native `unittest` and `pytest`-compatible fixtures. The tests run against an isolated in-memory SQLite datastore utilizing SQLAlchemy 2.0 declarative models and StaticPool isolation, ensuring sub-second execution without state leakage between test classes.

---

## 2. Tested Backend Domains

1. **Event Ingestion Pipeline (`tests/test_ingestion.py`)**:
   - Ingestion batch intake with collector `X-API-Key` verification.
   - Idempotency & SHA-256 fingerprint deduplication.
   - `SensitiveDataInspector` credential rejection (prohibiting raw passwords).
   - Provenance environment and decoy registration verification.
2. **Behavioral Detection Engine (`tests/test_detection.py`, `tests/test_scenarios.py`, `tests/test_scoring.py`)**:
   - Deterministic rule scenario evaluation (18 rules).
   - Severity and confidence metric calculation.
   - Evidence binding and explainability trace generation.
3. **Session Correlation & Identity (`tests/modules/correlation/`)**:
   - Explicit session correlation.
   - Inactivity timeout boundaries and cross-session identity clustering.
   - Strict avoidance of IP-only attribution.
4. **MITRE ATT&CK Mapping (`tests/modules/mitre/`)**:
   - STIX 2.1 JSON parsing and technique indexing.
   - Rule-to-technique confidence scoring.
   - Analyst mapping review lifecycle.
5. **Defensive Response Management (`tests/modules/response/`)**:
   - Case lifecycle state transitions (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED`).
   - Dual-analyst approval enforcement for sensitive actions.
   - Statutory evidence preservation holds.
6. **Honeypot Sensor Operations (`tests/modules/sensors/`)**:
   - Cryptographic HMAC authentication and key rotation.
   - Heartbeat health state engine (`ACTIVE`, `DEGRADED`, `OFFLINE`).
   - Versioned configuration rollbacks.
7. **Platform Resilience & Recovery (`tests/modules/resilience/`)**:
   - 7 internal control-plane detection rules.
   - Checksummed database backup generation.
   - Isolated sandbox restore verification (zero production table mutations).
   - 5 failure scenario runbooks.

---

## 3. Execution Commands

```powershell
cd c:\Projects\SnareSight\backend
$env:PYTHONPATH="c:\Projects\SnareSight\backend"

# Run full backend discovery suite (357 tests)
python -m unittest discover -s tests -p "test_*.py"

# Run specific domain suite
python -m unittest discover -s tests/modules/resilience -p "test_*.py"
python -m unittest discover -s tests/modules/sensors -p "test_*.py"
python -m unittest discover -s tests/modules/e2e_workflows -p "test_*.py"
```

