# Detection Scenario Test Plan (Task P18)

## 1. Test Architecture and Isolation
The test suite for Task P18 validates all 10 detection scenarios across 44 automated test cases in `backend/tests/test_scenarios.py`.

Testing adheres to strict isolation standards:
- **In-Memory SQLite Database:** All tests execute against isolated, transactional in-memory database instances using `StaticPool`.
- **Zero Production Interaction:** No external network traffic, real credentials, or production services are touched.
- **Safety Mocking:** Filesystem and process execution APIs (`open`, `os.path.exists`, `subprocess.run`, `os.system`) are actively mocked where traversal, command, and file scenarios are evaluated to verify that no execution occurs.

---

## 2. Test Matrix (44 Tests)

### Authentication Group (7 Tests)
- `TEST AUTH-001`: Single failed login does not trigger repeated-failure rule.
- `TEST AUTH-002`: Configured repeated failures trigger expected detection.
- `TEST AUTH-003`: Events outside configured time window do not qualify.
- `TEST AUTH-004`: Duplicate ingestion does not inflate failure count.
- `TEST AUTH-005`: Different validated sessions remain separate.
- `TEST AUTH-006`: Decoy authentication acceptance is accurately classified.
- `TEST AUTH-007`: Simulated access is not reported as real production compromise.

### Username Enumeration Group (4 Tests)
- `TEST ENUM-001`: Repeated identical username fingerprint handled correctly.
- `TEST ENUM-002`: Distinct username fingerprints counted according to policy.
- `TEST ENUM-003`: Missing username metadata does not create false match.
- `TEST ENUM-004`: Plaintext usernames not required for detection.

### Web Path Enumeration Group (4 Tests)
- `TEST WEB-DET-001`: Repeated distinct path categories trigger configured rule.
- `TEST WEB-DET-002`: Repeated access to one path assessed correctly.
- `TEST WEB-DET-003`: Normalized equivalent paths not double-counted unnecessarily.
- `TEST WEB-DET-004`: Ordinary missing-resource requests do not become high-severity alerts.

### Directory Traversal Group (5 Tests)
- `TEST TRAV-001`: Known safe traversal indicators recognized.
- `TEST TRAV-002`: Encoded traversal representations handled correctly.
- `TEST TRAV-003`: Benign path strings do not produce unsupported matches.
- `TEST TRAV-004`: Detection does not access filesystem.
- `TEST TRAV-005`: No submitted path is executed.

### Command Interaction Group (3 Tests)
- `TEST CMD-001`: Supported command-category event classified correctly.
- `TEST CMD-002`: Unsupported command telemetry rejected or deferred safely.
- `TEST CMD-003`: Recorded command text is never executed.

### File Interaction Group (4 Tests)
- `TEST FILE-001`: Supported transfer metadata generates expected finding.
- `TEST FILE-002`: Missing transfer fields handled correctly.
- `TEST FILE-003`: No uploaded file is executed.
- `TEST FILE-004`: No unnecessary file contents persisted.

### Behavioral and Correlation Group (5 Tests)
- `TEST BEHAV-001`: Multiple distinct suspicious categories identified.
- `TEST BEHAV-002`: Unrelated sessions not combined.
- `TEST BEHAV-003`: Duplicate observations do not inflate evidence.
- `TEST BEHAV-004`: Repeated suspicious requests evaluated correctly.
- `TEST BEHAV-005`: False-positive suppression works as configured.

### Scoring and Provenance Group (5 Tests)
- `TEST SCORE-001`: Severity generated using P17 assessment service.
- `TEST SCORE-002`: Confidence generated independently of severity.
- `TEST SCORE-003`: Evidence strength preserved.
- `TEST SCORE-004`: Explanation matches actual evidence.
- `TEST SCORE-005`: Synthetic provenance remains visible.

### Alert Generation and Streaming Group (7 Tests)
- `TEST ALERT-001`: Matching detection generates alert where configured.
- `TEST ALERT-002`: Nonmatching detection does not generate alert.
- `TEST ALERT-003`: Duplicate alert generation prevented via cooldown.
- `TEST ALERT-004`: Rule version retained in persistent record.
- `TEST ALERT-005`: Supporting event references remain valid in junction table.
- `TEST ALERT-006`: Streaming notification occurs post-commit over SSE channel.
- `TEST ALERT-007`: Streaming failure does not delete or roll back persistent alert.

