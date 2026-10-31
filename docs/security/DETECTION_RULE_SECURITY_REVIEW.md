# Detection Rule Security and Safety Review

## 1. Security Scope and Review Objectives
This security review assesses the attack resistance, isolation boundaries, and operational safety of the SnareSight threat detection and alert generation subsystem.

---

## 2. Security Invariant Verification

### Invariant 1: No Arbitrary Code or Dynamic Evaluation
- **Analysis:** Rules are declarative JSON/Pydantic data models validated by `RuleValidator`.
- **Finding:** No `eval()`, `exec()`, or dynamic code execution exists in the detection engine. Comparisons use allowlisted Python operators strictly bound to approved operand types.

### Invariant 2: Host Filesystem and Process Isolation
- **Analysis:** Evaluators inspect strings (`metadata.http_path`, `metadata.command_text`).
- **Finding:** `os.path.exists`, `open()`, and `subprocess` are never invoked on inputs. Tested and verified in `test_trav_004`, `test_trav_005`, and `test_cmd_003`.

### Invariant 3: Zero Password Persistence & Prohibited Field Denylist
- **Analysis:** `FieldRegistry` maintains an explicit denylist (`password`, `password_hash`, `secret`, `api_key`, `credentials`, etc.). Any rule targeting these is rejected with `RestrictedFieldError`.
- **Finding:** Tested and confirmed in `test_detection.py` and `test_scenarios.py`.

### Invariant 4: Transactional Decoupling of Live Streaming
- **Analysis:** SSE frames (`event: security_alert`) are emitted post-commit.
- **Finding:** If an SSE subscriber's queue overflows or network delivery fails, the database alert transaction remains safely committed and immutable.

### Invariant 5: Simulated Decoy Finding Clarity
- **Analysis:** Alerts generated from decoy interactions could potentially cause unwarranted incident escalations if misread as production breaches.
- **Finding:** `AlertModel.recommendations` and finding titles explicitly categorize interactions as occurring within an isolated honeypot environment.

