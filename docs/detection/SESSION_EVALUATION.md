# Session-Level Evaluation Foundations

## 1. Principles of Session Evaluation

SnareSight supports multi-event behavioral correlation across an interaction session.

### Core Invariants:
1. **Validated Session Identity**:
   - Interactions are grouped strictly by `session_id`.
   - Events sharing the same source IP but distinct session IDs are **never merged**.
2. **Chronological Ordering**:
   - Events within a session are retrieved and evaluated strictly in ascending observed timestamp order (`observed_at ASC`).
3. **Bounded Query Limits**:
   - Querying session telemetry is hard-capped at 100 events (`MAX_SESSION_EVENTS = 100`) to guarantee deterministic memory and latency.

