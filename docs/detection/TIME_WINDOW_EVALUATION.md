# Time-Window Evaluation Foundations

## 1. Sliding Window Principles

Time-window evaluation enables detecting temporal clusters of events (e.g. brute-force login attempts or high-frequency reconnaissance) across a specified time span.

### Core Invariants:
1. **Bounded Temporal Horizons**:
   - Time window evaluations enforce a strict upper limit of 86,400 seconds (24 hours).
   - Maximum query results are capped at 200 events (`MAX_WINDOW_EVENTS = 200`).
2. **Trusted Reference Timestamps**:
   - Window calculations are anchored to the evaluation reference time (UTC).
   - Queries look backward over `[reference_time - window_seconds, reference_time]`.
3. **Late-Arriving Telemetry Handling**:
   - Events delivered with minor network delays are properly captured based on their original `observed_at` timestamp.

