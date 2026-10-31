# Event Reconnection and Cursor-Based Replay Architecture

## 1. Cursor Architecture

SnareSight implements deterministic cursor-based reconnection to guarantee zero event loss across transient network interruptions.

### Format
The cursor string encodes the ISO-8601 UTC timestamp and UUID of the last processed event:
```
<ISO8601_TIMESTAMP>:<EVENT_UUID>
Example: 2026-10-31T14:30:00.000000+00:00:d1d36a71-6c28-4444-934c-2231ab009121
```

### Determinism & Monotonic Ordering
- Events are ordered chronologically by `observed_at ASC, event_id ASC`.
- The compound key handles multiple events sharing the exact same sub-second timestamp without skipping or duplicating records.

## 2. Replay Mechanics

1. **Reconnection Request**:
   - The client reconnects supplying the cursor via the standard `Last-Event-ID` HTTP header (or fallback query parameter `cursor` for test harness support).
2. **Cursor Parsing & Validation**:
   - `StreamCursor.parse_cursor()` validates the format and ISO-8601 validity.
   - Malformed cursors raise `StreamCursorError`, rejecting the request with HTTP 400.
3. **Database Querying**:
   - Queries `SecurityEventModel` for events where:
     `observed_at > cursor_ts OR (observed_at == cursor_ts AND event_id > cursor_uuid)`.
   - Results are capped at 500 events to prevent memory spikes.
4. **Seamless Transition**:
   - Replayed events are yielded first to the client socket.
   - Once replay catches up to current time, the subscriber transitions into listening to the real-time `asyncio.Queue`.

