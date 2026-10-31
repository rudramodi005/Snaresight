# Security Events Search and Filtering

## 1. Multi-Attribute Filtering Engine

The `SecurityEventsService` supports fine-grained, concurrent filtering across multiple telemetry dimensions:

| Filter Parameter | Target Column | Supported Values / Format | Index Used |
|:---|:---|:---|:---|
| `start_time` | `observed_at` | ISO 8601 UTC timestamp | `idx_sec_events_src_time` |
| `end_time` | `observed_at` | ISO 8601 UTC timestamp | `idx_sec_events_src_time` |
| `category` | `event_category` | `AUTHENTICATION`, `RECONNAISSANCE`, `EXPLOITATION`, `COMMAND_EXECUTION`, `NETWORK_PROBE` | `ix_security_events_event_category` |
| `event_type` | `event_type` | Canonical event identifier (e.g. `LOGIN_ATTEMPT`, `PORT_SCAN`) | `ix_security_events_event_type` |
| `sensor_id` | `decoy_id` | Honeypot decoy ID (e.g. `WEB-001`, `SSH-001`) | `ix_security_events_decoy_id` |
| `protocol` | `source_protocol` | `TCP`, `UDP`, `HTTP`, `SSH` | None (filtered in scan) |
| `source_address` | `source_address` | Exact IPv4 / IPv6 address | `idx_sec_events_src_time` |
| `session_id` | `session_id` | Correlated session identifier | `ix_security_events_session_id` |
| `outcome` | `outcome` | `SUCCESS`, `FAILURE`, `BLOCKED`, `ERROR`, `UNKNOWN` | `ix_security_events_outcome` |
| `detection_status` | `AlertEvidenceModel` | `DETECTED` (has alerts) or `NORMAL` (clean) | Outer join on `event_id` |
| `severity` | `AlertModel.severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` | Outer join on `AlertEvidenceModel` |

---

## 2. Global Text Search

Free-text search executes bounded `ILIKE` queries across indexed high-cardinality fields:
- `source_address`
- `event_type`
- `event_category`
- `decoy_id`
- `action`
- `session_id`

Arbitrary raw SQL execution is strictly forbidden. The input query is sanitized and bounded to prevent database denial-of-service.

---

## 3. Server-Side Pagination & Sorting

To protect backend resources:
- `page`: 1-based page number (default 1).
- `page_size`: Bounded between 1 and 100 items (default 25).
- `sort_by`: Permitted on indexed columns (`observed_at`, `event_type`, `source_address`).
- `sort_order`: `asc` or `desc` (default `desc`).

