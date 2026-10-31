# Confidence Scoring Methodology

## 1. Five-Tier Confidence Framework

Confidence evaluates how strongly the available evidence supports the detection assessment:

| Rating | Score Range | Operational Meaning |
| :--- | :--- | :--- |
| **VERY LOW** | `0 – 19` | Highly provisional evidence; key fields missing, corrupted timestamps, or high contradiction. |
| **LOW** | `20 – 39` | Minimal evidence; unverified collector or unparsed metadata with weak correlation. |
| **MODERATE** | `40 – 59` | Standard evidence; valid event schema but single interaction without session depth. |
| **HIGH** | `60 – 79` | Reliable evidence; validated schema, verified session context, and consistent timestamps. |
| **VERY HIGH** | `80 – 100` | Exceptional evidence; multi-event corroboration within verified session and trusted collector. |

## 2. Weighted Component Formula

The confidence score is computed deterministically using configurable weights defined in the active `ScoringPolicyDefinition`:

$$\text{Raw Score} = \sum_{i=1}^{n} (\text{Component}_i \times \text{Weight}_i) - \text{Penalties}$$

$$\text{Confidence Score} = \max(0, \min(100, \text{round}(\text{Raw Score})))$$

### Component Weights (Default Policy v1.0):
1. **Rule Match Quality** (Weight: `0.25`):
   - Explicit predicate match against verified fields: `100 pts`.
   - Heuristic / default fallback match: `50 pts`.
2. **Event Validity** (Weight: `0.20`):
   - Passed schema validation and data integrity checks: `100 pts`.
   - Incomplete or degraded schema: `30 pts`.
3. **Source Reliability** (Weight: `0.15`):
   - Registered collector agent with ONLINE status: `100 pts`.
   - Unregistered or missing collector ID: `40 pts`.
4. **Provenance Fidelity** (Weight: `0.15`):
   - `LIVE_HONEYPOT` or `CONTROLLED_TEST`: `100 pts`.
   - `SYNTHETIC_SIMULATION`: `90 pts` (with explicit demonstration tag).
   - Unknown provenance: `40 pts`.
5. **Session Consistency** (Weight: `0.15`):
   - Verified `decoy_sess_*` tracking: `100 pts`.
   - Missing session context: `20 pts`.
6. **Timestamp Quality** (Weight: `0.10`):
   - Valid ISO-8601 UTC timestamp within clock skew bounds: `100 pts`.
   - Invalid or missing timestamp: `0 pts`.

## 3. Documented Penalties
- **Invalid Timestamp**: `-30 pts`
- **Contradictory Evidence**: `-25 pts`
- **Missing Session Context**: `-15 pts`

## 4. Fundamental Boundaries & Limitations
- Confidence represents **evidence reliability**, NOT:
  - Probability that a specific human is an adversary.
  - Probability of real-world system compromise.
  - Attribution certainty regarding a source IP address.

