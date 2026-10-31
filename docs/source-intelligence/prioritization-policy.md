# Profile Prioritization Policy

## 1. Overview
The **Profile Prioritization Engine** (`prioritization.py`) assigns a deterministic priority tier to each Observed Source Profile based strictly on observable deception telemetry, detection alerts, and feature metrics.

Priority is decoupled from human assumptions and subjective analyst bias.

---

## 2. Priority Tiers and Decision Matrix

### `INSUFFICIENT_DATA`
- **Criteria:** Observed activity has fewer than 2 total events or 0 correlated sessions.
- **Rationale:** Probing is too sparse to evaluate behavioral posture or establish reliable baselines.

### `CRITICAL`
- **Criteria (any of):**
  - Triggered 1 or more confirmed `CRITICAL` security alerts.
  - Multi-decoy lateral targeting across 2+ decoys with 2+ `HIGH` alerts.
  - High-velocity combined credential spray ($\ge 30$ failures) AND directory traversal probes ($\ge 5$).
- **Action Required:** Immediate SOC escalation and triage.

### `HIGH`
- **Criteria (any of):**
  - Triggered 1 or more `HIGH` security alerts.
  - Broad reconnaissance spanning 3 or more distinct honeypot decoys.
  - Credential spraying behavior: $\ge 10$ failed attempts across $\ge 5$ distinct usernames.
  - Repeated path traversal or command execution probes ($\ge 3$).
- **Action Required:** Active threat hunt review; check for internal network pivot attempts.

### `MEDIUM`
- **Criteria (any of):**
  - Triggered 1 or more `LOW` or `MEDIUM` security alerts.
  - Persistent multi-session engagement ($\ge 3$ sessions or $\ge 20$ events).
  - Targeted path exploration ($\ge 1$ traversal probe or $\ge 2$ usernames probed) without high-severity triggers.
- **Action Required:** Monitored baseline; watch for recurrence or escalation.

### `LOW`
- **Criteria:** Low-volume interactions with no elevated detection alerts or exploit signatures.
- **Rationale:** Isolated connection attempt, casual port ping, or minimal non-intrusive traffic.

---

## 3. Priority Rationale Traceability
Every priority assignment generates an immutable, transparent `priority_rationale` string stored in `SourceProfileModel.behavioral_summary['priority_rationale']`.

Example:
> *"Multi-decoy targeting across 3 honeypots with 2 HIGH-severity security alerts."*

