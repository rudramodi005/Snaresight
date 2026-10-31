# Detection Threshold and Window Configuration

## 1. Configurable Parameters Overview
SnareSight avoids hardcoded magical numbers. All multi-event rules define explicit, configurable thresholds and sliding time windows tailored for small-to-medium lab environments.

| Rule ID | Parameter | Default Value | Recommended Range | Purpose |
|---|---|---|---|---|
| `AUTH-001` | `threshold` | `3` | `2 - 10` | Minimum failed attempts to trigger alert |
| `AUTH-001` | `time_window_seconds` | `300` | `60 - 3600` | Window for aggregating login failures |
| `AUTH-003` | `threshold` | `3` | `2 - 10` | Minimum distinct username fingerprints |
| `AUTH-003` | `time_window_seconds` | `300` | `60 - 3600` | Observation window for username discovery |
| `WEB-001` | `threshold` | `3` | `3 - 20` | Distinct normalized paths visited |
| `WEB-001` | `time_window_seconds` | `300` | `60 - 3600` | Window for path enumeration detection |
| `WEB-003` | `threshold` | `3` | `2 - 10` | Distinct suspicious requests |
| `BEHAV-001` | `threshold` | `2` | `2 - 4` | Distinct security categories in session |
| `BEHAV-001` | `time_window_seconds` | `600` | `120 - 7200` | Multi-category correlation window |
| All | `cooldown_seconds` | `300` | `60 - 1800` | Alert suppression interval per session |

---

## 2. Lab vs. Enterprise Context
The default thresholds are calibrated for an isolated honeypot environment where any interaction is inherently unexpected. In an isolated honeypot, 3 failed logins or 3 non-existent path requests represent clear intentional exploration, justifying alert generation without waiting for hundreds of requests.

