# Behavioral Feature Extraction & Baselines

## 1. Overview
The **Behavioral Feature Extractor** (`feature_extractor.py`) derives quantitative and qualitative metrics from validated honeypot telemetry and correlated sessions. Metrics are calculated across five standard time horizons (`1H`, `24H`, `7D`, `30D`, `ALL_TIME`).

---

## 2. Feature Dimensions

### A. Interaction Dynamics & Tempo
- **`interaction_tempo` (Events per Active Minute):**
  - Measures the transmission velocity of inbound requests during periods of activity.
  - Formula: $\text{Tempo} = \frac{\text{Total Events}}{\max(\Delta t_{\text{minutes}}, 1.0)}$
  - Automated scanners typically present high tempo ($> 60\text{ ev/min}$), whereas human operators show deliberate pacing ($< 10\text{ ev/min}$).
- **`burstiness_ratio`:**
  - Evaluates whether traffic arrives in sudden bursts vs steady rates.
  - Ratio of peak 1-minute bucket count to the average 1-minute count.
- **`concurrency_level`:**
  - Maximum count of overlapping active sessions.
  - Indicates parallel multi-threaded scanning or multi-endpoint tooling.

### B. Authentication Exploration
- **`auth_attempt_count` & `auth_failure_count`:**
  - Frequency of login interactions and resultant failure outcomes.
- **`distinct_usernames_count`:**
  - Tracks the breadth of user accounts probed (e.g., `root`, `admin`, `test`, `ubnt`).
  - High distinct username count with high failure rate strongly indicates **credential spraying** (MITRE T1110.003).
  - *Invariant:* Passwords and secret values are **never** extracted or persisted.

### C. Reconnaissance & Traversal Probes
- **`path_traversal_probes`:**
  - Counts events containing classic directory traversal or command injection tokens:
    - Path indicators: `..`, `%2e%2e`, `/etc/passwd`, `/etc/shadow`, `boot.ini`, `win.ini`
    - Shell execution: `cmd.exe`, `powershell`, `/bin/sh`, `/bin/bash`
- **`distinct_paths_probed`:**
  - Total unique URI paths, endpoints, or commands requested.
- **`distinct_honeypots_targeted`:**
  - Number of distinct decoys targeted (e.g. SSH Bastion + Web Portal + MySQL Honeypot).
  - Multi-decoy targeting indicates lateral movement or comprehensive network scanning.

### D. Threat Intelligence Distributions
- **`tactic_distribution`:** JSON map of MITRE ATT&CK tactic codes to counts (e.g., `{"TA0001": 5, "TA0007": 12}`).
- **`technique_distribution`:** JSON map of MITRE technique IDs to counts (e.g., `{"T1110": 10, "T1059": 3}`).
- **`severity_breakdown`:** Distribution of triggered alerts across severity levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).

