# Event Validation Policy

**Document ID:** SEC-VAL-001  
**Classification:** Security Policy & Enforcement Standards  
**Scope:** SnareSight Phase 3 — Event Pipeline & Database (P13)  
**Status:** IMPLEMENTED  

---

## 1. Policy Overview

All telemetry entering the SnareSight platform must undergo deterministic validation prior to reaching any persistence layer or processing worker. Telemetry failing validation is rejected immediately with a structured diagnostic record.

---

## 2. Validation Criteria

### 1. Temporal Integrity & Clock Skew
- **Syntax:** Strict ISO-8601 UTC representation (e.g., `YYYY-MM-DDTHH:MM:SSZ` or with offset).
- **Future Skew Limit:** A maximum tolerance of **300 seconds (5 minutes)** into the future is permitted to accommodate reasonable sensor clock drift. Events dated further into the future are rejected (`CLOCK_SKEW_EXCEEDED`).
- **Historical Limit:** Events dated more than 365 days in the past require administrative override flag.

### 2. Identifier Formats
- **Raw Event ID:** Must be a valid UUIDv4 string (e.g. `3c518cfd-4d7a-4299-a417-6ffce4db6835`).
- **Session ID:** Alphanumeric string between 3 and 64 characters matching `^[a-zA-Z0-9_\-\.:]+$`.
- **Source & Decoy IDs:** Non-empty string between 2 and 64 characters registered in the active Source Registry.

### 3. Network Attributes
- **IP Address:** Must parse as valid IPv4 or IPv6 address via standard IP network libraries.
- **Port:** When present, must fall between `1` and `65535`.

### 4. Data Provenance Enumeration
The `data_provenance` attribute must exactly match one of the following authorized tokens:
- `real_attacker`: Direct external adversary activity observed on decoy.
- `internal_test`: Authorized security team testing.
- `controlled_test`: Pre-scripted lab verification activity.
- `synthetic_simulation`: Generated benchmark/simulation data (never promoted to live).
- `automated_scan`: Uncorrelated public scanning engine (e.g., Shodan, Censys).
- `research`: Academic or threat intelligence data.

Events bearing unrecognized provenance tokens are rejected with `INVALID_PROVENANCE`.

