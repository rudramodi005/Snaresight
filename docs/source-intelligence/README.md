# SnareSight Source Intelligence & Profiling Subsystem

## Overview
The **Source Intelligence Subsystem** (Task P23 / Prompt 23 of 40) implements systematic, multi-session source context profiling and behavioral intelligence within the SnareSight deception and threat detection platform.

Rather than treating inbound connections as isolated, ephemeral events, this subsystem correlates observed activity over time into persistent **Observed Source Profiles** (`Source Context Profiles`). It computes statistical and qualitative behavioral feature baselines, multi-window metrics, explainable similarity scores across profiles, recurrence patterns after dormant intervals, and transparent priority ratings.

---

## Key Principles & Guardrails

1. **Strict Terminology Invariant:**
   Profiles are labelled strictly as **"Observed Source Profile"** or **"Source Context Profile"**. The system **never** claims confirmed physical human identity or external threat actor attribution. An IP address is an observed network routing artifact, not proof of identity (accounting for shared proxies, NAT gateways, and VPN infrastructure).
2. **Zero Password Persistence Invariant:**
   Passwords, private credentials, and secret authentication tokens are never stored, indexed, or feature-extracted. Only username frequency and authentication failure counts are tracked.
3. **Deterministic & Explainable Scoring:**
   Profile prioritization (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `INSUFFICIENT_DATA`) and behavioral similarity metrics are fully transparent with human-readable rationale.
4. **Idempotent & Incremental Aggregation:**
   Profile calculation can be executed on-demand or incrementally without producing duplicate sessions, duplicate features, or corrupted histories.

---

## Subsystem Architecture
```
                               +----------------------------+
                               | Normalized Security Events |
                               +--------------+-------------+
                                              |
                                              v
+----------------------------+   +------------+------------+   +----------------------+
| Activity Sessions (P21)    |-->| SourceProfileAggregator |<--| Security Alerts (P16)|
+----------------------------+   +------------+------------+   +----------------------+
                                              |
                     +------------------------+------------------------+
                     |                        |                        |
                     v                        v                        v
          +--------------------+    +--------------------+   +--------------------+
          | SourceProfileModel |    | ProfileFeatures    |   | ProfileRecurrences |
          | (source_profiles)  |    | (1H, 24H, 7D, 30D) |   | (Dormancy Return)  |
          +----------+---------+    +--------------------+   +--------------------+
                     |
                     +------------------------+
                     |                        |
                     v                        v
          +--------------------+    +--------------------+
          | ProfileSessions    |    | ProfileHistory     |
          | (Junction links)   |    | (Audit & Reviews)  |
          +--------------------+    +--------------------+
```

---

## Documentation Index
1. [Architecture Overview](architecture.md)
2. [Profile Data Model](profile-data-model.md)
3. [Association Policy](association-policy.md)
4. [Behavioral Feature Extraction](behavioral-features.md)
5. [Behavioral Similarity Method](similarity-method.md)
6. [Prioritization Policy](prioritization-policy.md)
7. [API Reference](api-reference.md)
8. [Security and Privacy Guardrails](security-and-privacy.md)
9. [Testing & Verification Guide](testing.md)

