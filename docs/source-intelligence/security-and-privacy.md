# Security and Privacy Guardrails

## 1. Zero Password Persistence Invariant
The SnareSight platform enforces strict credential safety invariants across all telemetry ingestion, storage, and profiling layers:
- Passwords, plaintext passphrases, API secrets, and private keys submitted to honeypots are **never** stored in the database.
- Database schemas are validated by `test_03_zero_password_columns_exist_across_all_models` in `test_models.py` to ensure no password columns exist in any table.
- The behavioral feature extractor (`feature_extractor.py`) inspects only username strings, counting distinct accounts attempted. Credentials and tokens are discarded immediately.
- Automated tests (`test_zero_password_persistence_enforced`) verify that sensitive credentials in mock event payloads do not leak into feature dictionaries or database columns.

---

## 2. Prohibition of External Deanonymization & Outbound Probing
The Source Intelligence Subsystem operates strictly on **inbound passive deception telemetry**:
- **No Outbound Scanning:** The system does not port-scan, fingerprint, or probe the observed source host.
- **No Third-Party Deanonymization:** External geolocation lookups (e.g. MaxMind, IPinfo) or threat-actor attribution APIs are prohibited unless sanitized and specifically authorized.
- **Local Network Safety:** Canonicalization distinguishes between private/loopback and routable IP ranges via standard library functions (`ipaddress.ip_address`), with zero external network dependencies.

---

## 3. Labeling and Attribution Guardrails
To prevent misattribution and flawed forensic conclusions:
- The system labels every source entity as an **Observed Source Profile** or **Source Context Profile**.
- Under no circumstance does the UI or API label a profile as a "confirmed attacker", "hacker identity", or "attributed nation-state actor".
- The system explicitly supports flagging shared infrastructure (`is_shared_infrastructure = true`), recognizing that proxies, NAT gateways, and VPN services bundle multiple distinct actors behind a single IP address.

