# Username Enumeration Detection Specification (`AUTH-003`)

## 1. Objective and Threat Model
`AUTH-003` detects systematic probing of multiple user identities across a login interface. Adversaries perform username enumeration to identify valid accounts before conducting targeted credential stuffing or brute-force attacks.

---

## 2. Privacy-Safe Telemetry Design
To adhere to SnareSight's strict privacy invariants:
- **Zero Plaintext Username Requirement:** Evaluators never require or expose plaintext usernames.
- **One-Way Fingerprints:** Telemetry contains `metadata.username_fingerprint` (a SHA-256 hash or salted digest of the submitted username).
- **Non-Reversible:** Evaluators count distinct fingerprint digests without attempting decryption or dictionary lookups.

---

## 3. Evaluation Logic and Thresholds
1. Session Retrieval: Events belonging to the validated session are chronologically gathered.
2. Fingerprint Extraction: For each event in the session, `SessionEvaluator.count_distinct_username_fingerprints()` collects non-empty fingerprints.
3. Deduplication: Repeated submissions with the exact same fingerprint are treated as multiple attempts on a single identity, not enumeration.
4. Threshold Evaluation: If the count of distinct fingerprints $\ge 3$ within the session window (300s), the rule triggers `MATCHED`.
5. Explainability: The detection explanation explicitly details the count of distinct fingerprints observed.

