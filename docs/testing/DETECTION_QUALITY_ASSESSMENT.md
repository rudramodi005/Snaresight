# Detection Quality Assessment

## 1. Quality Evaluation Dimensions
SnareSight evaluates detection scenarios against five core quality dimensions:
1. **Explainability:** Does every detection result clearly explain what was observed, which conditions matched, and what supporting evidence exists?
2. **Precision and Boundary Isolation:** Are session boundaries strictly respected? Are unrelated events from distinct sessions prevented from merging?
3. **Resilience to Anti-Forensics:** Are URL encodings and trailing slash variances canonicalized to prevent enumeration bypass?
4. **Zero-Secret Invariant:** Are plaintext credentials completely absent from rule definitions, metadata extraction, alert summaries, and streaming notifications?
5. **Operational Safety:** Are adversarial inputs treated as passive data rather than instructions or code?

---

## 2. Assessment Findings
- **High Explainability:** Detection results provide full condition diagnostics and link triggering and correlated observations directly to `AlertEvidenceModel`.
- **Zero Ingestion Leakage:** Plaintext passwords and secrets are completely rejected during ingestion and never enter the detection pipeline.
- **Strict Session Scoping:** Session boundaries are verified in unit tests; no cross-session pollution occurs.
- **Reliable Suppression:** Cooldown suppression prevents alert floods while maintaining an auditable trail of suppressed candidate alerts.

