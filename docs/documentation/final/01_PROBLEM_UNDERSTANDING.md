# Evaluation Criterion 1: Problem Understanding & Domain Context

**Document Version:** 1.0.0  
**Phase:** 8 — Testing, Demonstration & Project Handover  
**Document:** `docs/final/01_PROBLEM_UNDERSTANDING.md`  
**Evaluation Weight:** 20% (Equal Weighting)  

---

## 1. Concise Problem Statement (For Presentation Slide)

> Modern Security Operations Centers (SOCs) are overwhelmed by thousands of ambiguous perimeter alerts daily, resulting in severe analyst fatigue and missed multi-stage intrusions. 
> 
> Conventional perimeter defenses suffer from a poor signal-to-noise ratio because they must inspect vast volumes of legitimate business traffic. 
> 
> **SnareSight** solves this asymmetric challenge through **high-fidelity cyber deception**. By deploying isolated decoy assets with zero legitimate business utility, SnareSight converts unauthorized interaction into unambiguous, explainable threat intelligence—enabling analysts to reconstruct attack progression, map verified tradecraft to MITRE ATT&CK®, and coordinate rapid defensive containment without alert fatigue.

---

## 2. Limitations of Conventional Perimeter-Based Detection

Traditional enterprise security models rely heavily on perimeter firewalls, Web Application Firewalls (WAFs), Intrusion Detection Systems (IDS), and Endpoint Detection & Response (EDR) agents. While essential, perimeter-only defenses exhibit critical structural limitations:

1. **The Signal-to-Noise Problem:** In a typical enterprise network, $>99.9\%$ of observed network traffic and system calls represent legitimate business operations. Perimeter tools must evaluate massive telemetry streams to find rare malicious needles, resulting in thousands of false positives and alert fatigue.
2. **Encrypted & Evasive Traffic:** Modern adversaries bypass signature-based WAFs and IDSs using encrypted HTTPS channels, living-off-the-land binaries (LOLBins), domain fronting, and polymorphic payloads.
3. **Delayed Intruder Discovery:** Industry threat reports consistently highlight that adversary dwell time (the duration between initial network compromise and detection) frequently averages weeks or months.
4. **Lack of Early Threat Intent Visibility:** Perimeter filters typically drop malicious packets immediately, providing security teams with zero visibility into the attacker's ultimate objectives, tooling, or lateral movement strategy.

---

## 3. The Role & Power of Deception Technology

Cyber deception shifts the defensive asymmetry back in favor of the security team:

* **Zero Legitimate Traffic Invariant:** A decoy server (honeypot) possesses no business purpose, hosts no authentic user accounts, and is omitted from standard enterprise service directories. Consequently, **any interaction with a decoy is by definition unauthorized and suspicious**.
* **Observation Without Production Risk:** Decoys provide a controlled, safe observation environment where security teams can monitor attacker behavior, command execution, and reconnaissance patterns without endangering production enterprise databases or customer data.
* **Low False-Positive Baseline:** Because benign employees and automated internal systems have zero reason to interact with decoy assets, deception-driven alerts start with an exceptionally high baseline confidence ($>90\%$).

---

## 4. Why Raw Telemetry Alone is Insufficient

Deploying a honeypot (such as Cowrie or a web decoy) and capturing raw logs is trivial, but raw honeypot logs alone do not solve the SOC analyst's problem:

1. **Format Heterogeneity:** HTTP web decoys emit Apache/Nginx-style access logs or JSON request bodies; SSH honeypots emit terminal command strings and TTY recordings; network probes emit PCAP packet streams.
2. **Data Overload Without Context:** A single automated vulnerability scanner (e.g., Nikto, Nuclei, or ZAP) can generate 10,000 HTTP requests in 5 minutes. If each request produces an alert, the analyst suffers from honeypot alert fatigue.
3. **Lack of Temporal Progression:** An isolated failed login log entry does not reveal whether the attacker previously performed a port scan or subsequently attempted directory traversal.
4. **Absence of Actionable Containment:** Raw logs do not generate firewall blocking scripts or provide integration with incident response playbooks.

---

## 5. Why Normalization, Detection, Scoring & Correlation Are Mandatory

To transform raw deception hits into operational security intelligence, SnareSight establishes a rigorous processing pipeline:

```
Raw Decoy Hit 
  │
  ▼ (Schema Validation & Salted SHA-256 Redaction)
Normalized Event 
  │
  ▼ (Explainable Rule Matching & Thresholds)
Deterministic Detection 
  │
  ▼ (Independent Severity & Confidence Calculation)
Scored Alert 
  │
  ▼ (Temporal Sliding Window & Session Clustering)
Correlated Attack Chain
```

* **Data Protection & Zero-Password Invariant:** Raw attacker submissions frequently contain credentials or sensitive inputs. Normalization enforces salted SHA-256 hashing and PII redaction *before* persistence.
* **Deterministic Explainability:** The platform avoids black-box ML models for primary detection. Every alert is traced to human-auditable logic (e.g., 3 failed logins within 300s).
* **Decoupled Scoring:** Severity (impact on assets) and Confidence (evidentiary proof) must be calculated independently. A low-impact reconnaissance scan can have 95% confidence but only 30% severity.
* **Temporal Session Correlation:** Grouping events by source IP and session window allows the platform to reconstruct the intruder's narrative rather than treating each packet as an isolated incident.

---

## 6. The Necessity of Evidence-Grounded MITRE ATT&CK Mapping

Many commercial security tools perform speculative or marketing-driven MITRE ATT&CK mapping—tagging a technique merely because an attacker "might" attempt it. 

SnareSight enforces strict **evidence-grounded mapping**:
1. **Explicit Forensic Lineage:** An ATT&CK technique (e.g., `T1083 - File & Directory Discovery`) is mapped *only* when an event contains concrete evidentiary indicators (e.g. `../etc/passwd` path traversal).
2. **Tactics Progression:** Mappings follow the chronological timeline of tactics (Reconnaissance $\to$ Discovery $\to$ Credential Access $\to$ Execution).
3. **Analyst Review & Verification:** Analysts retain full human-in-the-loop control to review, verify, or dispute automated technique mappings.

---

## 7. Problem Domain Scope Boundaries & Assumptions

To maintain academic and architectural discipline, SnareSight explicitly defines what it is and what it is not:

### What SnareSight IS:
* A browser-based, deception-driven threat detection and investigation platform.
* A high-fidelity early-warning system for internal virtual lab subnets.
* A correlation and visualization workspace for SOC analysts.

### What SnareSight is NOT:
* **NOT a Full Enterprise SIEM Replacement:** It does not ingest millions of benign corporate syslog streams.
* **NOT an Antivirus / EDR Tool:** It does not monitor endpoint kernel processes.
* **NOT a Malware Sandbox:** It does not detonate or execute malicious binaries.
* **NOT an Offensive Tool:** It does not perform active counter-attacks, port scans, or hack-backs.
* **NOT Proof of Legal Physical Identity:** An IP address or threat profile represents clustered network behavior, not a verified individual human.

---

## 8. Alignment: General Problem vs SnareSight Gap vs Actual Demonstration

| Evaluation Dimension | General Cybersecurity Problem | Specific Gap SnareSight Fills | What Current Code Actually Demonstrates |
|---|---|---|---|
| **Alert Volume** | Thousands of ambiguous perimeter alerts daily. | High-fidelity deception telemetry with near-zero false positive baseline. | Verified 100% precision on synthetic honeypot attack scenarios. |
| **Telemetry Usability** | Raw honeypot logs are noisy and disconnected. | Normalized schema, Zero-Password redaction, and temporal session grouping. | 532 automated tests verifying ingestion, redaction, and session clustering. |
| **Investigation** | Analysts struggle to understand intruder progression. | Interactive React Flow Attack Chain DAG and MITRE ATT&CK heatmap. | Live interactive graph rendering multi-phase attacks (`Recon` $\to$ `Cred Access` $\to$ `Discovery`). |
| **Response** | Delayed containment handoff to network teams. | Instantaneous generation of validated firewall rules (`iptables`, `UFW`). | Automated export of copy-pasteable firewall commands inside incident cases. |

