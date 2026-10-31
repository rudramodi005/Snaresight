# SnareSight MITRE ATT&CK Mapping Confidence Policy

> [!WARNING]
> **CRITICAL OPERATIONAL NOTICE:**
> An ATT&CK mapping indicates that observed behavior is consistent with a documented adversary technique. It does not, by itself, establish attacker identity, successful compromise, intent, or completion of an attack.

---

## 1. Separation from Detection Confidence

SnareSight enforces strict conceptual and mathematical separation between **Detection Confidence** (P17) and **Mapping Confidence** (P20):

- **Detection Confidence (0–100):** Evaluates how reliably the observed telemetry indicates suspicious or anomalous activity matching detection rule conditions.
- **Mapping Confidence (0–100):** Evaluates how strongly the verified behavior and its supporting forensic evidence align with the technical definition of a specific MITRE ATT&CK technique.

A detection finding may have 100% detection confidence (e.g. 5 failed logins definitely occurred), but have only 60% mapping confidence to Password Guessing if the attacker's intent or dictionary structure cannot be verified from the telemetry.

---

## 2. Confidence Calculation Model

Mapping confidence is calculated deterministically by `MappingConfidenceEngine` (Policy Version `1.0`):

$$\text{Mapping Confidence} = \text{Base Category Score} + \Delta_{\text{Telemetry}} + \Delta_{\text{Volume}} + \Delta_{\text{Specificity}} - \Delta_{\text{Caution}}$$

### 2.1 Base Category Scores
- `DIRECTLY_SUPPORTED`: 75
- `PARTIALLY_SUPPORTED`: 55
- `REQUIRES_ANALYST_REVIEW`: 40
- `NOT_MAPPED`: 0

### 2.2 Modifiers
1. **Telemetry Source Reliability ($\Delta_{\text{Telemetry}}$):**
   - Controlled honeypot sensor audit stream: **+10**
2. **Corroborating Evidence Volume ($\Delta_{\text{Volume}}$):**
   - Session contains $\ge 3$ supporting events: **+10**
   - Single triggering event: **+0**
3. **Sub-Technique Granularity ($\Delta_{\text{Specificity}}$):**
   - Specific sub-technique justified by telemetry: **+5**
4. **Decoy Simulation Caution ($\Delta_{\text{Caution}}$):**
   - Trap account interaction (e.g. `AUTH-002`): **-15** (reflecting simulated decoy acceptance rather than authentic production access)

### 2.3 Categorical Confidence Levels
- **`HIGH`**: 80–100
- **`MODERATE`**: 50–79
- **`LOW`**: 0–49

