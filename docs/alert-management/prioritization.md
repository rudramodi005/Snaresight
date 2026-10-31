# Alert Prioritization Engine

## 1. Separation of Severity, Confidence, and Priority

In high-volume SOC operations, conflating severity and priority leads to triage fatigue:
- **Severity (Inherent Impact):** How damaging the activity would be if executed against production assets (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- **Confidence (Certainty):** How conclusively the observed telemetry matches the detection rule without ambiguity (0 to 100%).
- **Operational Priority (Urgency):** Where this alert ranks in the analyst queue right now (`P1_CRITICAL`, `P2_HIGH`, `P3_MEDIUM`, `P4_LOW`).

> [!IMPORTANT]
> A 100% confidence scan on `/robots.txt` is `INFO` severity and `P4_LOW` priority.  
> A 70% confidence brute force burst across 20 decoys is `HIGH` severity and `P1_CRITICAL` priority.

---

## 2. Priority Scoring Formula (Formula v1.0)

Operational Priority is calculated dynamically out of 100.0 points using documented weights:

$$\text{Priority Score} = \min(100.0, S_{\text{sev}} + C_{\text{conf}} + E_{\text{evid}} + X_{\text{context}} + R_{\text{recency}})$$

### 1. Severity Component ($S_{\text{sev}}$, Max 40 pts)
- `CRITICAL`: 40.0 pts
- `HIGH`: 30.0 pts
- `MEDIUM`: 20.0 pts
- `LOW`: 10.0 pts
- `INFO`: 5.0 pts

### 2. Confidence Component ($C_{\text{conf}}$, Max 25 pts)
$$\text{Confidence Score} \times 0.25$$
- 100% confidence = 25.0 pts
- 80% confidence = 20.0 pts
- 40% confidence = 10.0 pts

### 3. Evidence Strength & Volume ($E_{\text{evid}}$, Max 20 pts)
- Evidence Strength Base:
  - `DEFINITIVE`: 15.0 pts
  - `STRONG`: 12.0 pts
  - `CORROBORATED`: 8.0 pts
  - `WEAK`: 4.0 pts
- Event Volume Bonus: $+1.0$ pt per supporting event beyond the first (capped at $+5.0$ pts).

### 4. Cross-Subsystem Context Linkage ($X_{\text{context}}$, Max 10 pts)
- $+10.0$ pts if the alert or source IP is already linked to an active **Behavioral Sequence** or **Investigation Cluster**.

### 5. Recency Urgency Bonus ($R_{\text{recency}}$, Max 5 pts)
- Generated $\le 2$ hours ago: $+5.0$ pts
- Generated $\le 12$ hours ago: $+3.0$ pts
- Generated $\le 24$ hours ago: $+1.0$ pt
- Older: $0.0$ pts

---

## 3. Priority Tiers

| Calculated Score | Priority Level | Triage SLA & Expectation |
|:---|:---|:---|
| $\ge 75.0$ | `P1_CRITICAL` | Immediate analyst triage within 15 minutes. |
| $\ge 50.0$ | `P2_HIGH` | Active triage within 1 hour. |
| $\ge 30.0$ | `P3_MEDIUM` | Routine queue review during current shift. |
| $< 30.0$ | `P4_LOW` | Automated correlation and informational logging. |

---

## 4. Non-Attribution Caveat

Every priority calculation and queue display carries the following mandatory disclaimer:
> *"Priority reflects telemetry severity, detection confidence, and operational urgency. It does not infer attacker capability, nation-state attribution, or confirmed human identity."*

