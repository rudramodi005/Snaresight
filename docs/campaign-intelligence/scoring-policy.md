# Relationship Confidence & Prioritization Policy

## Decoupling Principle
A fundamental architectural invariant of SnareSight is the strict separation of concerns across analytical scores:

| Score Metric | Target Evaluated | Meaning |
|:---|:---|:---|
| **Event Severity** | Single Event | Technical impact or invasiveness of a specific honeypot interaction |
| **Detection Confidence** | Detection Rule Match | Reliability and false-positive resilience of a detection pattern |
| **Profile Priority** | Source Context Profile | Urgency with which analysts should investigate an IP address |
| **Behavioral Severity** | Attack Chain / Sequence | Progression risk across multi-session attack steps |
| **Relationship Confidence** | Cluster / Relationship | **Strength of evidence linking two or more entities together** |

> High Event Severity does NOT automatically imply High Relationship Confidence. A severe exploit attempt with vague or generic tooling yields a low relationship confidence when linked to other events. Conversely, highly distinctive custom probe artifacts linking two benign probes yield high relationship confidence.

---

## Relationship Confidence Scoring (`RelationshipScorer`)

Relationship confidence is computed from positive supporting signals and reduced by contradictory evidence:

$$\text{Confidence} = \operatorname{clamp}\left(\sum w_{\text{positive}} - \sum p_{\text{contradiction}},\, 0.0,\, 1.0\right)$$

### Positive Signal Weights

| Correlation Signal | Weight | Description |
|:---|:---:|:---|
| `EXACT_IP_MATCH` | +0.40 | Observed activity originates from the exact same source IP |
| `IDENTICAL_TOOLING_SIGNATURE` | +0.30 | Exact match of uncommon User-Agent, SSH banner, or payload hash |
| `SHARED_TARGET_PORT_BURST` | +0.25 | Probes targeting identical unusual ports within a 10-minute window |
| `MATCHING_BEHAVIORAL_SEQUENCE` | +0.25 | Multiple sessions execute the exact same multi-stage command sequence |
| `SHARED_CREDENTIAL_PATTERN` | +0.20 | Distinctive non-default credential list probed across sources |
| `COMMON_MITRE_CHAIN` | +0.15 | Concordant progression through MITRE tactics |

### Contradiction Penalties

| Contradiction Signal | Penalty | Description |
|:---|:---:|:---|
| `DISPARATE_GEOGRAPHY_BURST` | -0.30 | Near-simultaneous activity from geographically impossible points without proxy indicators |
| `CONFLICTING_OPERATING_SYSTEM` | -0.25 | Divergent TCP/IP fingerprint or conflicting client OS signatures |
| `TEMPORAL_DISCONNECT` | -0.20 | Observations separated by extensive periods with no intermediate continuity |
| `DIVERGENT_ATTACK_OBJECTIVES` | -0.15 | Completely unrelated payload targets (e.g., IoT Mirai vs enterprise CMS web exploit) |

---

## Confidence Level Classifications

Confidence scores are mapped to transparent categorical levels:

- **`HIGH`** ($\ge 0.80$): Multiple strong correlating signals (e.g., matching custom payload and identical IP/tooling) with zero contradictions.
- **`STRONG`** ($0.65 - 0.79$): Solid evidence with multiple corroborating indicators.
- **`MODERATE`** ($0.45 - 0.64$): Plausible relationship with some shared indicators, but potential alternative explanations exist.
- **`LOW`** ($0.25 - 0.44$): Weak correlation, such as targeting common internet ports (22, 80) with generic scanning tools.
- **`UNCONFIRMED`** ($< 0.25$): Candidate grouping pending further telemetry.

---

## Cluster Priority Calculation

Cluster priority determines triage queue placement:
- **`CRITICAL`**: Contains High/Critical severity behavioral sequences, verified alerts, and high relationship confidence.
- **`HIGH`**: Correlates multiple alerts or sequences with moderate-to-high relationship confidence.
- **`MEDIUM`**: Standard multi-session investigation cluster with suspicious activity.
- **`LOW`**: Candidate cluster composed of low-severity automated scanning.

