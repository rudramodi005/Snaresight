# Cross-Subsystem Event Relationships

## Relationship Graph Assembly
In modern SOC operations, isolated events provide minimal context. The `SecurityEventsService` dynamically discovers and maps relationships across the SnareSight platform:

```
                          +------------------------+
                          |  Security Event (P13)  |
                          +-----------+------------+
                                      |
         +----------------------------+----------------------------+
         |              |             |              |             |
         v              v             v              v             v
   +-----------+  +-----------+  +-----------+  +-----------+  +-----------+
   | Raw Event |  |  Session  |  |  Source   |  |  Alert    |  |  Cluster  |
   | (Capture) |  |   (P21)   |  |  Profile  |  |   (P16)   |  |   (P24)   |
   +-----------+  +-----------+  |   (P23)   |  +-----+-----+  +-----------+
                                 +-----------+        |
                                                      v
                                                +-----------+
                                                |   MITRE   |
                                                | Technique |
                                                |   (P20)   |
                                                +-----------+
```

---

## Relationship Types & Semantics

| Relationship Type | Source Entity | Semantic Meaning | Navigation URL |
|:---|:---|:---|:---|
| `ORIGINAL_CAPTURE` | `raw_events` | Immutable raw capture before normalization | N/A |
| `SAME_SESSION` | `activity_sessions` | Events belonging to the same continuous connection | `/sessions?session_id=...` |
| `OBSERVED_SOURCE` | `source_profiles` | Behavioral intelligence profile for the source IP | `/source-intelligence?profile_id=...` |
| `TRIGGERING_EVIDENCE` | `alerts` | Threat detection triggered by this event | `/alerts?alert_id=...` |
| `TACTIC_TECHNIQUE_MAPPING` | `attack_techniques` | MITRE ATT&CK technique mapped via detection rule | `/mitre?technique_id=...` |
| `ATTACK_STEP` | `behavioral_sequences` | Multi-session attack chain step | `/sequences?sequence_id=...` |
| `INVESTIGATION_MEMBER` | `investigation_clusters` | Curated campaign cluster grouping related activity | `/investigations?cluster_id=...` |

---

## Non-Attribution Guardrail
Having relationships to the same source IP or similar detection rules does **not** prove shared physical actor identity. Relationships are strictly documented as **"Correlated Inbound Activity"**.

