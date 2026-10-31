# SnareSight: Requirements Traceability Matrix (RTM)
**Document ID:** ARCH-011  
**Status:** Approved Traceability Baseline  

---

## 1. Classification Scheme

* **[REQ-ORIG] Original Requirement:** Explicitly derived from approved problem identity and objective.
* **[REQ-NEC] Necessary Implementation:** Essential technical prerequisite needed to fulfill an original requirement.
* **[REQ-ENH] In-Scope Enhancement:** Valued feature that directly strengthens the deception detection mission.
* **[REQ-FUT] Optional Future Feature:** Candidate for post-MVP releases.

---

## 2. Requirements Traceability Matrix

| Req ID | Classification | Requirement Summary | Responsible Module | Backend Service | Database Entity | API Endpoint | Frontend View | Verification Test | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **REQ-01** | [REQ-ORIG] | Deploy and manage isolated web-login decoy | Honeypots | `HoneypotService` | `honeypots` | `GET/POST /api/v1/honeypots` | Decoy Manager | Decoy registration & heartbeat test | Planned (P09) |
| **REQ-02** | [REQ-ORIG] | Ingest and validate decoy interaction telemetry | Ingestion | `IngestionService` | `raw_events` | `POST /api/v1/ingest/events` | Live Events | Ingestion schema validation test | Planned (P13) |
| **REQ-03** | [REQ-ORIG] | Normalize telemetry and enforce data provenance | Normalization | `NormalizationService` | `security_events` | `GET /api/v1/events` | Live Events | Provenance tagging test | Planned (P14) |
| **REQ-04** | [REQ-ORIG] | Explainable rule-based threat detection | Detection Engine | `RuleEngineService` | `detection_rules`, `alerts` | `GET /api/v1/alerts` | Alert Center | Brute-force rule firing test | Planned (P16) |
| **REQ-05** | [REQ-ORIG] | Independent severity and confidence scoring | Detection Engine | `ScoringService` | `alerts.severity`, `alerts.confidence` | `GET /api/v1/alerts` | Alert Center | Scoring calculation test | Planned (P17) |
| **REQ-06** | [REQ-ORIG] | Temporal & session event correlation | Correlation | `CorrelationService` | `sessions`, `attack_chains` | `GET /api/v1/attack-chains` | Attack Chains | Session correlation window test | Planned (P21) |
| **REQ-07** | [REQ-ORIG] | Interactive attack-chain graph visualization | Frontend UI | `AttackChainBuilder` | `attack_chain_events` | `GET /api/v1/attack-chains/{id}/graph` | React Flow Visualizer | Graph rendering & node layout test | Planned (P22) |
| **REQ-08** | [REQ-ORIG] | Evidence-based MITRE ATT&CK technique mapping | Intelligence | `MitreMapperService` | `attack_techniques`, `technique_mappings` | `GET /api/v1/intelligence/mitre` | ATT&CK Explorer | Evidence-backed mapping test | Planned (P20) |
| **REQ-09** | [REQ-ORIG] | Observed source activity profiling | Intelligence | `SourceProfilerService`| `observed_sources` | `GET /api/v1/sources` | Source Profiles | IP interaction profile test | Planned (P23) |
| **REQ-10** | [REQ-ORIG] | Real-time SOC dashboard with live streaming | Frontend / Core | `SSEBroadcaster` | N/A (Streaming) | `GET /api/v1/events/stream` | Overview & Live Feeds| SSE broadcast latency test | Planned (P25) |
| **REQ-11** | [REQ-ORIG] | Analyst investigation cases & notes | Investigations | `InvestigationService`| `investigations`, `investigation_notes` | `POST /api/v1/investigations` | Investigations Workspace| Case workflow & note export test | Planned (P32) |
| **REQ-12** | [REQ-ORIG] | Structured forensic reporting & IOC export | Reporting | `ReportingService` | N/A (Generated Artifacts)| `GET /api/v1/reports` | Reports Center | Report generation & PDF export test | Planned (P32) |
| **REQ-13** | [REQ-NEC] | Platform health & decoy availability monitoring | Health | `HealthService` | `system_health` | `GET /api/v1/health` | System Health | Heartbeat timeout test | Planned (P15) |
| **REQ-14** | [REQ-NEC] | Zero bridged networking & lab isolation | Lab Isolation | N/A (Infra) | N/A (Infra) | N/A | Settings / Runbook | Network routing verification test | Planned (P08) |
| **REQ-15** | [REQ-ENH] | Reproducible attack simulation generator | Simulation | `SimulationRunner` | `simulation_runs` | `POST /api/v1/simulations` | Live Events | End-to-end replay test | Planned (P36) |
| **REQ-16** | [REQ-FUT] | Cowrie SSH honeypot modular adapter | Honeypots | `CowrieAdapter` | `honeypots` | `POST /api/v1/ingest/cowrie`| Decoy Manager | Post-MVP Cowrie log ingestion test | Post-MVP |

