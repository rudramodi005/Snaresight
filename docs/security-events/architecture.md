# Security Events Explorer Architecture

## System Position
The Security Events Explorer is the investigative lens of Phase 6 (SOC Dashboard). It connects normalized telemetry from Phase 3 with detection results from Phase 4 and correlation entities from Phase 5:

```
+-----------------------------------------------------------------------------------+
| Phase 3: Telemetry & Ingestion (RawEventModel, SecurityEventModel, Deduplicator)  |
+-----------------------------------------+-----------------------------------------+
                                          |
+-----------------------------------------v-----------------------------------------+
| Phase 4: Threat Detection (DetectionRuleModel, AlertModel, AlertEvidenceModel)     |
+-----------------------------------------+-----------------------------------------+
                                          |
+-----------------------------------------v-----------------------------------------+
| Phase 5: Correlation & Profiles                                                   |
| - Activity Sessions (ActivitySessionModel)                                        |
| - Behavioral Sequences (BehavioralSequenceMemberModel)                            |
| - Source Context Profiles (SourceProfileModel)                                    |
| - Investigation Clusters (InvestigationClusterModel, ClusterMembershipModel)     |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| TASK P27: Security Events Explorer & Advanced Event Investigation                 |
|                                                                                   |
|  +------------------------+      +-----------------------+                        |
|  | SecurityEventsService  | <--> | SecurityEventsRouter  |                        |
|  +------------------------+      +-----------+-----------+                        |
|              |                               |                                    |
|              v                               v                                    |
|  +------------------------+      +-----------------------+                        |
|  | EventAuditLogModel     |      | React Events Table &  |                        |
|  | (event_audit_logs)     |      | 6-Tab Forensic Drawer |                        |
|  +------------------------+      +-----------------------+                        |
+-----------------------------------------------------------------------------------+
```

---

## Architectural Components

### 1. `SecurityEventsService`
- **Location:** `backend/app/modules/security_events/service.py`
- **Role:** High-performance database query and business logic facade.
- **Capabilities:**
  - Dynamic query construction with composite index support.
  - Automatic recursive credential scrubbing via `_scrub_sensitive_dict`.
  - Relationship graph assembly linking events to 7 distinct entity types.
  - Multi-event comparison matrix calculation with non-attribution caveat.
  - Non-destructive analyst audit log appending.

### 2. `SecurityEventsRouter`
- **Location:** `backend/app/modules/security_events/routes.py`
- **Role:** REST API endpoints mounted at `/api/v1/events`.
- **Enforcement:** Parameter validation, date range bounds, Pydantic serialization, and UTC timestamp standards.

### 3. `EventAuditLogModel`
- **Location:** `backend/app/db/models/event.py`
- **Role:** Relational table `event_audit_logs` tracking notes, review decisions (`UNDER_REVIEW`, `REVIEWED`, `ESCALATED`, `DISMISSED`), and cluster links.

