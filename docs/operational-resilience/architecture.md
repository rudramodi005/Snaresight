# Platform Resilience & Operational Monitoring Architecture

## 1. Overview & Operational Scope

SnareSight is a browser-based Deception-Driven Threat Detection and Security Operations Platform. As a critical SOC operations hub, SnareSight's own availability, integrity, and resilience are paramount.

The Platform Resilience subsystem monitors internal platform health, preserves critical threat telemetry, validates database recoverable states, enforces disaster recovery (DR) targets, and detects internal threats targeting the SnareSight control plane.

```mermaid
flowchart TD
    subgraph ControlPlane [SnareSight Control Plane]
        FastAPI[FastAPI Gateway & Auth]
        Ingestion[Honeypot Ingestion Engine]
        Detection[Correlation & Rule Engine]
        Sensors[Sensor Fleet Manager]
        Audit[Immutable Audit Trail]
    end

    subgraph ResilienceSubsystem [Resilience & Security Subsystem]
        HealthCheck[Health & Readiness Probes]
        RuleEngine[Internal Rule Engine (7 Rules)]
        BackupService[Managed Backup Service]
        DRRunbooks[Disaster Recovery Runbooks]
        IncidentManager[Internal Incident Workflows]
    end

    subgraph SafeStorage [Cryptographic Artifacts & Sandboxes]
        ChecksumStore[(SHA-256 Checksummed Dumps)]
        IsolatedSandbox[(Isolated Restore Sandbox DB)]
    end

    ControlPlane --> HealthCheck
    ControlPlane --> RuleEngine
    RuleEngine --> IncidentManager
    BackupService --> ChecksumStore
    BackupService --> IsolatedSandbox
    DRRunbooks --> ControlPlane
```

---

## 2. Architectural Boundaries & Segregation

1. **Separation of Honeypot Alerts vs. Internal Platform Alerts**:
   - External attacker telemetry collected from decoys is stored in `alerts` and analyzed by SOC analysts for external threats.
   - Internal control-plane security events (e.g. repeated failed logins to SnareSight admin, unauthorized configuration mutations) are routed to `internal_security_events` and `internal_security_alerts`.
2. **Safe Restoration Isolation**:
   - Automated and manual backup restore tests run strictly within an isolated sandbox environment (`isolated_sandbox_db`).
   - Live production tables are protected by immutability constraints during verification drills.
3. **Cryptographic Checksumming**:
   - Every backup artifact generated calculates a genuine SHA-256 digest on export and verifies it prior to sandbox test restoration.
   - Storage locations are recorded using safe URI masking (`safe://backups/...`) to prevent filesystem password or token leaks.

