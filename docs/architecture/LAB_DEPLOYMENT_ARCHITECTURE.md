# SnareSight: Honeypot Lab Deployment Architecture
**Document ID:** ARCH-LAB-001  
**Phase:** 2 — Lab Isolation and Honeypot  
**Status:** Approved Deployment Architecture  

---

## 1. Architectural Topology

```mermaid
graph TD
    subgraph Host_Environment["Host Development Environment (Windows 11)"]
        Browser["Analyst SOC Dashboard<br/>(http://127.0.0.1:5173)"]
        BackendEngine["FastAPI Core Engine<br/>(http://127.0.0.1:8000 & 192.168.56.1:8000)"]
        Database[("PostgreSQL 16 DB<br/>(127.0.0.1:5432 only)")]
        TestClient["Controlled Test Client Script<br/>(Simulated Attacker)"]
    end

    subgraph Virtual_Switch["Virtual Host-Only Switch (192.168.56.0/24)"]
        vHost["Host Adapter (192.168.56.1)"]
        vGuest["Guest Adapter (192.168.56.10)"]
    end

    subgraph Linux_Honeypot_VM["Isolated Linux Guest VM (Ubuntu 24.04 LTS)"]
        subgraph Decoy_Layer["Decoy Services"]
            WebDecoy["Web-Login Decoy Service<br/>(Port 8080 - Python/FastAPI Mock)"]
            CowrieSSH["Modular Cowrie SSH Decoy<br/>(Port 2222 - Post-MVP)"]
        end

        subgraph Shipper_Layer["Telemetry Forwarding"]
            Spool["Local SQLite/JSON Circular Spool<br/>(/var/spool/snaresight/)"]
            ShipperDaemon["Log Shipper Daemon<br/>(systemd service)"]
        end
    end

    %% Wiring
    TestClient -->|"Targeted Probes: Port 8080"| vHost
    vHost --> vGuest
    vGuest --> WebDecoy
    WebDecoy -->|"Raw Event Log"| Spool
    CowrieSSH -.->|"Terminal Log"| Spool
    Spool --> ShipperDaemon
    ShipperDaemon -->|"HTTP POST (Token Auth): Port 8000"| vGuest
    vGuest --> vHost
    vHost --> BackendEngine
    BackendEngine --> Database
    Database --> BackendEngine
    BackendEngine --> Browser
```

---

## 2. Decoy Deployment Lifecycle & Roles

1. **Initial Deception Target: Web-Login Decoy (Task P09):**
   * **Role:** Simulates a corporate single sign-on (SSO) or administrative portal.
   * **Execution Model:** Lightweight Python service running as an unprivileged system daemon (`snaresight-decoy` user) inside the Linux VM, bound strictly to internal IP `192.168.56.10:8080`.
   * **Behavior:** Captures HTTP POST parameters (username, submitted password length, password SHA-256 hash, client headers, source IP). Returns simulated authentication error screens without granting any real access.
2. **Modular Extension: Cowrie SSH Honeypot (Post-MVP):**
   * **Role:** Emulates a medium-interaction UNIX SSH shell on port `2222`.
   * **Integration:** Telemetry logs emitted to `/var/log/cowrie/cowrie.json` are read by the common Shipper Daemon and normalized into the standard SnareSight schema.

