# SnareSight: Windows Host Protection Verification
**Document ID:** SEC-AUDIT-002  
**Phase:** 2 — Lab Isolation and Honeypot  
**Task:** P08 — Verify Isolation and Emergency Shutdown  
**Status:** Verified Operational Baseline  

---

## 1. Host Interface & Firewall Audit

Empirical inspection of Windows host defenses was executed using PowerShell:

```powershell
=== EMPIRICAL AUDIT RESULTS ===
Host Firewall Profiles:
  Domain  : Enabled (True)
  Private : Enabled (True)
  Public  : Enabled (True)

Virtual Network Interface:
  Name            : VirtualBox Host-Only Ethernet Adapter (Ethernet 3)
  IP Address      : 192.168.56.1
  Network Mask    : 255.255.255.0 (/24)
  DHCP Server     : Disabled
  Link Status     : Up
  Medium Type     : Ethernet (Virtual Host-Only)
```

---

## 2. Port Exposure Audit

A diagnostic scan for listening sockets on sensitive ports was performed:

| Port | Monitored Service | Listening Interface | Process Owner | Audit Finding |
| :---: | :--- | :--- | :--- | :--- |
| **5432** | PostgreSQL Database | None (Not Active) | None | **SECURE:** Zero exposed database ports. |
| **8000** | FastAPI Ingestion API | None (Not Active) | None | **SECURE:** Zero open backend listeners. |
| **8080** | Web-Login Decoy | None (Not Active) | None | **SECURE:** Decoy is not running. |
| **2222** | Cowrie SSH Honeypot | None (Not Active) | None | **SECURE:** Honeypot is not running. |
| **445**  | Windows SMB Sharing | `0.0.0.0` / Local | System | **PROTECTED:** Host-Only subnet firewall rule blocks VM probing. |

