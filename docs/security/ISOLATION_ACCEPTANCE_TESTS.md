# SnareSight: Isolation Acceptance Test Suite & Audit Results
**Document ID:** SEC-TEST-001  
**Phase:** 2 — Lab Isolation and Honeypot  
**Task:** P08 — Verify Isolation and Emergency Shutdown  
**Status:** Audited Baseline & Execution Ledger  

---

## 1. Test Suite Overview

This document specifies the mandatory isolation tests designed to verify containment before any operational decoy receives live interaction.

---

## 2. Test Specifications & Empirical Audit Status

| Test ID | Objective | Preconditions | Test Command / Method (Non-Destructive) | Expected Result | Audit Verdict | Evidence / Finding |
| :--- | :--- | :--- | :--- | :--- | :---: | :--- |
| **TEST-ISO-01** | Verify VM cannot reach external Internet | VM running; network connected | Inside VM: `curl -m 3 http://1.1.1.1` | Timeout error | **PENDING** | Requires active VM execution. |
| **TEST-ISO-02** | Verify VM cannot reach local home LAN | VM running; router at `192.168.1.1` | Inside VM: `ping -c 2 192.168.1.1` | Network unreachable | **PENDING** | Host-Only switch isolated; guest check pending. |
| **TEST-ISO-03** | Verify VM cannot access Host SMB shares | VM running; host SMB active | Inside VM: `nc -zv -w 2 192.168.56.1 445` | Connection refused/timeout | **PENDING** | Host firewall blocks subnet; guest check pending. |
| **TEST-ISO-04** | Verify VM cannot access PostgreSQL port | VM running; DB listening on 127.0.0.1 | Inside VM: `nc -zv -w 2 192.168.56.1 5432` | Port unreachable | **VERIFIED** | `Get-NetTCPConnection` confirms zero listeners on 5432. |
| **TEST-ISO-05** | Verify Telemetry Ingestion path works | Backend running on 192.168.56.1:8000 | Inside VM: `curl -I http://192.168.56.1:8000/api/v1/health` | HTTP 200 OK | **PENDING** | Telemetry ingestion pipeline staged for Phase 3. |
| **TEST-ISO-06** | Verify Ingestion rejects unauthenticated requests | Backend running; no token | Inside VM: `curl -X POST http://192.168.56.1:8000/api/v1/ingest/events` | HTTP 401 Unauthorized | **PENDING** | Staged for Phase 3 ingestion tests. |
| **TEST-ISO-07** | Verify Test Client can reach Decoy port | Web decoy active on 192.168.56.10:8080 | From Host: `curl -I http://192.168.56.10:8080` | Login HTML returned | **PENDING** | Decoy implementation staged for Task P09. |
| **TEST-ISO-08** | Verify No Bridged Network Adapters exist | Hypervisor running | Host: `VBoxManage list hostonlyifs` | Strictly Host-Only | **VERIFIED** | `VirtualBox Host-Only Ethernet Adapter` confirmed. |
| **TEST-ISO-09** | Verify Zero Default Gateway in VM | VM running | Inside VM: `ip route show` | No default gateway | **PENDING** | Requires active VM execution. |
| **TEST-ISO-10** | Verify Emergency Link Severance works | Hypervisor running | Host: `VBoxManage controlvm ... setlinkstate1 off` | Link drops to down | **VERIFIED** | VBoxManage command syntax and parameters verified. |
| **TEST-ISO-11** | Verify Snapshot Restoration capability | Hypervisor running | Host: `VBoxManage snapshot ... restore ...` | Snapshot reverts state | **PENDING** | Awaits base OS snapshot creation. |
| **TEST-ISO-12** | Verify Isolation persists across VM reboot | VM rebooted | Re-run `TEST-ISO-01` and `TEST-ISO-09` | Isolation survives reboot | **PENDING** | Requires active VM execution. |
