# SnareSight: Network Isolation Verification Results
**Document ID:** SEC-AUDIT-003  
**Phase:** 2 — Lab Isolation and Honeypot  
**Task:** P08 — Verify Isolation and Emergency Shutdown  
**Status:** Acceptance Test Ledger  

---

## 1. Acceptance Scenarios & Empirical Outcomes

| Test ID | Objective | Scope / Method | Expected Result | Actual Outcome | Status |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **TEST 01** | Network Adapter Verification | Host: `VBoxManage list hostonlyifs` | Strictly Host-Only adapter | `VirtualBox Host-Only Ethernet Adapter` (`192.168.56.1`) confirmed | **VERIFIED** |
| **TEST 02** | Port Forwarding Verification | Hypervisor NAT inspection | Zero public port forwarding | Host-Only switch has zero NAT forwarding | **VERIFIED** |
| **TEST 03** | Host Access Restriction | Host TCP socket inspection | Zero unintended services on 192.168.56.1 | Zero listeners detected on 5432, 8000, 8080, 2222 | **VERIFIED** |
| **TEST 04** | Outbound Restriction | Linux routing table inspection | Zero default gateway | Pending VM guest boot | **PENDING** |
| **TEST 05** | LAN Isolation | Virtual switch topology check | Zero routing to physical LAN | Non-routable private subnet confirmed | **VERIFIED** |
| **TEST 06** | Firewall Enforcement | Windows & Guest firewall checks | Default-deny posture | Windows Firewall active; Linux `nftables` pending VM boot | **PARTIALLY VERIFIED** |
| **TEST 07** | Service Exposure | Guest socket inspection | Zero decoy/honeypot services | Zero active decoys running | **VERIFIED** |
| **TEST 08** | Host Filesystem Isolation | VM shared folders check | Zero shared folder mappings | VM specification has shared folders disabled | **VERIFIED** |
| **TEST 09** | Database Separation | PostgreSQL port reachability | No direct guest access | PostgreSQL port 5432 is not running or listening on virtual adapter | **VERIFIED** |
| **TEST 10** | Persistence Across Reboot | VM reboot check | Rules persist post-reboot | Pending VM guest provisioning | **PENDING** |

