# SnareSight: VM Recovery & Snapshot Verification
**Document ID:** SEC-AUDIT-006  
**Phase:** 2 — Lab Isolation and Honeypot  
**Task:** P08 — Verify Isolation and Emergency Shutdown  
**Status:** Verification Specification  

---

## 1. Verified VirtualBox Snapshot Architecture

VirtualBox 7.2.14 supports hierarchical tree snapshots natively stored in `C:\Users\rudra\VirtualBox VMs\SnareSight-Lab\Snapshots\`.

---

## 2. Recovery Plan Execution Ledger

* **Target Snapshot 1 (`SNARESIGHT-BASE-OS`):** Clean Ubuntu 24.04 installation. *(PENDING OS install)*
* **Target Snapshot 2 (`SNARESIGHT-ISOLATED-NETWORK`):** Hardened static IP and `nftables` baseline. *(PENDING network staging)*
* **Target Snapshot 3 (`SNARESIGHT-GOLDEN-BASELINE`):** Operational decoy baseline. *(PENDING Phase 2 deployment)*
* **Rollback Verification Command:**
  ```powershell
  & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" snapshot "SnareSight-Lab" restore "SNARESIGHT-ISOLATED-NETWORK"
  ```

