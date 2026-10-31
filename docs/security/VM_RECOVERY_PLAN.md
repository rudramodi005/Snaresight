# SnareSight: VM Recovery & Emergency Isolation Plan
**Document ID:** SEC-REC-001  
**Phase:** 2 — Lab Isolation and Honeypot  
**Status:** Approved Security Specification  

---

## 1. Multi-Tiered VM Snapshot Strategy

To ensure deterministic recovery from experimental changes or potential honeypot compromise, the VM follows a strict three-tier snapshot baseline:

```
[Snapshot 1: BASELINE-CLEAN-OS]
  │  (Clean Ubuntu 24.04 LTS installation, updated packages, labadmin user, no decoys)
  │
  └── [Snapshot 2: PRE-HONEYPOT-HARDENED]
        │  (Firewall nftables rules active, logging daemons installed, no honeypots running)
        │
        └── [Snapshot 3: GOLDEN-OPERATIONAL-STATE]
              (Web-login decoy installed, forwarder daemon registered, zero operational logs)
```

### Snapshot Naming & Storage Conventions:
* `SNAP-01-CLEAN-BASE-UBUNTU2404-20261031`
* `SNAP-02-HARDENED-NETWORK-20261031`
* `SNAP-03-GOLDEN-OPERATIONAL-20261031`
* **Storage Location:** Stored exclusively on primary NVMe drive (`C:\VMs\SnareSight-Lab\Snapshots\`), consuming ~3.5 to 5 GB total.

---

## 2. Emergency Isolation & Shutdown Procedures

If an anomalous outbound connection, unusual host-bound packet, or suspected VM escape attempt is detected, execute the three-phase emergency protocol:

### Phase 1: Immediate Virtual Network Severance (< 2 seconds)
Disconnect the virtual network cable to instantly isolate the guest without killing active memory:
```powershell
# VirtualBox CLI network severance command
VBoxManage controlvm "SnareSight-Honeypot-VM" setlinkstate1 off
```

### Phase 2: Complete Virtual Machine Suspension
Freeze the virtual CPU state to preserve forensic artifacts in volatile memory:
```powershell
VBoxManage controlvm "SnareSight-Honeypot-VM" savestate
```

### Phase 3: Host Socket Teardown
Terminate any active local ingestion listeners:
```powershell
Stop-Process -Name "uvicorn" -Force -ErrorAction SilentlyContinue
```

---

## 3. Forensic Preservation Invariant

> [!IMPORTANT]
> When investigating a suspected compromise, **never delete or overwrite the virtual disk immediately**. 
> 1. Export the VM state to an unmounted `.ova` / `.vdi` forensic archive.
> 2. Roll back the active virtual machine to `Snapshot 3: GOLDEN-OPERATIONAL-STATE`.
> 3. Verify isolation acceptance tests before resuming telemetry collection.

