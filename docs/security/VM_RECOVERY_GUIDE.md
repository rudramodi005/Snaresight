# SnareSight: Virtual Machine Recovery & Snapshot Guide
**Document ID:** SEC-REC-002  
**Phase:** 2 — Lab Isolation and Honeypot  
**Status:** Approved Operational Runbook  

---

## 1. Official Recovery Snapshots

1. **`SNARESIGHT-BASE-OS`:** Clean Ubuntu 24.04 LTS installation, updated packages, `labadmin` user, no services.
2. **`SNARESIGHT-ISOLATED-NETWORK`:** Static IP `192.168.56.10/24` configured, zero default gateway verified, `nftables` default-deny active.
3. **`SNARESIGHT-GOLDEN-BASELINE`:** Clean baseline ready for Task P09 honeypot deployment.

---

## 2. Command Line Restoration Runbook

### Reverting VM to Clean Snapshot
```powershell
# 1. Stop the running VM immediately
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "SnareSight-Lab" poweroff

# 2. Restore the desired snapshot
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" snapshot "SnareSight-Lab" restore "SNARESIGHT-ISOLATED-NETWORK"

# 3. Restart the VM in headless or GUI mode
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" startvm "SnareSight-Lab" --type headless
```

### Emergency Network Disconnection (Cable Severance)
```powershell
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "SnareSight-Lab" setlinkstate1 off
```

