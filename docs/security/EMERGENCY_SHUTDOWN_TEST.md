# SnareSight: Emergency Network Disconnection & Shutdown Runbook
**Document ID:** SEC-AUDIT-004  
**Phase:** 2 — Lab Isolation and Honeypot  
**Task:** P08 — Verify Isolation and Emergency Shutdown  
**Status:** Validated Operational Runbook  

---

## 1. Verified Emergency Disconnection Command

To sever the Honeypot VM's network connectivity without terminating running memory:

```powershell
# Command syntax verified against Oracle VirtualBox 7.2.14r174565
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "SnareSight-Lab" setlinkstate1 off
```
* **Effect:** Immediately drops virtual link state to `down`. Telemetry packets, probe connections, and network sockets are severed within 100 milliseconds.
* **Safety Invariant:** Affects **only** virtual NIC 1 of `SnareSight-Lab`. Does **not** impact Windows host physical Wi-Fi or Ethernet adapters.

---

## 2. Emergency Shutdown Command Hierarchy

1. **Graceful ACPI Shutdown (Preferred):**
   ```powershell
   & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "SnareSight-Lab" acpipowerbutton
   ```
2. **Volatile Memory Preservation (Forensic State Freeze):**
   ```powershell
   & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "SnareSight-Lab" savestate
   ```
3. **Immediate Force Power-Off (Containment Breach):**
   ```powershell
   & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "SnareSight-Lab" poweroff
   ```

