# SnareSight: Windows Host Firewall Configuration
**Document ID:** SEC-FW-002  
**Phase:** 2 — Lab Isolation and Honeypot  
**Status:** Approved Implementation Baseline  

---

## 1. Host Firewall Strategy

The Windows host firewall (Windows Defender Firewall) must permit telemetry from the Honeypot VM on port 8000 while explicitly blocking all attempts by the VM to probe host Windows management ports.

---

## 2. Windows PowerShell Rule Definitions

```powershell
# ==============================================================================
# SNARESIGHT HOST FIREWALL CONFIGURATION COMMANDS (AWAITING USER APPROVAL)
# ==============================================================================

# 1. Allow inbound telemetry from Honeypot VM to Ingestion API port 8000
New-NetFirewallRule -DisplayName "SnareSight-Ingest-Allow" `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort 8000 `
    -RemoteAddress 192.168.56.10 `
    -Profile Private, Domain `
    -Description "Allows SnareSight Honeypot VM to post telemetry to Host Ingestion API"

# 2. Explicitly drop all other inbound probe traffic from the virtual honeypot subnet
New-NetFirewallRule -DisplayName "SnareSight-Host-Block-Subnet" `
    -Direction Inbound `
    -Action Block `
    -Protocol Any `
    -RemoteAddress 192.168.56.0/24 `
    -Profile Any `
    -Description "Blocks all inbound probing from Honeypot VM to Windows host services"

# 3. Ensure PostgreSQL port 5432 is strictly inaccessible from non-loopback interfaces
New-NetFirewallRule -DisplayName "SnareSight-PostgreSQL-Block-Virtual" `
    -Direction Inbound `
    -Action Block `
    -Protocol TCP `
    -LocalPort 5432 `
    -RemoteAddress 192.168.56.0/24 `
    -Profile Any `
    -Description "Prevents Honeypot VM from accessing PostgreSQL database port"
```

---

## 3. Rollback Procedure
```powershell
Remove-NetFirewallRule -DisplayName "SnareSight-Ingest-Allow" -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName "SnareSight-Host-Block-Subnet" -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName "SnareSight-PostgreSQL-Block-Virtual" -ErrorAction SilentlyContinue
```

