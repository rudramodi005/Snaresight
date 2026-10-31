# SnareSight: Security Boundaries & Lab Isolation Policy
**Document ID:** SEC-003  
**Status:** Approved Security Boundary Policy  

---

## 1. The Five Immutable Security Invariants

SnareSight enforces five mandatory, non-negotiable security rules across all environments:

1. **The Isolation Invariant:** Operational honeypots must run strictly within an isolated virtual environment (WSL 2 or dedicated Linux VM) configured with **Internal Host-Only or Private NAT networking**. Bridged networking is strictly prohibited.
2. **The Zero-Execution Invariant:** Under no circumstance will SnareSight execute, run, or simulate any binary payload, script, or executable code captured by a decoy. Captured files are treated exclusively as static forensic data (calculating size, mime-type, and SHA-256 hash).
3. **The Localhost Binding Invariant:** During development, the FastAPI backend, PostgreSQL database, and Vite frontend must bind exclusively to `127.0.0.1` (localhost). They must never accept incoming traffic from external network adapters.
4. **The Host Defense Invariant:** SnareSight will never attempt to disable, bypass, or weaken Windows Defender, McAfee Antivirus, or Windows Firewall.
5. **The Non-Offensive Invariant:** SnareSight is strictly a defensive deception and monitoring platform. It contains zero offensive strike-back, automated port-scanning, or retaliatory penetration capabilities.

---

## 2. Emergency Shutdown Procedure

In the event of unexpected decoy behavior, anomalous network traffic, or an apparent containment breach:

```powershell
# ==============================================================================
# SNARESIGHT LAB EMERGENCY SHUTDOWN RUNBOOK (POWERSHELL)
# ==============================================================================

# 1. Immediately terminate the isolated decoy runtime
wsl --terminate Ubuntu-SnareSight   # If running under WSL 2
docker stop snaresight-decoy-web   # If running under Docker

# 2. Sever any active telemetry sockets
Stop-Process -Name "uvicorn" -Force -ErrorAction SilentlyContinue

# 3. Confirm network interface closure
Get-NetTCPConnection -LocalPort 8080, 8000, 5432 -ErrorAction SilentlyContinue
```

This procedure terminates all decoy services and telemetry listeners within 2 seconds.

