# SnareSight: Network Isolation Policy & Egress Controls
**Document ID:** SEC-NET-002  
**Phase:** 2 — Lab Isolation and Honeypot  
**Status:** Approved Security Policy  

---

## 1. Core Isolation Policy Directives

1. **The Non-Bridged Directives:**
   * Under no circumstance will any virtual network adapter attached to the Honeypot VM be set to `Bridged`.
   * Any configuration change detected that bridges virtual interfaces with the physical Wi-Fi or Ethernet adapter constitutes an immediate policy violation requiring automated VM suspension.
2. **The Zero-Default-Gateway Policy:**
   * The Linux guest operating system must be provisioned **without an IPv4 default gateway**.
   * In the absence of a default gateway route (`0.0.0.0/0`), the Linux kernel cannot route packets destined for external subnets, neutralizing automated reverse shells or botnet command-and-control (C2) callbacks.
3. **Unidirectional Ingestion Boundary:**
   * Outbound communication from the Honeypot VM is restricted strictly to a single target: the Host Telemetry Ingestion port (`TCP 8000`).
   * All other outbound connection attempts (e.g., DNS port 53, HTTP port 80, SSH port 22, SMB port 445) are immediately dropped and logged.
4. **Localhost Isolation:**
   * PostgreSQL (`port 5432`) and the Vite development server (`port 5173`) must bind strictly to `127.0.0.1` and will **never** listen on the virtual network adapter (`192.168.56.1`).
   * The Honeypot VM cannot reach the PostgreSQL database under any circumstance.

