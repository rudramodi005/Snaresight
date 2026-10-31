# SnareSight: Virtual Machine Resource Controls
**Document ID:** SEC-RES-001  
**Phase:** 2 — Lab Isolation and Honeypot  
**Status:** Approved Implementation Baseline  

---

## 1. Resource Quotas & Host Protection

To protect the host development machine from memory exhaustion or CPU starvation:

| Dimension | Constraint | Host Guardrail | Enforcement Method |
| :--- | :--- | :--- | :--- |
| **CPU Cores** | 2 Virtual CPUs | 10 Cores reserved for Windows | `VBoxManage modifyvm "SnareSight-Lab" --cpus 2` |
| **CPU Execution Cap** | 85% Maximum | Windows always retains scheduler priority | `VBoxManage modifyvm "SnareSight-Lab" --cpuexecutioncap 85` |
| **RAM Allocation** | 2,048 MB (2 GB) | Leaves ~13 GB RAM visible for Windows | `VBoxManage modifyvm "SnareSight-Lab" --memory 2048` |
| **Virtual Disk** | 30 GB Dynamic VDI | Pre-allocated space is ~3.5 GB | Dynamic allocation prevents premature disk consumption |
| **I/O Bandwidth** | 30 MB/sec limit | Prevents disk thrashing during brute-force floods | Storage controller bandwidth groups |

---

## 2. Storage Threshold Alarm

* **Host Drive C: Safety Ceiling:** Virtual machine execution must be suspended if free host disk space on Drive C: falls below **25 GB** (currently has **122.03 GB** free).
* **Automated Safety Check:** A pre-launch PowerShell script validates free disk space before bringing the VM out of suspended state.

