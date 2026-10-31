# SnareSight: Virtual Machine Configuration Specification
**Document ID:** SEC-VM-002  
**Phase:** 2 — Lab Isolation and Honeypot  
**Task:** P07 — Configure VM, Firewall, Egress and Resource Controls  
**Status:** Approved Implementation Baseline  

---

## 1. Verified Hypervisor & Host Baseline

* **Detected Hypervisor:** Oracle VirtualBox Version `7.2.14r174565` (Verified installed at `C:\Program Files\Oracle\VirtualBox\VBoxManage.exe`).
* **Hardware Acceleration:** AMD-V hardware virtualization enabled in BIOS.
* **Coexistence:** Runs via Windows Hypervisor Platform (WHPX) alongside Windows Virtualization-Based Security (VBS).
* **Existing VMs:** `kali-linux-2026.2-virtualbox-amd64` (Preserved intact; no modifications permitted).

---

## 2. Dedicated Honeypot VM Parameters (`SnareSight-Lab`)

| Configuration Parameter | Exact Setting | Rationale & Safety Justification |
| :--- | :--- | :--- |
| **VM Name** | `SnareSight-Lab` | Distinctly identifies honeypot infrastructure. |
| **Guest OS Type** | `Ubuntu_64` (Linux 64-bit) | Configures optimal kernel paravirtualization timers. |
| **Virtual CPUs (vCPUs)**| **2 Cores** (Execution Cap: 85%) | Capped to prevent honeypot spikes from starving Windows host. |
| **Base RAM** | **2,048 MB (2.0 GB)** | Minimum viable footprint for Ubuntu 24.04 Server + decoys. |
| **Virtual Disk** | **30.0 GB (Dynamic VDI)** | Initial size is ~3.5 GB on disk; expands only when required. |
| **Storage Controller** | SATA Controller (AHCI) | Native asynchronous disk I/O. |
| **Primary Network Adapter**| **Adapter 1: Host-Only** | Bound strictly to `VirtualBox Host-Only Ethernet Adapter`. |
| **Promiscuous Mode** | **Deny** | Prevents guest from sniffing neighboring host adapter traffic. |
| **Secondary Adapters** | **Disabled (None)** | Guarantees zero secondary routes or accidental bridged interfaces. |
| **Shared Folders** | **None (Disabled)** | Eliminates host filesystem escape vector via hypervisor drivers. |
| **Shared Clipboard / DnD**| **Disabled** | Prevents accidental data transfer between host and guest. |
| **Audio / USB Filters** | **Disabled** | Eliminates peripheral device attack surface. |

