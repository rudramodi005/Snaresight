# SnareSight: Honeypot Virtual Machine Architecture Specification
**Document ID:** SEC-VM-001  
**Phase:** 2 — Lab Isolation and Honeypot  
**Task:** P06 — Design Isolated VM and Virtual Network  
**Status:** Approved Design Baseline  

---

## 1. Executive Summary & Objective

This document defines the virtualization architecture for hosting SnareSight's operational deception services (honeypots). The primary objective is:
> **Prevent a compromised or maliciously probed honeypot from becoming a pathway into the host Windows development environment, local network devices, or the external Internet.**

---

## 2. Windows 11 Host Virtualization Environment (Audited P01 Baseline)

All architectural parameters are calibrated against the actual hardware discovered in Task P01:
* **Host Operating System:** Microsoft Windows 11 Home Single Language (64-bit, Build 26300).
* **CPU:** AMD Ryzen 7 7445HS (6 Physical Cores / 12 Logical Threads).
* **Hardware Virtualization:** AMD-V firmware extensions **Enabled** in BIOS (`VirtualizationFirmwareEnabled: True`).
* **Active Hypervisor Layer:** Virtualization-Based Security (VBS) / Core Isolation active.
* **Host Memory:** 16 GB Total RAM (15.27 GB visible, ~5.4 GB free at baseline).
* **Storage Headroom:** 122.03 GB free on primary NVMe SSD (C:).
* **Windows 11 Home Limitation:** Native Hyper-V Manager is not included in Windows 11 Home. Virtualization must rely on **Type-2 Hypervisors (VirtualBox / VMware Workstation)** or **Windows Subsystem for Linux 2 (WSL 2)** via the Virtual Machine Platform.

---

## 3. Virtualization Hypervisor Evaluation

| Feature / Metric | Oracle VirtualBox 7.1+ | VMware Workstation Pro 17+ | WSL 2 (Ubuntu 24.04 LTS) | Hyper-V (Native) |
| :--- | :--- | :--- | :--- | :--- |
| **Windows 11 Home Compatibility** | **Full (via WHPX/AMD-V)** | **Full (Free Personal)** | **Full (Built-in Feature)** | **Unsupported (Pro/Ent only)** |
| **Hypervisor Type** | Type-2 Hypervisor | Type-2 Hypervisor | MicroVM Utility Engine | Type-1 Hypervisor |
| **Isolation Strength** | **Very High** (Separate virtual NICs, isolated RAM/disk) | **Very High** (Isolated virtual switches) | **Moderate** (Shares kernel/network namespace defaults) | N/A |
| **Network Segmentation** | **Host-Only vSwitch, Internal Network** | **VMnet Custom Private Switches** | Dynamic NAT (Shares localhost unless reconfigured) | N/A |
| **Snapshot Capabilities** | **Native Multilevel Tree Snapshots** | **Native Tree Snapshots** | Manual `wsl --export` tarballs | N/A |
| **Resource Overhead** | Low–Moderate (~200 MB host RAM) | Low–Moderate (~250 MB host RAM) | Very Low (~100 MB host RAM) | N/A |
| **Console Access** | Native GUI window & headless CLI | Native GUI window & headless CLI | Terminal shell only | N/A |
| **Suitability for Honeypot Lab** | **Primary Recommendation** | **Strong Alternative** | Fallback / Dev Simulation | Not Applicable |

### Recommendation:
* **Primary Hypervisor:** **Oracle VirtualBox 7.1+** (or **VMware Workstation Pro 17+**). It provides true, dedicated virtual switches (Host-Only Network), granular outbound traffic blocks, and one-click snapshot rollback, ensuring complete isolation from Windows.
* **Alternative / Simulation Fallback:** **WSL 2** configured with a custom `.wslconfig` and strict iptables rules for lightweight, command-line only simulations.

---

## 4. Host Resource Allocation Budget

To ensure your computer remains completely stable and responsive during development, the VM is sized according to a **Standard Isolated Lab** budget:

| Resource Dimension | Allocated to Honeypot VM | Reserved for Windows Host & Dev Tools | Allocation Rationale |
| :--- | :--- | :--- | :--- |
| **Virtual CPUs (vCPUs)** | **2 Cores** | **10 Logical Processors** | Plenty of capacity for Python web decoy and Cowrie without starving Windows. |
| **Base RAM** | **2,048 MB (2.0 GB)** | **~13.27 GB visible** | Leaves ~13 GB for Windows 11, VS Code/Antigravity, Vite, and PostgreSQL. |
| **Maximum RAM Ceiling** | **3,072 MB (3.0 GB)** | **~12.27 GB visible** | Enforced maximum clamp to prevent VM memory leaks from affecting host. |
| **Virtual Disk Capacity** | **30.0 GB (Dynamically Allocated)** | **> 90 GB free SSD space** | Grows only as needed; initial footprint is ~3.5 GB on disk. |
| **Snapshot Reserve** | **15.0 GB** | **Free headroom** | Supports 3 historical baseline snapshots without disk exhaustion. |

---

## 5. Linux Guest Operating System Design

### Selected Distribution: **Ubuntu 24.04 LTS (Noble Numbat) Minimal Server**
* **Why Suitable:** 
  * 5-year guaranteed long-term support (LTS) for security updates.
  * Ultra-small footprint (minimal server image requires < 1 GB disk and < 300 MB RAM at idle).
  * Native Python 3.12/3.14 support, modern `systemd` process management, and standard `nftables` / `iptables` packet filtering.
* **Account Strategy:**
  * Root account disabled for direct interactive login.
  * Dedicated unprivileged management user: `labadmin` with `sudo` rights.
  * Dedicated sandboxed service account: `snaresight-decoy` (no login shell, `nologin`) for executing the web honeypot.
* **Management Policy:**
  * Initial configuration performed via hypervisor console window.
  * Direct SSH from the Windows host is **disabled by default** during initial deployment to prevent lateral movement vulnerabilities.

