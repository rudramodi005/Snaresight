# SnareSight: Network Configuration Specification
**Document ID:** SEC-NET-003  
**Phase:** 2 — Lab Isolation and Honeypot  
**Status:** Approved Implementation Baseline  

---

## 1. Verified Host Virtual Interface

* **Adapter Name:** `VirtualBox Host-Only Ethernet Adapter` (`Ethernet 3` in Windows).
* **Interface GUID:** `3ab7aa39-4a5c-4f29-9773-d317b91997dc`
* **Assigned Host IP:** `192.168.56.1`
* **Subnet Mask:** `255.255.255.0` (`/24`)
* **DHCP Server:** **Disabled** (Forces static addressing; prevents rogue DHCP lease allocation).
* **Link Status:** **Up** (Verified active).

---

## 2. Linux Guest Addressing Plan (Static Netplan Specification)

Because the DHCP server on the Host-Only adapter is disabled, the Linux guest utilizes static interface configuration via Netplan (`/etc/netplan/01-netcfg.yaml`):

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      dhcp4: no
      dhcp6: no
      addresses:
        - 192.168.56.10/24
      # CRITICAL SECURITY DIRECTIVE:
      # No gateway4 or default routes are defined.
      # The guest kernel has zero routability outside 192.168.56.0/24.
```

---

## 3. Communication Matrix

| Source | Destination | Protocol / Port | Permitted? | Architectural Justification |
| :--- | :--- | :--- | :---: | :--- |
| **Guest (`192.168.56.10`)** | **Host (`192.168.56.1`)** | `TCP 8000` | **YES** | Forwarder telemetry shipment to Ingestion API. |
| **Host (`192.168.56.1`)** | **Guest (`192.168.56.10`)** | `TCP 8080` | **YES** | Controlled test client interacting with web decoy. |
| **Guest (`192.168.56.10`)** | **Host (`192.168.56.1`)** | `TCP 445, 135, 3389` | **BLOCKED** | Windows file sharing, RPC, and RDP strictly dropped. |
| **Guest (`192.168.56.10`)** | **Host (`127.0.0.1`)** | `TCP 5432` | **BLOCKED** | PostgreSQL database isolated to host loopback interface. |
| **Guest (`192.168.56.10`)** | **Physical Home LAN** | Any | **BLOCKED** | Host-Only switch drops non-local traffic automatically. |
| **Guest (`192.168.56.10`)** | **Public Internet** | Any | **BLOCKED** | Zero gateway route; packet routing drops instantly at guest kernel. |

