# SnareSight: Logical Firewall Policy & Filtering Rules
**Document ID:** SEC-FW-001  
**Phase:** 2 — Lab Isolation and Honeypot  
**Status:** Approved Security Specification  

---

## 1. Global Firewall Posture: Default Deny

All firewall layers enforce a strict **Default Deny** posture: all inbound and outbound traffic is blocked by default; only explicitly justified communication flows are permitted.

---

## 2. Zone Firewall Rule Tables

### Table 1: Windows Host Firewall Rules (Applied via Windows Defender Firewall)

| Rule Name | Direction | Protocol | Source IP / Port | Destination IP / Port | Action | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `SNARESIGHT-INGEST-ALLOW` | Inbound | TCP | `192.168.56.10` (Honeypot VM) / Any | `192.168.56.1` / Port `8000` | **ALLOW** | Permits authenticated decoy telemetry intake. |
| `SNARESIGHT-HOST-BLOCK-ALL`| Inbound | Any | `192.168.56.0/24` (Virtual Subnet) / Any| `192.168.56.1` / All other ports | **DROP (LOG)**| Blocks VM from probing Windows SMB (445), RPC (135), RDP (3389). |
| `SNARESIGHT-POSTGRES-LOCAL` | Inbound | TCP | `127.0.0.1` / Any | `127.0.0.1` / Port `5432` | **ALLOW** | Local database queries from backend API only. |
| `SNARESIGHT-POSTGRES-BLOCK` | Inbound | TCP | `0.0.0.0/0` (External/Virtual) / Any | Any / Port `5432` | **DROP** | Protects PostgreSQL from external or VM connections. |

---

### Table 2: Linux Honeypot Guest Firewall Rules (Applied via `nftables` / `iptables`)

| Chain | Protocol | Source IP / Port | Destination IP / Port | Action | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `INPUT` | TCP | `192.168.56.1` (Test Harness) / Any | `192.168.56.10` / Port `8080` | **ALLOW** | Permits authorized test interactions with the web login decoy. |
| `INPUT` | Any | `127.0.0.1` / Any | `127.0.0.1` / Any | **ALLOW** | Local guest loopback communications. |
| `INPUT` | Any | Any / Any | Any / Any | **DROP (LOG)**| Drops all unapproved incoming probe attempts. |
| `OUTPUT` | TCP | `192.168.56.10` / Ephemeral | `192.168.56.1` / Port `8000` | **ALLOW** | Permits forwarder to ship telemetry to Host Ingestion API. |
| `OUTPUT` | Any | `127.0.0.1` / Any | `127.0.0.1` / Any | **ALLOW** | Local guest loopback communications. |
| `OUTPUT` | Any | Any / Any | Any / Any | **DROP (LOG)**| Drops all unauthorized outbound traffic (prevents C2, pivoting, scans). |

---

## 3. Logging & Intrusion Alerting Directives

* Any packet dropped by the `OUTPUT` chain on the Linux Honeypot VM indicates anomalous guest activity (e.g. an exploit script attempting to initiate an outbound reverse shell).
* Dropped egress attempts are recorded locally to `/var/log/nftables-egress-violations.log` and surfaced in the health dashboard as an immediate high-priority indicator.

