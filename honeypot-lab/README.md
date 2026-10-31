# SnareSight: Honeypot Lab Environment
### Isolated Decoy Architecture & Adapters

---

## 1. Overview
The `honeypot-lab` directory houses the service definitions, mock templates, container manifests, and log forwarders that operate within the **Zone 3 Isolated Virtual Environment**.

---

## 2. Directory Structure
```
honeypot-lab/
├── web-decoy/          # Primary MVP Decoy: Simulated corporate web-login portal
├── cowrie-adapter/     # Post-MVP Decoy: Modular adapter for Cowrie SSH honeypots
└── documentation/      # Virtual network configuration & emergency shutdown runbooks
```

---

## 3. Security Isolation Notice
> [!CAUTION]
> **Zero Bridged Networking:** Services defined here must never be attached to a physical LAN network interface. All decoy services operate strictly on private virtual switches (NAT or host-only) with unidirectional telemetry forwarding.

