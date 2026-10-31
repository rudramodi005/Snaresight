# SnareSight: Linux Guest OS Hardening Specification
**Document ID:** SEC-HARD-001  
**Phase:** 2 — Lab Isolation and Honeypot  
**Status:** Approved Hardening Baseline  

---

## 1. Operating System Account Structure

* **Root Account:** Interactive login disabled (`passwd -l root`).
* **Lab Administrator:** `labadmin` account with `sudo` privileges for maintenance.
* **Decoy Service Account:** `snaresight-decoy` (System account, UID < 1000, shell set to `/usr/sbin/nologin`, home directory `/var/empty`).
* **Principle of Least Privilege:** Web honeypots and forwarder daemons execute exclusively under `snaresight-decoy`, preventing any honeypot compromise from altering guest OS binaries or firewall rules.

---

## 2. SSH Management Policy

* **Initial Phase:** Direct SSH listener is **Disabled** (`systemctl stop ssh && systemctl disable ssh`).
* **Console Access:** All initial VM administration and inspection is conducted strictly through the native VirtualBox GUI / CLI console window.
* **Future SSH Rule:** If SSH is enabled in later phases for automated lab orchestration, it must bind strictly to `192.168.56.10:22`, use ED25519 public key authentication only (`PasswordAuthentication no`), and reject `root` login (`PermitRootLogin no`).

---

## 3. Kernel Parameter Hardening (`/etc/sysctl.d/99-snaresight.conf`)

```ini
# Disable IP forwarding (prevents VM from acting as a router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Ignore ICMP echo broadcasts and bogus error responses
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Disable Source Packet Routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Enable TCP SYN Cookies (DoS mitigation)
net.ipv4.tcp_syncookies = 1

# Restrict dmesg and kernel pointer access
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
```

