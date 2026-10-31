# SnareSight: Linux Guest Firewall Configuration (`nftables`)
**Document ID:** SEC-FW-003  
**Phase:** 2 — Lab Isolation and Honeypot  
**Status:** Approved Implementation Baseline  

---

## 1. Guest Firewall Architecture (`nftables`)

Ubuntu 24.04 LTS uses `nftables` as its modern packet filtering framework. The guest firewall enforces a strict **Default Deny** posture on both `INPUT` and `OUTPUT` chains.

---

## 2. Configuration Script (`/etc/nftables.conf`)

```nftables
#!/usr/sbin/nft -f

flush ruleset

table inet snaresight_filter {
    chain input {
        type filter hook input priority filter; policy drop;

        # Allow local loopback traffic
        iif "lo" accept

        # Allow established and related connections
        ct state established,related accept

        # Allow test client probes to web decoy port 8080 strictly from Host Virtual IP
        ip saddr 192.168.56.1 tcp dport 8080 ct state new accept

        # Log and drop any other inbound attempts
        log prefix "SNARESIGHT-INPUT-DROP: " flags all drop
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy drop;

        # Allow local loopback traffic
        oif "lo" accept

        # Allow established and related connections
        ct state established,related accept

        # Allow telemetry forwarder to post to Host Ingestion API on port 8000
        ip daddr 192.168.56.1 tcp dport 8000 ct state new accept

        # CRITICAL SECURITY DIRECTIVE:
        # Log and drop all other outbound traffic (blocks reverse shells, C2 callbacks, LAN scans)
        log prefix "SNARESIGHT-EGRESS-VIOLATION: " flags all drop
    }
}
```

---

## 3. Persistence & Service Verification
* Service enabled via: `systemctl enable --now nftables`
* Status verified via: `nft list ruleset`

