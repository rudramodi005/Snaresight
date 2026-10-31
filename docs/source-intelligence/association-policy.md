# Source Association & Labelling Policy

## 1. Network Observable vs Human Identity Guardrail
A core principle of SnareSight is that **an observed IP address is a routing artifact, not proof of a specific human actor or organized threat group**.

- **NAT and Carrier-Grade NAT (CGNAT):** Hundreds or thousands of legitimate client devices may egress via a single public IP.
- **Corporate Proxies and Cloud Egress:** Cloud services (e.g. AWS NAT Gateway, Azure NAT, DigitalOcean droplets) frequently rotate or share IPs across disparate tenants.
- **Commercial VPNs & Tor Exit Nodes:** High concentrations of anonymous or multi-user activity originate from known egress clusters.
- **Dynamic DHCP Reassignments:** Consumer broadband addresses change periodically.

### Terminology Invariants
The system enforces strict UI and API labeling:
- Permitted: `Observed Source Profile: <IP>`, `Source Context Profile: <IP>`, `Observed Network Source`
- Prohibited: `Attacker <IP>`, `Hacker Profile`, `Confirmed Threat Actor`, `Attributed APT Group`

---

## 2. Association Types and Confidence

When activity sessions are bound to source profiles in `source_profile_sessions`, an `association_type` and `confidence_score` are recorded:

1. **`DIRECT_IP` (Confidence: 100):**
   - The session's `source_address` directly matches the profile's canonical IP.
   - Standard automated baseline binding.
2. **`FINGERPRINT` (Confidence: 85):**
   - Contextual matching based on matching client TLS fingerprints, HTTP headers, or decoy affinity under subnet proximity.
3. **`ANALYST_MERGED` (Confidence: 95):**
   - Manual association performed by a SOC analyst during incident investigation.
4. **`SUBNET_PROXIMITY` (Confidence: 60):**
   - Correlated within a tightly bounded `/28` or `/64` CIDR block exhibiting synchronized probing behavior.

---

## 3. Shared Infrastructure Handling

Analysts can mark `is_shared_infrastructure = true` on any Observed Source Profile. This applies:
- Visual indication on SOC dashboards alerting investigators to potential multi-tenant egress.
- Prevents over-prioritizing low-confidence single-session probes originating from known multi-tenant networks.
- Full audit logging of the analyst review in `source_profile_history`.

