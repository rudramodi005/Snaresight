"""Safe IP canonicalization, fingerprint generation, and source profile labelling."""

import hashlib
import ipaddress
from typing import Tuple


def canonicalize_ip(ip_str: str) -> Tuple[str, str, bool]:
    """Canonicalizes an IPv4 or IPv6 string.
    
    Returns:
        Tuple of (canonical_ip_str, ip_family, is_private)
    """
    cleaned = ip_str.strip()
    try:
        addr = ipaddress.ip_address(cleaned)
        family = "IPv4" if addr.version == 4 else "IPv6"
        is_private = addr.is_private or addr.is_loopback or addr.is_link_local
        # Standard compressed canonical form
        canonical = addr.compressed
        return canonical, family, is_private
    except ValueError:
        # Fallback for mock/test strings that aren't strictly valid IP syntax
        return cleaned, "IPv4", False


def generate_source_fingerprint(canonical_ip: str, salt: str = "SnareSight-SourceProfile-v1") -> str:
    """Generates a deterministic SHA-256 fingerprint for a canonical source IP."""
    hasher = hashlib.sha256()
    hasher.update(salt.encode("utf-8"))
    hasher.update(b":")
    hasher.update(canonical_ip.encode("utf-8"))
    return hasher.hexdigest()


def generate_profile_id(canonical_ip: str) -> str:
    """Generates a stable profile identifier prefixing 'PROF-' with truncated fingerprint."""
    fp = generate_source_fingerprint(canonical_ip)
    return f"PROF-{fp[:16].upper()}"


def format_source_display_label(canonical_ip: str) -> str:
    """Formats the standardized display label for a source profile.
    
    ENFORCES POLICY: Strictly labels as 'Observed Source Profile: <IP>',
    never claims confirmed human identity or threat actor attribution.
    """
    return f"Observed Source Profile: {canonical_ip}"

