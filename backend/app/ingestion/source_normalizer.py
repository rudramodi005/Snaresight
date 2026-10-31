"""Source and target normalization engine for SnareSight.

Standardizes source address, protocol, port, and pseudonymous profile IDs
without conflating network addresses with individual identity.
"""

from typing import Any, Dict


class SourceNormalizer:
    """Standardizes network endpoint attributes and generates pseudonymous source references."""

    @classmethod
    def normalize_source_info(
        cls, raw_event: Dict[str, Any], session_id: str
    ) -> Dict[str, Any]:
        """Extracts and normalizes source endpoint details."""
        source_meta = raw_event.get("source", {})
        
        # Source address extraction (handling ip_address, ip, or client.ip)
        source_addr = (
            source_meta.get("ip_address")
            or source_meta.get("ip")
            or raw_event.get("client", {}).get("ip")
            or "unknown"
        )
        
        # Source port extraction
        source_port = (
            source_meta.get("port")
            or raw_event.get("client", {}).get("port")
        )
        if source_port is not None:
            try:
                source_port = int(source_port)
                if not (1 <= source_port <= 65535):
                    source_port = None
            except (ValueError, TypeError):
                source_port = None

        # Protocol extraction
        source_proto = (
            source_meta.get("protocol")
            or raw_event.get("protocol")
            or "http"
        ).lower()

        # Pseudonymous profile reference (scoped to session/prefix, avoiding personal attribution)
        observed_source_id = f"src_profile_{session_id[:8]}" if session_id else "src_profile_unknown"

        return {
            "source_address": source_addr,
            "source_port": source_port,
            "source_protocol": source_proto,
            "observed_source_id": observed_source_id,
        }

    @classmethod
    def normalize_target_info(
        cls, raw_event: Dict[str, Any], decoy_id: str
    ) -> Dict[str, Any]:
        """Extracts and standardizes target service information based on decoy identity."""
        if decoy_id.startswith("WEB"):
            target_service = "WEB_PORTAL"
            target_port = 8080
        elif decoy_id.startswith("COWRIE") or decoy_id.startswith("SSH"):
            target_service = "SSH_DAEMON"
            target_port = 2222
        else:
            target_service = "HONEYPOT_SERVICE"
            target_port = 8080

        # Allow explicit override from target metadata if provided
        target_meta = raw_event.get("target", {})
        if "service" in target_meta:
            target_service = str(target_meta["service"])
        if "port" in target_meta and isinstance(target_meta["port"], int):
            target_port = target_meta["port"]

        return {
            "target_service": target_service,
            "target_port": target_port,
        }

