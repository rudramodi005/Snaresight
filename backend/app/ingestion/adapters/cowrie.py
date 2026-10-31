"""Cowrie SSH/Telnet decoy event adapter specification for SnareSight.

Prepared adapter architecture for future SSH/Telnet telemetry without requiring
operational Cowrie deployment or altering existing core data contracts.
"""

from typing import Any, Dict
from app.ingestion.adapters.base import BaseSourceAdapter


class CowrieDecoyAdapter(BaseSourceAdapter):
    """Adapter for future SSH/Telnet honeypot telemetry (COWRIE-SSH)."""

    @property
    def source_prefix(self) -> str:
        return "COWRIE"

    def parse_event(self, raw_input: Dict[str, Any]) -> Dict[str, Any]:
        """Translates Cowrie log structure into the canonical SnareSight Raw Event format."""
        raw_id = raw_input.get("raw_event_id") or raw_input.get("eventid") or raw_input.get("event_id")
        decoy_id = raw_input.get("decoy_id", "COWRIE-SSH-01")
        session_id = raw_input.get("session") or raw_input.get("session_id", "sess_unknown")
        
        event_type = raw_input.get("eventid") or raw_input.get("event_type", "cowrie.session.connect")
        
        parsed: Dict[str, Any] = {
            "raw_event_id": raw_id,
            "decoy_id": decoy_id,
            "session_id": session_id,
            "schema_version": "1.0",
            "event_type": event_type,
            "observed_at": raw_input.get("timestamp") or raw_input.get("observed_at"),
            "source": {
                "ip_address": raw_input.get("src_ip") or raw_input.get("source", {}).get("ip_address", "unknown"),
                "port": raw_input.get("src_port") or raw_input.get("source", {}).get("port"),
                "protocol": "ssh",
            },
            "target": {
                "service": "SSH_DAEMON",
                "port": raw_input.get("dst_port", 2222),
            },
            "interaction": {
                "username_attempted": raw_input.get("username"),
                "password_present": bool(raw_input.get("password")),
                "command": raw_input.get("input"),
            },
            "provenance": raw_input.get("provenance", {
                "source_classification": "HONEYPOT_DECOY",
                "environment": "isolated_lab",
                "collection_method": "cowrie_ssh",
            }),
        }

        # Categorize
        if "login" in event_type.lower():
            parsed["event_category"] = "AUTHENTICATION"
        elif "command" in event_type.lower():
            parsed["event_category"] = "COMMAND_INTERACTION"
        else:
            parsed["event_category"] = "CONNECTION"

        return parsed

