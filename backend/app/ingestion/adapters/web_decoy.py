"""Web-decoy event adapter for SnareSight (WEB-001, WEB-DECOY-01).

Translates web login and portal probe telemetry into canonical raw event structures.
"""

from typing import Any, Dict
from app.ingestion.adapters.base import BaseSourceAdapter


class WebDecoyAdapter(BaseSourceAdapter):
    """Adapter for web decoy services (P09 web-login honeypot)."""

    @property
    def source_prefix(self) -> str:
        return "WEB"

    def parse_event(self, raw_input: Dict[str, Any]) -> Dict[str, Any]:
        """Maps web decoy JSON or dictionary into canonical raw schema format."""
        # Support both legacy event_id and raw_event_id
        raw_id = raw_input.get("raw_event_id") or raw_input.get("event_id")
        decoy_id = raw_input.get("decoy_id") or raw_input.get("source", {}).get("decoy_id", "WEB-001")
        
        # Build canonical structure
        parsed = dict(raw_input)
        if raw_id:
            parsed["raw_event_id"] = raw_id
        parsed["decoy_id"] = decoy_id
        
        # Ensure event category
        if "event_category" not in parsed:
            ev_type = str(parsed.get("event_type", "")).lower()
            if "login" in ev_type:
                parsed["event_category"] = "AUTHENTICATION"
            elif "page" in ev_type or "visit" in ev_type:
                parsed["event_category"] = "REQUEST"
            elif "session" in ev_type:
                parsed["event_category"] = "SESSION"
            else:
                parsed["event_category"] = "REQUEST"

        return parsed

