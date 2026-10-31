"""SSE Heartbeat manager for SnareSight real-time event streaming.

Maintains stream keep-alives and detects broken client connections without
creating synthetic threat events or database records.
"""

from datetime import datetime, timezone


class HeartbeatManager:
    """Generates periodic SSE keepalive frames."""

    DEFAULT_INTERVAL_SECONDS = 15

    @classmethod
    def format_heartbeat_frame(cls) -> str:
        """Formats a lightweight SSE comment frame.
        
        Using standard SSE comment syntax (': ping\n\n') prevents browser EventSource
        from misinterpreting keepalive traffic as actual security event data.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        return f": ping {now_iso}\n\n"

