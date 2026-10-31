"""Session management service for SnareSight Web Decoy.

Maintains opaque, unguessable interaction session cookies without any connection
to real application authentication stores.
"""

import time
from typing import Optional
from uuid import uuid4


class DecoySessionManager:
    """In-memory tracker for decoy visitor sessions."""

    def __init__(self, ttl_seconds: int = 3600):
        self.ttl_seconds = ttl_seconds
        # In-memory session registry: {session_id: {"created_at": float, "last_seen": float, "event_count": int}}
        self._sessions: dict[str, dict] = {}

    def get_or_create_session(self, existing_token: Optional[str]) -> tuple[str, bool]:
        """Validates an existing session or creates a new opaque session identifier.

        Returns:
            (session_id, is_new_session)
        """
        now = time.time()

        if existing_token and existing_token in self._sessions:
            sess = self._sessions[existing_token]
            if now - sess["last_seen"] < self.ttl_seconds:
                sess["last_seen"] = now
                sess["event_count"] += 1
                return existing_token, False
            # Session expired
            del self._sessions[existing_token]

        # Generate new opaque session
        new_token = f"decoy_sess_{uuid4().hex}"
        self._sessions[new_token] = {
            "created_at": now,
            "last_seen": now,
            "event_count": 1,
        }
        return new_token, True

    def get_session_stats(self, token: str) -> Optional[dict]:
        """Returns metadata for an active session."""
        return self._sessions.get(token)

    def active_session_count(self) -> int:
        """Returns total active non-expired sessions."""
        now = time.time()
        # Clean expired
        expired = [k for k, v in self._sessions.items() if now - v["last_seen"] >= self.ttl_seconds]
        for k in expired:
            del self._sessions[k]
        return len(self._sessions)


# Global singleton instance
session_manager = DecoySessionManager()

