"""JSONL Event Logger for SnareSight Web Decoy.

Guarantees thread-safe write operations, log rotation, and strict zero-password
invariants before disk persistence.
"""

import json
import logging
import threading
from pathlib import Path
from typing import Optional
from app.config import settings
from app.schemas.events import DecoyEvent

logger = logging.getLogger("snaresight.decoy.logger")


class DecoyEventLogger:
    """Thread-safe, append-only JSONL logger with forensic validation."""

    def __init__(self, log_path: Optional[Path] = None, max_size_bytes: Optional[int] = None):
        self.log_path = log_path or settings.event_log_path
        self.max_size_bytes = max_size_bytes or settings.MAX_LOG_SIZE_BYTES
        self._lock = threading.Lock()
        self._events_logged_count = 0
        self._ensure_log_directory()

    def _ensure_log_directory(self) -> None:
        """Ensures the target log directory exists."""
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to create log directory: {e}")

    def log_event(self, event: DecoyEvent) -> bool:
        """Serializes and safely appends a DecoyEvent to events.jsonl.

        Enforces pre-write safety assertions to prevent password leakage.
        """
        # Serialize to JSON dictionary
        event_dict = event.model_dump()

        # CRITICAL SECURITY INVARIANT: Verify no plaintext password key exists
        serialized = json.dumps(event_dict, separators=(",", ":"))
        if '"password":' in serialized.lower() and not '"password_present":' in serialized.lower():
            logger.critical("SECURITY INVARIANT VIOLATION: Refusing to log event containing password key!")
            raise ValueError("SECURITY VIOLATION: Event payload contains forbidden password data.")

        with self._lock:
            try:
                # Check log rotation threshold
                if self.log_path.exists() and self.log_path.stat().st_size >= self.max_size_bytes:
                    self._rotate_log()

                # Atomic line append
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(serialized + "\n")

                self._events_logged_count += 1
                return True
            except Exception as e:
                logger.error(f"Failed to append to event log: {e}")
                return False

    def _rotate_log(self) -> None:
        """Rotates the active log file to .1 when maximum capacity is reached."""
        rotated_path = self.log_path.with_suffix(".jsonl.1")
        try:
            if rotated_path.exists():
                rotated_path.unlink()
            self.log_path.rename(rotated_path)
            logger.info(f"Rotated honeypot log file to {rotated_path}")
        except Exception as e:
            logger.error(f"Log rotation error: {e}")

    @property
    def total_events_logged(self) -> int:
        """Returns the count of events logged during this process session."""
        return self._events_logged_count


# Global singleton instance
event_logger = DecoyEventLogger()
