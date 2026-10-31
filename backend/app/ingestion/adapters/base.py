"""Base adapter contract for source-specific honeypot parsers in SnareSight."""

from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseSourceAdapter(ABC):
    """Abstract interface for source-specific event translation into standardized raw schema."""

    @property
    @abstractmethod
    def source_prefix(self) -> str:
        """The source or decoy ID prefix this adapter handles (e.g. 'WEB', 'COWRIE')."""
        pass

    @abstractmethod
    def parse_event(self, raw_input: Dict[str, Any]) -> Dict[str, Any]:
        """Translates source-specific telemetry into the standardized SnareSight Raw Event structure."""
        pass

