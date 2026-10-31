"""Source adapters registry for SnareSight honeypot telemetry."""

from app.ingestion.adapters.base import BaseSourceAdapter
from app.ingestion.adapters.web_decoy import WebDecoyAdapter
from app.ingestion.adapters.cowrie import CowrieDecoyAdapter

__all__ = [
    "BaseSourceAdapter",
    "WebDecoyAdapter",
    "CowrieDecoyAdapter",
]

