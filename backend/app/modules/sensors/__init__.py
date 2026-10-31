"""Honeypot Sensor Management, Health Monitoring, and Operational Reliability module."""

from app.modules.sensors.routes import sensors_router
from app.modules.sensors.service import sensor_service
from app.modules.sensors.auth import authenticate_sensor_request, generate_sensor_api_key

__all__ = [
    "sensors_router",
    "sensor_service",
    "authenticate_sensor_request",
    "generate_sensor_api_key",
]

