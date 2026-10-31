"""Alembic migration for Honeypot Sensor Management and Health Monitoring (Task P33).

Revision ID: p33_sensor_management
Revises: p32_defensive_response
Create Date: 2026-10-31 23:55:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'p33_sensor_management'
down_revision = 'p32_defensive_response'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. sensors table
    op.create_table(
        'sensors',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('sensor_id', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('sensor_type', sa.String(length=64), nullable=False),
        sa.Column('sensor_version', sa.String(length=32), nullable=False, server_default='1.0.0'),
        sa.Column('deployment_environment', sa.String(length=32), nullable=False, server_default='isolated_lab'),
        sa.Column('lab_zone', sa.String(length=64), nullable=False, server_default='zone_alpha'),
        sa.Column('operational_status', sa.String(length=32), nullable=False, server_default='REGISTERED'),
        sa.Column('health_status', sa.String(length=32), nullable=False, server_default='UNKNOWN'),
        sa.Column('heartbeat_interval_seconds', sa.Integer(), nullable=False, server_default='60'),
        sa.Column('missed_heartbeat_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_heartbeat_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_telemetry_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('current_config_version', sa.String(length=32), nullable=False, server_default='1.0.0'),
        sa.Column('supported_telemetry_types', sa.JSON(), nullable=False),
        sa.Column('admin_notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('sensor_id'),
    )
    op.create_index('ix_sensors_sensor_id', 'sensors', ['sensor_id'])
    op.create_index('ix_sensors_sensor_type', 'sensors', ['sensor_type'])
    op.create_index('ix_sensors_deployment_environment', 'sensors', ['deployment_environment'])
    op.create_index('ix_sensors_operational_status', 'sensors', ['operational_status'])
    op.create_index('ix_sensors_health_status', 'sensors', ['health_status'])

    # 2. sensor_credentials table
    op.create_table(
        'sensor_credentials',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('key_id', sa.String(length=64), nullable=False),
        sa.Column('sensor_id', sa.String(length=64), nullable=False),
        sa.Column('key_prefix', sa.String(length=24), nullable=False),
        sa.Column('hashed_api_key', sa.String(length=128), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='ACTIVE'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revocation_reason', sa.String(length=255), nullable=True),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['sensor_id'], ['sensors.sensor_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('key_id'),
    )
    op.create_index('ix_sensor_credentials_key_id', 'sensor_credentials', ['key_id'])
    op.create_index('ix_sensor_credentials_sensor_id', 'sensor_credentials', ['sensor_id'])
    op.create_index('ix_sensor_credentials_status', 'sensor_credentials', ['status'])

    # 3. sensor_heartbeats table
    op.create_table(
        'sensor_heartbeats',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('sensor_id', sa.String(length=64), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='HEALTHY'),
        sa.Column('latency_ms', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('metrics_payload', sa.JSON(), nullable=False),
        sa.Column('error_category', sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(['sensor_id'], ['sensors.sensor_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_sensor_heartbeats_sensor_id', 'sensor_heartbeats', ['sensor_id'])
    op.create_index('ix_sensor_heartbeats_timestamp', 'sensor_heartbeats', ['timestamp'])

    # 4. sensor_configurations table
    op.create_table(
        'sensor_configurations',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('sensor_id', sa.String(length=64), nullable=False),
        sa.Column('version', sa.String(length=32), nullable=False),
        sa.Column('config_payload', sa.JSON(), nullable=False),
        sa.Column('is_current', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('change_reason', sa.String(length=255), nullable=True),
        sa.Column('updated_by', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['sensor_id'], ['sensors.sensor_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_sensor_configurations_sensor_id', 'sensor_configurations', ['sensor_id'])
    op.create_index('ix_sensor_configurations_is_current', 'sensor_configurations', ['is_current'])

    # 5. operational_alerts table
    op.create_table(
        'operational_alerts',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('alert_id', sa.String(length=64), nullable=False),
        sa.Column('sensor_id', sa.String(length=64), nullable=False),
        sa.Column('alert_category', sa.String(length=64), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False, server_default='MEDIUM'),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='OPEN'),
        sa.Column('first_observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('evidence_payload', sa.JSON(), nullable=False),
        sa.Column('recommended_action', sa.Text(), nullable=False),
        sa.Column('acknowledged_by', sa.String(length=64), nullable=True),
        sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolved_by', sa.String(length=64), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolution_notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['sensor_id'], ['sensors.sensor_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('alert_id'),
    )
    op.create_index('ix_operational_alerts_alert_id', 'operational_alerts', ['alert_id'])
    op.create_index('ix_operational_alerts_sensor_id', 'operational_alerts', ['sensor_id'])
    op.create_index('ix_operational_alerts_alert_category', 'operational_alerts', ['alert_category'])
    op.create_index('ix_operational_alerts_status', 'operational_alerts', ['status'])

    # 6. sensor_maintenance_history table
    op.create_table(
        'sensor_maintenance_history',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('sensor_id', sa.String(length=64), nullable=False),
        sa.Column('maintenance_mode_enabled', sa.Boolean(), nullable=False),
        sa.Column('reason', sa.String(length=255), nullable=False),
        sa.Column('initiated_by', sa.String(length=64), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['sensor_id'], ['sensors.sensor_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_sensor_maintenance_history_sensor_id', 'sensor_maintenance_history', ['sensor_id'])

    # 7. sensor_telemetry_metrics table
    op.create_table(
        'sensor_telemetry_metrics',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('sensor_id', sa.String(length=64), nullable=False),
        sa.Column('window_start', sa.DateTime(timezone=True), nullable=False),
        sa.Column('window_end', sa.DateTime(timezone=True), nullable=False),
        sa.Column('events_received', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('events_validated', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('events_rejected', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('events_persisted', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('duplicate_events', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('average_latency_ms', sa.Float(), nullable=False, server_default='0.0'),
        sa.ForeignKeyConstraint(['sensor_id'], ['sensors.sensor_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_sensor_telemetry_metrics_sensor_id', 'sensor_telemetry_metrics', ['sensor_id'])
    op.create_index('ix_sensor_telemetry_metrics_window_start', 'sensor_telemetry_metrics', ['window_start'])


def downgrade() -> None:
    op.drop_table('sensor_telemetry_metrics')
    op.drop_table('sensor_maintenance_history')
    op.drop_table('operational_alerts')
    op.drop_table('sensor_configurations')
    op.drop_table('sensor_heartbeats')
    op.drop_table('sensor_credentials')
    op.drop_table('sensors')

