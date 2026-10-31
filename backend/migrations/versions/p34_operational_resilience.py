"""Alembic migration for Operational Resilience, Backups, and Internal Security (Task P34).

Revision ID: p34_operational_resilience
Revises: p33_sensor_management
Create Date: 2026-10-31 23:59:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'p34_operational_resilience'
down_revision = 'p33_sensor_management'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. internal_security_events
    op.create_table(
        'internal_security_events',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('event_type', sa.String(length=64), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('actor_username', sa.String(length=64), nullable=True),
        sa.Column('actor_role', sa.String(length=32), nullable=True),
        sa.Column('source_component', sa.String(length=64), nullable=False),
        sa.Column('outcome', sa.String(length=32), nullable=False, server_default='SUCCESS'),
        sa.Column('severity', sa.String(length=32), nullable=False, server_default='INFO'),
        sa.Column('correlation_id', sa.String(length=64), nullable=True),
        sa.Column('metadata_payload', sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_internal_security_events_event_type', 'internal_security_events', ['event_type'])
    op.create_index('ix_internal_security_events_timestamp', 'internal_security_events', ['timestamp'])
    op.create_index('ix_internal_security_events_actor_username', 'internal_security_events', ['actor_username'])
    op.create_index('ix_internal_security_events_source_component', 'internal_security_events', ['source_component'])
    op.create_index('ix_internal_security_events_severity', 'internal_security_events', ['severity'])
    op.create_index('ix_internal_security_events_correlation_id', 'internal_security_events', ['correlation_id'])

    # 2. internal_security_alerts
    op.create_table(
        'internal_security_alerts',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('alert_id', sa.String(length=64), nullable=False),
        sa.Column('rule_id', sa.String(length=64), nullable=False),
        sa.Column('rule_version', sa.String(length=16), nullable=False, server_default='1.0'),
        sa.Column('title', sa.String(length=128), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
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
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('alert_id'),
    )
    op.create_index('ix_internal_security_alerts_alert_id', 'internal_security_alerts', ['alert_id'])
    op.create_index('ix_internal_security_alerts_rule_id', 'internal_security_alerts', ['rule_id'])
    op.create_index('ix_internal_security_alerts_severity', 'internal_security_alerts', ['severity'])
    op.create_index('ix_internal_security_alerts_status', 'internal_security_alerts', ['status'])

    # 3. component_health_records
    op.create_table(
        'component_health_records',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('component_name', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='HEALTHY'),
        sa.Column('latency_ms', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('details', sa.JSON(), nullable=False),
        sa.Column('checked_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_component_health_records_component_name', 'component_health_records', ['component_name'])
    op.create_index('ix_component_health_records_checked_at', 'component_health_records', ['checked_at'])

    # 4. database_backups
    op.create_table(
        'database_backups',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('backup_id', sa.String(length=64), nullable=False),
        sa.Column('backup_type', sa.String(length=32), nullable=False, server_default='FULL'),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='COMPLETED'),
        sa.Column('size_bytes', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('checksum_sha256', sa.String(length=64), nullable=True),
        sa.Column('storage_location_ref', sa.String(length=255), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('error_category', sa.String(length=64), nullable=True),
        sa.Column('error_details', sa.Text(), nullable=True),
        sa.Column('initiated_by', sa.String(length=64), nullable=False, server_default='system'),
        sa.Column('retention_hold', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('restore_verified', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('restore_verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('backup_id'),
    )
    op.create_index('ix_database_backups_backup_id', 'database_backups', ['backup_id'])
    op.create_index('ix_database_backups_status', 'database_backups', ['status'])
    op.create_index('ix_database_backups_restore_verified', 'database_backups', ['restore_verified'])

    # 5. restore_test_records
    op.create_table(
        'restore_test_records',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('test_id', sa.String(length=64), nullable=False),
        sa.Column('backup_id', sa.String(length=64), nullable=False),
        sa.Column('test_environment', sa.String(length=64), nullable=False, server_default='isolated_sandbox_db'),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='SUCCESS'),
        sa.Column('duration_seconds', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('schema_compatibility_verified', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('table_count_verified', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('integrity_check_passed', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('verified_by', sa.String(length=64), nullable=False),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('diagnostic_notes', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['backup_id'], ['database_backups.backup_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('test_id'),
    )
    op.create_index('ix_restore_test_records_test_id', 'restore_test_records', ['test_id'])
    op.create_index('ix_restore_test_records_backup_id', 'restore_test_records', ['backup_id'])

    # 6. dr_configs
    op.create_table(
        'dr_configs',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('config_name', sa.String(length=64), nullable=False, server_default='default'),
        sa.Column('rpo_target_minutes', sa.Integer(), nullable=False, server_default='60'),
        sa.Column('rto_target_minutes', sa.Integer(), nullable=False, server_default='30'),
        sa.Column('backup_frequency_hours', sa.Integer(), nullable=False, server_default='24'),
        sa.Column('backup_retention_days', sa.Integer(), nullable=False, server_default='30'),
        sa.Column('cold_archive_retention_days', sa.Integer(), nullable=False, server_default='365'),
        sa.Column('auto_restore_test_frequency_days', sa.Integer(), nullable=False, server_default='7'),
        sa.Column('updated_by', sa.String(length=64), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('config_name'),
    )

    # 7. dr_checklists
    op.create_table(
        'dr_checklists',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('scenario_id', sa.String(length=64), nullable=False),
        sa.Column('scenario_title', sa.String(length=128), nullable=False),
        sa.Column('current_status', sa.String(length=32), nullable=False, server_default='READINESS_VERIFIED'),
        sa.Column('checklist_items', sa.JSON(), nullable=False),
        sa.Column('last_reviewed_by', sa.String(length=64), nullable=True),
        sa.Column('last_reviewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('scenario_id'),
    )
    op.create_index('ix_dr_checklists_scenario_id', 'dr_checklists', ['scenario_id'])

    # 8. internal_security_incidents
    op.create_table(
        'internal_security_incidents',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('incident_id', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=128), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False, server_default='MEDIUM'),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='OPEN'),
        sa.Column('assigned_administrator', sa.String(length=64), nullable=True),
        sa.Column('affected_components', sa.JSON(), nullable=False),
        sa.Column('linked_alert_ids', sa.JSON(), nullable=False),
        sa.Column('containment_notes', sa.Text(), nullable=True),
        sa.Column('recovery_actions_taken', sa.Text(), nullable=True),
        sa.Column('resolution_summary', sa.Text(), nullable=True),
        sa.Column('created_by', sa.String(length=64), nullable=False, server_default='system'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('incident_id'),
    )
    op.create_index('ix_internal_security_incidents_incident_id', 'internal_security_incidents', ['incident_id'])
    op.create_index('ix_internal_security_incidents_status', 'internal_security_incidents', ['status'])
    op.create_index('ix_internal_security_incidents_severity', 'internal_security_incidents', ['severity'])
    op.create_index('ix_internal_security_incidents_assigned_administrator', 'internal_security_incidents', ['assigned_administrator'])

    # 9. internal_incident_notes
    op.create_table(
        'internal_incident_notes',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('incident_id', sa.String(length=64), nullable=False),
        sa.Column('author_username', sa.String(length=64), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('note_type', sa.String(length=32), nullable=False, server_default='OBSERVATION'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['incident_id'], ['internal_security_incidents.incident_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_internal_incident_notes_incident_id', 'internal_incident_notes', ['incident_id'])


def downgrade() -> None:
    op.drop_table('internal_incident_notes')
    op.drop_table('internal_security_incidents')
    op.drop_table('dr_checklists')
    op.drop_table('dr_configs')
    op.drop_table('restore_test_records')
    op.drop_table('database_backups')
    op.drop_table('component_health_records')
    op.drop_table('internal_security_alerts')
    op.drop_table('internal_security_events')

