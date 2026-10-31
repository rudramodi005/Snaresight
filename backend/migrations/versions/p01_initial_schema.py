"""Alembic baseline migration for SnareSight Core Relational Schema (P01–P23).

Revision ID: p23_source_profiles
Revises: None
Create Date: 2026-10-31 18:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Revision identifiers, used by Alembic
revision = 'p23_source_profiles'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. honeypots
    op.create_table(
        'honeypots',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('decoy_id', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('decoy_type', sa.String(length=64), nullable=False),
        sa.Column('protocol', sa.String(length=32), nullable=False),
        sa.Column('environment', sa.String(length=32), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='ACTIVE'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('decoy_id'),
    )
    op.create_index('ix_honeypots_decoy_id', 'honeypots', ['decoy_id'])

    # 2. event_sources
    op.create_table(
        'event_sources',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('source_id', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('source_type', sa.String(length=32), nullable=False),
        sa.Column('environment', sa.String(length=32), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='ACTIVE'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('source_id'),
    )

    # 3. raw_events
    op.create_table(
        'raw_events',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('raw_event_id', sa.UUID(), nullable=False),
        sa.Column('schema_version', sa.String(length=16), nullable=False, server_default='1.0'),
        sa.Column('event_type', sa.String(length=64), nullable=False),
        sa.Column('event_category', sa.String(length=64), nullable=False),
        sa.Column('decoy_id', sa.String(length=64), nullable=False),
        sa.Column('event_source_id', sa.String(length=64), nullable=False),
        sa.Column('session_id', sa.String(length=64), nullable=False),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('received_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('sanitized_payload', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('provenance', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('validation_status', sa.String(length=32), nullable=False, server_default='VALID'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['decoy_id'], ['honeypots.decoy_id'], ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('raw_event_id'),
    )
    op.create_index('ix_raw_events_raw_event_id', 'raw_events', ['raw_event_id'])
    op.create_index('ix_raw_events_session_id', 'raw_events', ['session_id'])
    op.create_index('ix_raw_events_observed_at', 'raw_events', ['observed_at'])

    # 4. security_events
    op.create_table(
        'security_events',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('event_id', sa.UUID(), nullable=False),
        sa.Column('raw_event_id', sa.UUID(), nullable=False),
        sa.Column('schema_version', sa.String(length=16), nullable=False, server_default='1.0'),
        sa.Column('event_type', sa.String(length=64), nullable=False),
        sa.Column('event_category', sa.String(length=64), nullable=False),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('outcome', sa.String(length=16), nullable=False),
        sa.Column('decoy_id', sa.String(length=64), nullable=False),
        sa.Column('session_id', sa.String(length=64), nullable=False),
        sa.Column('observed_source_id', sa.String(length=64), nullable=True),
        sa.Column('source_address', sa.String(length=45), nullable=False),
        sa.Column('source_port', sa.Integer(), nullable=True),
        sa.Column('source_protocol', sa.String(length=16), nullable=False),
        sa.Column('target_service', sa.String(length=32), nullable=False),
        sa.Column('target_port', sa.Integer(), nullable=False),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('received_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('normalized_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('sanitized_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('provenance', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('processing_status', sa.String(length=32), nullable=False, server_default='PROCESSED'),
        sa.Column('deduplication_reference', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['decoy_id'], ['honeypots.decoy_id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['raw_event_id'], ['raw_events.raw_event_id'], ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('event_id'),
        sa.UniqueConstraint('raw_event_id'),
        sa.UniqueConstraint('deduplication_reference'),
    )
    op.create_index('ix_security_events_event_id', 'security_events', ['event_id'])
    op.create_index('ix_security_events_session_id', 'security_events', ['session_id'])
    op.create_index('ix_security_events_source_address', 'security_events', ['source_address'])

    # 5. sessions
    op.create_table(
        'sessions',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('session_id', sa.String(length=64), nullable=False),
        sa.Column('source_address', sa.String(length=45), nullable=False),
        sa.Column('decoy_id', sa.String(length=64), nullable=False),
        sa.Column('start_time', sa.DateTime(timezone=True), nullable=False),
        sa.Column('end_time', sa.DateTime(timezone=True), nullable=True),
        sa.Column('event_count', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='ACTIVE'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('session_id'),
    )
    op.create_index('ix_sessions_session_id', 'sessions', ['session_id'])

    # 6. correlation_sequences
    op.create_table(
        'correlation_sequences',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('sequence_id', sa.String(length=64), nullable=False),
        sa.Column('source_address', sa.String(length=45), nullable=False),
        sa.Column('stage_count', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='ACTIVE'),
        sa.Column('first_observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('sequence_id'),
    )

    # 7. detection_rules
    op.create_table(
        'detection_rules',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('rule_id', sa.String(length=64), nullable=False),
        sa.Column('rule_version', sa.String(length=16), nullable=False, server_default='1.0'),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('category', sa.String(length=64), nullable=False),
        sa.Column('severity', sa.String(length=16), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('rule_id'),
    )

    # 8. alerts
    op.create_table(
        'alerts',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('alert_id', sa.UUID(), nullable=False),
        sa.Column('schema_version', sa.String(length=16), nullable=False, server_default='1.0'),
        sa.Column('detection_rule_id', sa.String(length=64), nullable=False),
        sa.Column('detection_rule_version', sa.String(length=16), nullable=False, server_default='1.0'),
        sa.Column('title', sa.String(length=128), nullable=False),
        sa.Column('summary', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=16), nullable=False),
        sa.Column('confidence', sa.SmallInteger(), nullable=False),
        sa.Column('assessment_status', sa.String(length=32), nullable=False, server_default='NEW'),
        sa.Column('evidence_strength', sa.String(length=32), nullable=False),
        sa.Column('source_address', sa.String(length=45), nullable=False),
        sa.Column('observed_source_id', sa.String(length=64), nullable=False),
        sa.Column('decoy_id', sa.String(length=64), nullable=False),
        sa.Column('target_service', sa.String(length=32), nullable=False),
        sa.Column('first_observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('generated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('detection_explanation', sa.Text(), nullable=False),
        sa.Column('recommendations', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['decoy_id'], ['honeypots.decoy_id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['detection_rule_id'], ['detection_rules.rule_id'], ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('alert_id'),
    )
    op.create_index('ix_alerts_alert_id', 'alerts', ['alert_id'])
    op.create_index('ix_alerts_detection_rule_id', 'alerts', ['detection_rule_id'])
    op.create_index('ix_alerts_severity', 'alerts', ['severity'])

    # 9. alert_evidence
    op.create_table(
        'alert_evidence',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('alert_id', sa.UUID(), nullable=False),
        sa.Column('event_id', sa.UUID(), nullable=False),
        sa.Column('evidence_role', sa.String(length=64), nullable=False, server_default='TRIGGERING_OBSERVATION'),
        sa.Column('evidence_summary', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.alert_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['event_id'], ['security_events.event_id'], ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('alert_id', 'event_id', name='uq_alert_evidence_pair'),
    )

    # 10. attack_techniques
    op.create_table(
        'attack_techniques',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('technique_id', sa.String(length=32), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('tactic', sa.String(length=64), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('technique_id'),
    )

    # 11. technique_mappings
    op.create_table(
        'technique_mappings',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('mapping_id', sa.String(length=64), nullable=False),
        sa.Column('rule_id', sa.String(length=64), nullable=False),
        sa.Column('technique_id', sa.String(length=32), nullable=False),
        sa.Column('confidence', sa.SmallInteger(), nullable=False, server_default='80'),
        sa.Column('review_status', sa.String(length=32), nullable=False, server_default='APPROVED'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['rule_id'], ['detection_rules.rule_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['technique_id'], ['attack_techniques.technique_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('mapping_id'),
    )

    # 12. source_profiles
    op.create_table(
        'source_profiles',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('source_profile_id', sa.String(length=64), nullable=False),
        sa.Column('source_address', sa.String(length=45), nullable=False),
        sa.Column('reputation_score', sa.SmallInteger(), nullable=False, server_default='50'),
        sa.Column('threat_classification', sa.String(length=32), nullable=False, server_default='UNKNOWN'),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('total_events', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('total_sessions', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('source_profile_id'),
        sa.UniqueConstraint('source_address'),
    )
    op.create_index('ix_source_profiles_source_address', 'source_profiles', ['source_address'])


def downgrade() -> None:
    op.drop_table('source_profiles')
    op.drop_table('technique_mappings')
    op.drop_table('attack_techniques')
    op.drop_table('alert_evidence')
    op.drop_table('alerts')
    op.drop_table('detection_rules')
    op.drop_table('correlation_sequences')
    op.drop_table('sessions')
    op.drop_table('security_events')
    op.drop_table('raw_events')
    op.drop_table('event_sources')
    op.drop_table('honeypots')

