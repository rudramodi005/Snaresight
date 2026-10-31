"""Alembic migration for SOC Alert Management, Triage Center, and Prioritization (Task P28).

Revision ID: p28_alert_triage_center
Revises: p27_event_investigations
Create Date: 2026-10-31 21:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'p28_alert_triage_center'
down_revision = 'p27_event_investigations'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Add triage & prioritization columns to alerts table
    op.add_column('alerts', sa.Column('assigned_analyst', sa.String(length=128), nullable=True))
    op.add_column('alerts', sa.Column('triage_decision', sa.String(length=32), nullable=True))
    op.add_column('alerts', sa.Column('triage_justification', sa.Text(), nullable=True))
    op.add_column('alerts', sa.Column('priority_score', sa.Float(), nullable=True))
    op.add_column('alerts', sa.Column('priority_level', sa.String(length=16), nullable=True, server_default='P3_MEDIUM'))
    op.add_column('alerts', sa.Column('resolution_category', sa.String(length=64), nullable=True))
    op.add_column('alerts', sa.Column('resolution_reason', sa.Text(), nullable=True))
    op.add_column('alerts', sa.Column('escalation_reason', sa.Text(), nullable=True))
    op.add_column('alerts', sa.Column('escalation_role', sa.String(length=64), nullable=True))
    op.add_column('alerts', sa.Column('closure_reason', sa.Text(), nullable=True))

    op.create_index('ix_alerts_assigned_analyst', 'alerts', ['assigned_analyst'])
    op.create_index('ix_alerts_triage_decision', 'alerts', ['triage_decision'])
    op.create_index('ix_alerts_priority_score', 'alerts', ['priority_score'])
    op.create_index('idx_alerts_priority', 'alerts', ['priority_score', 'generated_at'])

    # 2. Create alert_audit_logs table
    op.create_table(
        'alert_audit_logs',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('alert_id', sa.UUID(), nullable=False),
        sa.Column('action_type', sa.String(length=64), nullable=False),
        sa.Column('analyst_id', sa.String(length=128), nullable=False),
        sa.Column('previous_status', sa.String(length=32), nullable=True),
        sa.Column('new_status', sa.String(length=32), nullable=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('details', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.alert_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_alert_audit_logs_alert_id', 'alert_audit_logs', ['alert_id'])
    op.create_index('ix_alert_audit_logs_action_type', 'alert_audit_logs', ['action_type'])
    op.create_index('ix_alert_audit_logs_created_at', 'alert_audit_logs', ['created_at'])

    # 3. Create alert_notes table
    op.create_table(
        'alert_notes',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('alert_id', sa.UUID(), nullable=False),
        sa.Column('author_id', sa.String(length=128), nullable=False),
        sa.Column('author_role', sa.String(length=64), nullable=False, server_default='SOC_ANALYST'),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.alert_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_alert_notes_alert_id', 'alert_notes', ['alert_id'])
    op.create_index('ix_alert_notes_created_at', 'alert_notes', ['created_at'])


def downgrade() -> None:
    # 1. Drop alert_notes
    op.drop_index('ix_alert_notes_created_at', table_name='alert_notes')
    op.drop_index('ix_alert_notes_alert_id', table_name='alert_notes')
    op.drop_table('alert_notes')

    # 2. Drop alert_audit_logs
    op.drop_index('ix_alert_audit_logs_created_at', table_name='alert_audit_logs')
    op.drop_index('ix_alert_audit_logs_action_type', table_name='alert_audit_logs')
    op.drop_index('ix_alert_audit_logs_alert_id', table_name='alert_audit_logs')
    op.drop_table('alert_audit_logs')

    # 3. Drop columns from alerts
    op.drop_index('idx_alerts_priority', table_name='alerts')
    op.drop_index('ix_alerts_priority_score', table_name='alerts')
    op.drop_index('ix_alerts_triage_decision', table_name='alerts')
    op.drop_index('ix_alerts_assigned_analyst', table_name='alerts')

    op.drop_column('alerts', 'closure_reason')
    op.drop_column('alerts', 'escalation_role')
    op.drop_column('alerts', 'escalation_reason')
    op.drop_column('alerts', 'resolution_reason')
    op.drop_column('alerts', 'resolution_category')
    op.drop_column('alerts', 'priority_level')
    op.drop_column('alerts', 'priority_score')
    op.drop_column('alerts', 'triage_justification')
    op.drop_column('alerts', 'triage_decision')
    op.drop_column('alerts', 'assigned_analyst')

