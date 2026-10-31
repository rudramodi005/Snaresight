"""Alembic migration for Security Events Explorer & Event Investigation Audit Logs (Task P27).

Revision ID: p27_event_investigations
Revises: p24_campaign_clusters
Create Date: 2026-10-31 20:30:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'p27_event_investigations'
down_revision = 'p24_campaign_clusters'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. event_audit_logs
    op.create_table(
        'event_audit_logs',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('event_id', sa.UUID(), nullable=False),
        sa.Column('action_type', sa.String(length=64), nullable=False),
        sa.Column('analyst_id', sa.String(length=128), nullable=False),
        sa.Column('review_status', sa.String(length=32), nullable=False, server_default='UNREVIEWED'),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('extra_data', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['event_id'], ['security_events.event_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_event_audit_logs_event_id', 'event_audit_logs', ['event_id'])
    op.create_index('ix_event_audit_logs_action_type', 'event_audit_logs', ['action_type'])
    op.create_index('ix_event_audit_logs_created_at', 'event_audit_logs', ['created_at'])


def downgrade() -> None:
    op.drop_index('ix_event_audit_logs_created_at', table_name='event_audit_logs')
    op.drop_index('ix_event_audit_logs_action_type', table_name='event_audit_logs')
    op.drop_index('ix_event_audit_logs_event_id', table_name='event_audit_logs')
    op.drop_table('event_audit_logs')

