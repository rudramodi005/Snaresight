"""Alembic migration for SOC Analytics, Security Reporting and Executive Overview (Task P30).

Revision ID: p30_security_reports
Revises: p28_alert_triage_center
Create Date: 2026-10-31 22:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'p30_security_reports'
down_revision = 'p28_alert_triage_center'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'security_reports',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('report_title', sa.String(length=255), nullable=False),
        sa.Column('report_type', sa.String(length=64), nullable=False, server_default='EXECUTIVE_SUMMARY'),
        sa.Column('time_range_label', sa.String(length=64), nullable=False, server_default='24h'),
        sa.Column('start_time', sa.DateTime(timezone=True), nullable=False),
        sa.Column('end_time', sa.DateTime(timezone=True), nullable=False),
        sa.Column('generated_by', sa.String(length=128), nullable=False, server_default='analyst_soc_user'),
        sa.Column('file_format', sa.String(length=16), nullable=False, server_default='PDF'),
        sa.Column('filters_applied', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('summary_metrics', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='COMPLETED'),
        sa.Column('file_size_bytes', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('pdf_content', sa.LargeBinary(), nullable=True),
        sa.Column('csv_content', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_security_reports_created_at', 'security_reports', ['created_at'])
    op.create_index('ix_security_reports_generated_by', 'security_reports', ['generated_by'])
    op.create_index('ix_security_reports_type', 'security_reports', ['report_type'])


def downgrade() -> None:
    op.drop_index('ix_security_reports_type', table_name='security_reports')
    op.drop_index('ix_security_reports_generated_by', table_name='security_reports')
    op.drop_index('ix_security_reports_created_at', table_name='security_reports')
    op.drop_table('security_reports')

