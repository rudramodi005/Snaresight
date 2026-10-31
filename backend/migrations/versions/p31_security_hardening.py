"""Alembic migration for Application Security Hardening, Access Control and Audit Protection (Task P31).

Revision ID: p31_security_hardening
Revises: p30_security_reports
Create Date: 2026-10-31 23:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'p31_security_hardening'
down_revision = 'p30_security_reports'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. users table
    op.create_table(
        'users',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('username', sa.String(length=64), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('full_name', sa.String(length=128), nullable=True),
        sa.Column('role', sa.String(length=32), nullable=False, server_default='ANALYST'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('failed_login_attempts', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('username'),
        sa.UniqueConstraint('email'),
    )
    op.create_index('ix_users_username', 'users', ['username'])
    op.create_index('ix_users_email', 'users', ['email'])
    op.create_index('ix_users_role', 'users', ['role'])

    # 2. revoked_tokens table
    op.create_table(
        'revoked_tokens',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('jti', sa.String(length=64), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('jti'),
    )
    op.create_index('ix_revoked_tokens_jti', 'revoked_tokens', ['jti'])
    op.create_index('ix_revoked_tokens_user_id', 'revoked_tokens', ['user_id'])
    op.create_index('ix_revoked_tokens_expires_at', 'revoked_tokens', ['expires_at'])

    # 3. system_audit_logs table
    op.create_table(
        'system_audit_logs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('actor_username', sa.String(length=64), nullable=False),
        sa.Column('actor_role', sa.String(length=32), nullable=False),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('resource_type', sa.String(length=64), nullable=False),
        sa.Column('resource_id', sa.String(length=128), nullable=True),
        sa.Column('outcome', sa.String(length=16), nullable=False, server_default='SUCCESS'),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.String(length=255), nullable=True),
        sa.Column('request_context', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_system_audit_logs_actor_username', 'system_audit_logs', ['actor_username'])
    op.create_index('ix_system_audit_logs_action', 'system_audit_logs', ['action'])
    op.create_index('ix_system_audit_logs_created_at', 'system_audit_logs', ['created_at'])


def downgrade() -> None:
    op.drop_index('ix_system_audit_logs_created_at', table_name='system_audit_logs')
    op.drop_index('ix_system_audit_logs_action', table_name='system_audit_logs')
    op.drop_index('ix_system_audit_logs_actor_username', table_name='system_audit_logs')
    op.drop_table('system_audit_logs')

    op.drop_index('ix_revoked_tokens_expires_at', table_name='revoked_tokens')
    op.drop_index('ix_revoked_tokens_user_id', table_name='revoked_tokens')
    op.drop_index('ix_revoked_tokens_jti', table_name='revoked_tokens')
    op.drop_table('revoked_tokens')

    op.drop_index('ix_users_role', table_name='users')
    op.drop_index('ix_users_email', table_name='users')
    op.drop_index('ix_users_username', table_name='users')
    op.drop_table('users')

