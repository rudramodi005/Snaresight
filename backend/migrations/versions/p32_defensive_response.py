"""Alembic migration for Defensive Response and Incident Handling Workflow (Task P32).

Revision ID: p32_defensive_response
Revises: p31_security_hardening
Create Date: 2026-10-31 23:45:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'p32_defensive_response'
down_revision = 'p31_security_hardening'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. response_cases
    op.create_table(
        'response_cases',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('case_id', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=128), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='OPEN'),
        sa.Column('priority', sa.String(length=16), nullable=False, server_default='P3_MEDIUM'),
        sa.Column('severity', sa.String(length=16), nullable=False, server_default='MEDIUM'),
        sa.Column('assigned_analyst', sa.String(length=64), nullable=True),
        sa.Column('primary_alert_id', sa.String(length=64), nullable=True),
        sa.Column('primary_cluster_id', sa.String(length=64), nullable=True),
        sa.Column('resolution_summary', sa.Text(), nullable=True),
        sa.Column('resolution_category', sa.String(length=64), nullable=True),
        sa.Column('reopen_reason', sa.Text(), nullable=True),
        sa.Column('created_by', sa.String(length=64), nullable=False, server_default='system'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('case_id'),
    )
    op.create_index('ix_response_cases_case_id', 'response_cases', ['case_id'])
    op.create_index('ix_response_cases_status', 'response_cases', ['status'])
    op.create_index('ix_response_cases_priority', 'response_cases', ['priority'])
    op.create_index('ix_response_cases_assigned_analyst', 'response_cases', ['assigned_analyst'])

    # 2. case_relationships
    op.create_table(
        'case_relationships',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('case_id', sa.String(length=64), nullable=False),
        sa.Column('related_entity_type', sa.String(length=32), nullable=False),
        sa.Column('related_entity_id', sa.String(length=64), nullable=False),
        sa.Column('relationship_reason', sa.Text(), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('created_by', sa.String(length=64), nullable=False, server_default='system'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['response_cases.case_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_case_relationships_case_id', 'case_relationships', ['case_id'])
    op.create_index('ix_case_relationships_entity', 'case_relationships', ['related_entity_type', 'related_entity_id'])

    # 3. case_notes
    op.create_table(
        'case_notes',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('case_id', sa.String(length=64), nullable=False),
        sa.Column('author_username', sa.String(length=64), nullable=False),
        sa.Column('author_role', sa.String(length=32), nullable=False),
        sa.Column('note_type', sa.String(length=32), nullable=False, server_default='ANALYST_NOTE'),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['response_cases.case_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_case_notes_case_id', 'case_notes', ['case_id'])

    # 4. response_recommendations
    op.create_table(
        'response_recommendations',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('recommendation_id', sa.String(length=64), nullable=False),
        sa.Column('case_id', sa.String(length=64), nullable=False),
        sa.Column('rule_id', sa.String(length=64), nullable=False),
        sa.Column('rule_version', sa.String(length=16), nullable=False, server_default='1.0'),
        sa.Column('title', sa.String(length=128), nullable=False),
        sa.Column('explanation', sa.Text(), nullable=False),
        sa.Column('triggering_evidence', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('supporting_event_ids', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('priority', sa.String(length=16), nullable=False, server_default='MEDIUM'),
        sa.Column('confidence', sa.String(length=32), nullable=False, server_default='HIGH'),
        sa.Column('required_permission', sa.String(length=64), nullable=False, server_default='execute_defensive_action'),
        sa.Column('requires_approval', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('potential_impact', sa.Text(), nullable=False),
        sa.Column('reversal_guidance', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='PENDING'),
        sa.Column('decision_by', sa.String(length=64), nullable=True),
        sa.Column('decision_reason', sa.Text(), nullable=True),
        sa.Column('decision_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['response_cases.case_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('recommendation_id'),
    )
    op.create_index('ix_response_recommendations_rec_id', 'response_recommendations', ['recommendation_id'])
    op.create_index('ix_response_recommendations_case_id', 'response_recommendations', ['case_id'])

    # 5. playbook_definitions
    op.create_table(
        'playbook_definitions',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('playbook_id', sa.String(length=64), nullable=False),
        sa.Column('version', sa.String(length=16), nullable=False, server_default='1.0'),
        sa.Column('title', sa.String(length=128), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('trigger_conditions', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('required_inputs', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('workflow_steps', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('required_permission', sa.String(length=64), nullable=False, server_default='execute_defensive_action'),
        sa.Column('requires_approval', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('playbook_id'),
    )
    op.create_index('ix_playbook_definitions_id', 'playbook_definitions', ['playbook_id'])

    # 6. playbook_executions
    op.create_table(
        'playbook_executions',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('execution_id', sa.String(length=64), nullable=False),
        sa.Column('playbook_id', sa.String(length=64), nullable=False),
        sa.Column('case_id', sa.String(length=64), nullable=False),
        sa.Column('initiated_by', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='IN_PROGRESS'),
        sa.Column('current_step_index', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('step_results', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('inputs', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('outcome_summary', sa.Text(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['case_id'], ['response_cases.case_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('execution_id'),
    )
    op.create_index('ix_playbook_executions_id', 'playbook_executions', ['execution_id'])
    op.create_index('ix_playbook_executions_case_id', 'playbook_executions', ['case_id'])

    # 7. response_approvals
    op.create_table(
        'response_approvals',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('approval_id', sa.String(length=64), nullable=False),
        sa.Column('case_id', sa.String(length=64), nullable=False),
        sa.Column('recommendation_id', sa.String(length=64), nullable=True),
        sa.Column('action_type', sa.String(length=64), nullable=False),
        sa.Column('requested_by', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='PENDING'),
        sa.Column('justification', sa.Text(), nullable=False),
        sa.Column('approved_by', sa.String(length=64), nullable=True),
        sa.Column('decision_reason', sa.Text(), nullable=True),
        sa.Column('decision_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['response_cases.case_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('approval_id'),
    )
    op.create_index('ix_response_approvals_id', 'response_approvals', ['approval_id'])
    op.create_index('ix_response_approvals_case_id', 'response_approvals', ['case_id'])

    # 8. response_actions
    op.create_table(
        'response_actions',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('action_id', sa.String(length=64), nullable=False),
        sa.Column('case_id', sa.String(length=64), nullable=False),
        sa.Column('approval_id', sa.String(length=64), nullable=True),
        sa.Column('action_type', sa.String(length=64), nullable=False),
        sa.Column('executed_by', sa.String(length=64), nullable=False),
        sa.Column('execution_status', sa.String(length=32), nullable=False, server_default='SUCCESS'),
        sa.Column('is_simulated', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('parameters', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('result_details', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('executed_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['response_cases.case_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('action_id'),
    )
    op.create_index('ix_response_actions_id', 'response_actions', ['action_id'])
    op.create_index('ix_response_actions_case_id', 'response_actions', ['case_id'])

    # 9. evidence_preservation_holds
    op.create_table(
        'evidence_preservation_holds',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('hold_id', sa.String(length=64), nullable=False),
        sa.Column('case_id', sa.String(length=64), nullable=False),
        sa.Column('evidence_type', sa.String(length=32), nullable=False),
        sa.Column('evidence_identifier', sa.String(length=64), nullable=False),
        sa.Column('integrity_hash_sha256', sa.String(length=64), nullable=True),
        sa.Column('retention_hold_status', sa.String(length=32), nullable=False, server_default='ACTIVE'),
        sa.Column('hold_reason', sa.Text(), nullable=False),
        sa.Column('applied_by', sa.String(length=64), nullable=False),
        sa.Column('applied_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('released_by', sa.String(length=64), nullable=True),
        sa.Column('released_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('release_justification', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['case_id'], ['response_cases.case_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('hold_id'),
    )
    op.create_index('ix_evidence_preservation_holds_id', 'evidence_preservation_holds', ['hold_id'])
    op.create_index('ix_evidence_preservation_holds_case_id', 'evidence_preservation_holds', ['case_id'])
    op.create_index('ix_evidence_preservation_holds_evidence', 'evidence_preservation_holds', ['evidence_type', 'evidence_identifier'])


def downgrade() -> None:
    op.drop_table('evidence_preservation_holds')
    op.drop_table('response_actions')
    op.drop_table('response_approvals')
    op.drop_table('playbook_executions')
    op.drop_table('playbook_definitions')
    op.drop_table('response_recommendations')
    op.drop_table('case_notes')
    op.drop_table('case_relationships')
    op.drop_table('response_cases')

