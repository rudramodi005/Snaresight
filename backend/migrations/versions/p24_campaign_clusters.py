"""Alembic migration for Campaign Intelligence and Investigation Clusters (Task P24).

Revision ID: p24_campaign_clusters
Revises: p23_source_profiles
Create Date: 2026-10-31 19:30:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'p24_campaign_clusters'
down_revision = 'p23_source_profiles'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. investigation_clusters
    op.create_table(
        'investigation_clusters',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('cluster_id', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=128), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('lifecycle_status', sa.String(length=32), nullable=False),
        sa.Column('priority', sa.String(length=20), nullable=False),
        sa.Column('review_status', sa.String(length=32), nullable=False),
        sa.Column('analyst_owner', sa.String(length=64), nullable=True),
        sa.Column('cluster_methodology_version', sa.String(length=16), nullable=False),
        sa.Column('first_observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('evidence_summary', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('destination_cluster_id', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "lifecycle_status IN ('CANDIDATE', 'UNDER_REVIEW', 'ACTIVE', 'MONITORING', 'CLOSED', 'MERGED', 'SPLIT')",
            name='ck_cluster_lifecycle_status',
        ),
        sa.CheckConstraint("priority IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')", name='ck_cluster_priority'),
        sa.CheckConstraint("review_status IN ('UNREVIEWED', 'UNDER_REVIEW', 'ACCEPTED', 'DISMISSED')", name='ck_cluster_review_status'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('cluster_id'),
    )
    op.create_index('ix_investigation_clusters_cluster_id', 'investigation_clusters', ['cluster_id'])
    op.create_index('ix_cluster_status_prio', 'investigation_clusters', ['lifecycle_status', 'priority'])
    op.create_index('ix_cluster_last_obs', 'investigation_clusters', ['last_observed_at'])

    # 2. cluster_memberships
    op.create_table(
        'cluster_memberships',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('cluster_id', sa.String(length=64), nullable=False),
        sa.Column('member_type', sa.String(length=32), nullable=False),
        sa.Column('member_id', sa.String(length=64), nullable=False),
        sa.Column('association_method', sa.String(length=64), nullable=False),
        sa.Column('association_confidence', sa.SmallInteger(), nullable=False),
        sa.Column('evidence_references', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('membership_status', sa.String(length=32), nullable=False),
        sa.Column('analyst_review_status', sa.String(length=32), nullable=False),
        sa.Column('reviewed_by', sa.String(length=64), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("member_type IN ('SESSION', 'SOURCE_PROFILE', 'ALERT', 'SEQUENCE', 'EVENT')", name='ck_cluster_member_type'),
        sa.CheckConstraint("membership_status IN ('PROPOSED', 'ACCEPTED', 'REJECTED', 'REMOVED')", name='ck_cluster_member_status'),
        sa.CheckConstraint("analyst_review_status IN ('PENDING', 'APPROVED', 'DISMISSED')", name='ck_cluster_member_review_status'),
        sa.ForeignKeyConstraint(['cluster_id'], ['investigation_clusters.cluster_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('cluster_id', 'member_type', 'member_id', name='uq_cluster_member'),
    )

    # 3. cluster_evidence
    op.create_table(
        'cluster_evidence',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('evidence_id', sa.String(length=64), nullable=False),
        sa.Column('cluster_id', sa.String(length=64), nullable=False),
        sa.Column('evidence_type', sa.String(length=64), nullable=False),
        sa.Column('evidence_reference', sa.String(length=128), nullable=False),
        sa.Column('evidence_description', sa.Text(), nullable=False),
        sa.Column('contribution_score', sa.Float(), nullable=False),
        sa.Column('classification', sa.String(length=32), nullable=False),
        sa.Column('evidence_timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('methodology_version', sa.String(length=16), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("classification IN ('SUPPORTING', 'CONTRADICTING')", name='ck_cluster_evidence_classification'),
        sa.ForeignKeyConstraint(['cluster_id'], ['investigation_clusters.cluster_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('evidence_id'),
    )

    # 4. cluster_relationships
    op.create_table(
        'cluster_relationships',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('relationship_id', sa.String(length=64), nullable=False),
        sa.Column('source_cluster_id', sa.String(length=64), nullable=False),
        sa.Column('target_cluster_id', sa.String(length=64), nullable=False),
        sa.Column('relationship_type', sa.String(length=64), nullable=False),
        sa.Column('supporting_evidence', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('relationship_confidence', sa.SmallInteger(), nullable=False),
        sa.Column('analyst_review_status', sa.String(length=32), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("relationship_type IN ('BEHAVIORAL_SIMILARITY', 'SEQUENTIAL_PROGRESSION', 'SHARED_INFRASTRUCTURE', 'SHARED_TECHNIQUE_SET', 'SUB_CAMPAIGN')", name='ck_cluster_relationship_type'),
        sa.CheckConstraint("analyst_review_status IN ('PROPOSED', 'ACCEPTED', 'REJECTED')", name='ck_cluster_relationship_review_status'),
        sa.ForeignKeyConstraint(['source_cluster_id'], ['investigation_clusters.cluster_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['target_cluster_id'], ['investigation_clusters.cluster_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('source_cluster_id', 'target_cluster_id', 'relationship_type', name='uq_cluster_pair_rel'),
    )

    # 5. cluster_audit_logs
    op.create_table(
        'cluster_audit_logs',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('cluster_id', sa.String(length=64), nullable=False),
        sa.Column('actor', sa.String(length=64), nullable=False),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('target', sa.String(length=128), nullable=True),
        sa.Column('previous_state', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('new_state', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['cluster_id'], ['investigation_clusters.cluster_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    op.drop_table('cluster_audit_logs')
    op.drop_table('cluster_relationships')
    op.drop_table('cluster_evidence')
    op.drop_table('cluster_memberships')
    op.drop_table('investigation_clusters')

