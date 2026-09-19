"""create_evidence_and_update_audit_logs

Revision ID: 64a0d89a8460
Revises: ae5ff3420a0a
Create Date: 2026-09-08 15:38:27.496173

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '64a0d89a8460'
down_revision: Union[str, Sequence[str], None] = 'ae5ff3420a0a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # 1. Create evidence table
    op.create_table('evidence',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('evidence_id', sa.String(length=64), nullable=False),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('original_filename', sa.String(length=255), nullable=False),
        sa.Column('upload_timestamp', sa.DateTime(), nullable=False),
        sa.Column('size', sa.Integer(), nullable=False),
        sa.Column('uploader', sa.String(length=100), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_evidence_evidence_id'), 'evidence', ['evidence_id'], unique=True)
    op.create_index(op.f('ix_evidence_sha256'), 'evidence', ['sha256'], unique=False)

    # 2. Update audit_logs table
    with op.batch_alter_table('audit_logs') as batch_op:
        batch_op.add_column(sa.Column('user', sa.String(length=100), nullable=True, server_default='SOC Analyst'))
        batch_op.add_column(sa.Column('resource_type', sa.String(length=50), nullable=False, server_default='case'))
        batch_op.add_column(sa.Column('resource_id', sa.String(length=128), nullable=False, server_default=''))
        batch_op.add_column(sa.Column('metadata_json', sa.Text(), nullable=True, server_default='{}'))
        batch_op.alter_column('case_id', existing_type=sa.VARCHAR(length=36), nullable=True)
        batch_op.alter_column('details', existing_type=sa.TEXT(), nullable=True)
        batch_op.create_index(batch_op.f('ix_audit_logs_action'), ['action'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_logs_resource_id'), ['resource_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_logs_resource_type'), ['resource_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_logs_timestamp'), ['timestamp'], unique=False)

    # 3. Update case_emails table threat_score
    with op.batch_alter_table('case_emails') as batch_op:
        batch_op.alter_column('threat_score',
            existing_type=sa.INTEGER(),
            type_=sa.Float(),
            existing_nullable=True
        )

    # 4. Update cases indexes
    with op.batch_alter_table('cases') as batch_op:
        batch_op.create_index(batch_op.f('ix_cases_severity'), ['severity'], unique=False)
        batch_op.create_index(batch_op.f('ix_cases_status'), ['status'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('cases') as batch_op:
        batch_op.drop_index(batch_op.f('ix_cases_status'))
        batch_op.drop_index(batch_op.f('ix_cases_severity'))

    with op.batch_alter_table('case_emails') as batch_op:
        batch_op.alter_column('threat_score',
            existing_type=sa.Float(),
            type_=sa.INTEGER(),
            existing_nullable=True
        )

    with op.batch_alter_table('audit_logs') as batch_op:
        batch_op.drop_index(batch_op.f('ix_audit_logs_timestamp'))
        batch_op.drop_index(batch_op.f('ix_audit_logs_resource_type'))
        batch_op.drop_index(batch_op.f('ix_audit_logs_resource_id'))
        batch_op.drop_index(batch_op.f('ix_audit_logs_action'))
        batch_op.alter_column('details', existing_type=sa.TEXT(), nullable=False)
        batch_op.alter_column('case_id', existing_type=sa.VARCHAR(length=36), nullable=False)
        batch_op.drop_column('metadata_json')
        batch_op.drop_column('resource_id')
        batch_op.drop_column('resource_type')
        batch_op.drop_column('user')

    op.drop_index(op.f('ix_evidence_sha256'), table_name='evidence')
    op.drop_index(op.f('ix_evidence_evidence_id'), table_name='evidence')
    op.drop_table('evidence')
