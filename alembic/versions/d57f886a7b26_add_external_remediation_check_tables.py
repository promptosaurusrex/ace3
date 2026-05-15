"""add external remediation check tables

Revision ID: d57f886a7b26
Revises: 71b6228ef435
Create Date: 2026-05-13 15:57:28.873375

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision: str = 'd57f886a7b26'
down_revision: Union[str, None] = '71b6228ef435'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('external_remediation_check',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('probe_name', sa.String(length=64), nullable=False),
    sa.Column('observable_type', sa.String(length=64), nullable=False),
    sa.Column('observable_value', sa.Text(), nullable=False),
    sa.Column('alert_uuid', sa.String(length=36), nullable=False),
    sa.Column('status', sa.Enum('NEW', 'IN_PROGRESS', 'COMPLETED'), server_default=sa.text("'NEW'"), nullable=False),
    sa.Column('result', sa.Enum('CONFIRMED', 'NOT_FOUND', 'EXPIRED', 'ERROR', 'CANCELLED'), nullable=True),
    sa.Column('result_message', sa.Text(), nullable=True),
    sa.Column('insert_date', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.Column('update_time', sa.TIMESTAMP(), nullable=True),
    sa.Column('retry_count', sa.Integer(), server_default=sa.text('0'), nullable=False),
    sa.Column('max_retries', sa.Integer(), nullable=False),
    sa.Column('deadline', sa.DateTime(), nullable=False),
    sa.Column('lock', sa.String(length=36), nullable=True),
    sa.Column('lock_time', sa.DateTime(), nullable=True),
    sa.Column('events_json', mysql.MEDIUMTEXT(), nullable=True),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_erc_collector_loop', 'external_remediation_check', ['status', 'probe_name', sa.literal_column('insert_date DESC')], unique=False, mysql_length={'probe_name': 64})
    op.create_index('idx_erc_observable_lookup', 'external_remediation_check', ['probe_name', 'observable_type', 'alert_uuid'], unique=False, mysql_length={'probe_name': 64, 'observable_type': 64})
    op.create_index('idx_erc_probe_name', 'external_remediation_check', ['probe_name'], unique=False)
    op.create_index(op.f('ix_external_remediation_check_alert_uuid'), 'external_remediation_check', ['alert_uuid'], unique=False)
    op.create_index(op.f('ix_external_remediation_check_insert_date'), 'external_remediation_check', ['insert_date'], unique=False)
    op.create_index(op.f('ix_external_remediation_check_status'), 'external_remediation_check', ['status'], unique=False)
    op.create_index(op.f('ix_external_remediation_check_update_time'), 'external_remediation_check', ['update_time'], unique=False)
    op.create_table('external_remediation_check_history',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('check_id', sa.Integer(), nullable=False),
    sa.Column('insert_date', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.Column('result', sa.Enum('CONFIRMED', 'NOT_FOUND', 'EXPIRED', 'ERROR', 'CANCELLED', 'PENDING'), nullable=True),
    sa.Column('message', sa.Text(), nullable=True),
    sa.Column('status', sa.Enum('NEW', 'IN_PROGRESS', 'COMPLETED'), nullable=False),
    sa.ForeignKeyConstraint(['check_id'], ['external_remediation_check.id'], onupdate='CASCADE', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_external_remediation_check_history_check_id'), 'external_remediation_check_history', ['check_id'], unique=False)
    op.create_index(op.f('ix_external_remediation_check_history_insert_date'), 'external_remediation_check_history', ['insert_date'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_external_remediation_check_history_insert_date'), table_name='external_remediation_check_history')
    op.drop_index(op.f('ix_external_remediation_check_history_check_id'), table_name='external_remediation_check_history')
    op.drop_table('external_remediation_check_history')
    op.drop_index(op.f('ix_external_remediation_check_update_time'), table_name='external_remediation_check')
    op.drop_index(op.f('ix_external_remediation_check_status'), table_name='external_remediation_check')
    op.drop_index(op.f('ix_external_remediation_check_insert_date'), table_name='external_remediation_check')
    op.drop_index(op.f('ix_external_remediation_check_alert_uuid'), table_name='external_remediation_check')
    op.drop_index('idx_erc_probe_name', table_name='external_remediation_check')
    op.drop_index('idx_erc_observable_lookup', table_name='external_remediation_check', mysql_length={'probe_name': 64, 'observable_type': 64})
    op.drop_index('idx_erc_collector_loop', table_name='external_remediation_check', mysql_length={'probe_name': 64})
    op.drop_table('external_remediation_check')
