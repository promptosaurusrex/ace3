"""analysis cache refactor

Revision ID: dbae3bc8cdd5
Revises: 7e036674bf4f
Create Date: 2026-05-24 12:58:17.051126

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql


# revision identifiers, used by Alembic.
revision: str = 'dbae3bc8cdd5'
down_revision: Union[str, None] = '7e036674bf4f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_index('idx_by_referrer', table_name='blob_refs')
    op.drop_table('blob_refs')
    op.drop_index(op.f('ix_analysis_result_cache_expires_at'), table_name='analysis_result_cache')
    op.drop_index('idx_module_expires', table_name='analysis_result_cache')
    op.drop_table('analysis_result_cache')


def downgrade() -> None:
    op.create_table('analysis_result_cache',
    sa.Column('cache_key', sa.String(length=64), nullable=False),
    sa.Column('module_name', sa.String(length=512), nullable=False),
    sa.Column('module_version', sa.Integer(), nullable=False),
    sa.Column('observable_type', sa.String(length=64), nullable=False),
    sa.Column('observable_value', sa.Text(), nullable=False),
    sa.Column('delta_zstd', mysql.LONGBLOB(), nullable=False),
    sa.Column('delta_uncompressed_size', sa.Integer(), nullable=False),
    sa.Column('has_blob_refs', sa.Boolean(), server_default=sa.text('0'), nullable=False),
    sa.Column('created_at', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.Column('expires_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('cache_key')
    )
    op.create_index('idx_module_expires', 'analysis_result_cache', ['module_name', 'expires_at'], unique=False)
    op.create_index(op.f('ix_analysis_result_cache_expires_at'), 'analysis_result_cache', ['expires_at'], unique=False)
    op.create_table('blob_refs',
    sa.Column('sha256', sa.String(length=64), nullable=False),
    sa.Column('referrer_kind', sa.String(length=32), nullable=False),
    sa.Column('referrer_id', sa.String(length=128), nullable=False),
    sa.Column('created_at', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.PrimaryKeyConstraint('sha256', 'referrer_kind', 'referrer_id')
    )
    op.create_index('idx_by_referrer', 'blob_refs', ['referrer_kind', 'referrer_id'], unique=False)
