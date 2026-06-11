"""add node status

Revision ID: c4a7e91b52d3
Revises: dbae3bc8cdd5
Create Date: 2026-06-10 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql


# revision identifiers, used by Alembic.
revision: str = 'c4a7e91b52d3'
down_revision: Union[str, None] = 'dbae3bc8cdd5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('nodes', sa.Column(
        'status',
        sa.Enum('starting', 'running', 'draining', 'drained', 'stopped'),
        server_default=sa.text("'stopped'"),
        nullable=False))

    op.create_table('collector_status',
    sa.Column('node_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=256), nullable=False),
    sa.Column('status', sa.Enum('running', 'draining', 'drained', 'stopped'), nullable=False),
    sa.Column('backlog_count', sa.Integer(), server_default=sa.text('0'), nullable=False),
    sa.Column('last_update', mysql.DATETIME(), nullable=False),
    sa.ForeignKeyConstraint(['node_id'], ['nodes.id'], ondelete='CASCADE', onupdate='CASCADE'),
    sa.PrimaryKeyConstraint('node_id', 'name')
    )


def downgrade() -> None:
    op.drop_table('collector_status')
    op.drop_column('nodes', 'status')
