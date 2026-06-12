"""add draining_collectors node status

Revision ID: e7f2a4c81b09
Revises: c4a7e91b52d3
Create Date: 2026-06-12 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e7f2a4c81b09'
down_revision: Union[str, None] = 'c4a7e91b52d3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # the new value is appended to the end of the enum so mysql can alter in place
    op.alter_column(
        'nodes',
        'status',
        type_=sa.Enum('starting', 'running', 'draining', 'drained', 'stopped', 'draining_collectors'),
        existing_nullable=False,
        existing_server_default=sa.text("'stopped'"))


def downgrade() -> None:
    # collapse the new status back into draining before shrinking the enum
    op.execute("UPDATE nodes SET status = 'draining' WHERE status = 'draining_collectors'")
    op.alter_column(
        'nodes',
        'status',
        type_=sa.Enum('starting', 'running', 'draining', 'drained', 'stopped'),
        existing_nullable=False,
        existing_server_default=sa.text("'stopped'"))
