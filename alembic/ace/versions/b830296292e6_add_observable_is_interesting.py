"""add observable is_interesting

Revision ID: b830296292e6
Revises: 88d97a42fbef
Create Date: 2026-03-26 18:35:02.893992

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b830296292e6'
down_revision: Union[str, None] = '88d97a42fbef'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('observables', sa.Column('is_interesting', sa.BOOLEAN(), server_default=sa.text('0'), nullable=False))


def downgrade() -> None:
    op.drop_column('observables', 'is_interesting')
