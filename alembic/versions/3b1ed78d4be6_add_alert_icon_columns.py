"""add alert icon columns

Revision ID: 3b1ed78d4be6
Revises: 7e036674bf4f
Create Date: 2026-05-22 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3b1ed78d4be6'
down_revision: Union[str, None] = '7e036674bf4f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('alerts', sa.Column('icon_blueprint_name', sa.String(length=256), nullable=True))
    op.add_column('alerts', sa.Column('icon_blueprint_path', sa.String(length=1024), nullable=True))
    op.add_column('alerts', sa.Column('icon_url', sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column('alerts', 'icon_url')
    op.drop_column('alerts', 'icon_blueprint_path')
    op.drop_column('alerts', 'icon_blueprint_name')
