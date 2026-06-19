"""drop alerts.detection_count

Revision ID: 44a496c21410
Revises: 21378106119b
Create Date: 2026-06-17 17:10:58.159648

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision: str = '44a496c21410'
down_revision: Union[str, None] = '21378106119b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # detection_count is now computed on the fly from the detection_points table
    # (see the Alert.detection_count hybrid property), so the cached column is dropped.
    op.drop_column('alerts', 'detection_count')


def downgrade() -> None:
    op.add_column('alerts', sa.Column('detection_count', mysql.INTEGER(), server_default=sa.text("'0'"), autoincrement=False, nullable=True))
