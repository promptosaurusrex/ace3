"""add context_json to external_remediation_check

Revision ID: 7e036674bf4f
Revises: d57f886a7b26
Create Date: 2026-05-18 19:13:53.574310

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7e036674bf4f'
down_revision: Union[str, None] = 'd57f886a7b26'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'external_remediation_check',
        sa.Column('context_json', sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('external_remediation_check', 'context_json')
