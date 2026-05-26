"""initial cache schema (analysis_result_cache, blob_refs)

Idempotent: uses CREATE TABLE IF NOT EXISTS so this migration is a no-op on
deployments that already have these tables from sql/04-analysis-result-cache.sql
before the migration existed. New deployments get the tables created here;
sql/04 is reduced to only creating the empty database.

The raw SQL is used (rather than op.create_table) because Alembic autogenerate
cannot model MySQL PARTITION BY clauses, which both tables require.

Revision ID: edfa6bb9bb83
Revises:
Create Date: 2026-05-26 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op


revision: str = "edfa6bb9bb83"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


ANALYSIS_RESULT_CACHE_DDL = """
CREATE TABLE IF NOT EXISTS `analysis_result_cache` (
  `cache_key` VARCHAR(64) NOT NULL,
  `module_name` VARCHAR(512) NOT NULL,
  `module_version` INT NOT NULL,
  `observable_type` VARCHAR(64) NOT NULL,
  `observable_value` TEXT NOT NULL,
  `delta_zstd` LONGBLOB NOT NULL,
  `delta_uncompressed_size` INT NOT NULL,
  `has_blob_refs` TINYINT(1) NOT NULL DEFAULT 0,
  `created_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `expires_at` DATETIME NOT NULL,
  PRIMARY KEY (`cache_key`, `created_at`),
  KEY `idx_module_expires` (`module_name`, `expires_at`),
  KEY `ix_analysis_result_cache_expires_at` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
PARTITION BY RANGE COLUMNS(created_at) (
  PARTITION p_catchall VALUES LESS THAN (MAXVALUE)
)
"""

BLOB_REFS_DDL = """
CREATE TABLE IF NOT EXISTS `blob_refs` (
  `sha256` VARCHAR(64) NOT NULL,
  `referrer_kind` VARCHAR(32) NOT NULL,
  `referrer_id` VARCHAR(128) NOT NULL,
  `created_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`sha256`, `referrer_kind`, `referrer_id`, `created_at`),
  KEY `idx_by_referrer` (`referrer_kind`, `referrer_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
PARTITION BY RANGE COLUMNS(created_at) (
  PARTITION p_catchall VALUES LESS THAN (MAXVALUE)
)
"""


def upgrade() -> None:
    op.execute(ANALYSIS_RESULT_CACHE_DDL)
    op.execute(BLOB_REFS_DDL)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS `blob_refs`")
    op.execute("DROP TABLE IF EXISTS `analysis_result_cache`")
